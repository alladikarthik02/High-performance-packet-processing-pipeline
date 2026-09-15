# `pktpipe` — Technical Specification

A high-performance packet-processing pipeline in C and C++.

**Status:** living document. §7 (holes) and §8 (tasks) are the working plan.

---

## 1. Why this document exists

This project's requirements are not invented. They are a résumé bullet that is already
in front of an interviewer:

> **High-Performance Packet Processing Pipeline**
> - Built a packet processing pipeline in **C and C++** that **parses network protocol headers
>   across layers** and **applies configurable rules**, sustaining **high throughput** by using a
>   **cache-friendly layout** and **avoiding per-packet allocation on the hot path**
> - **Worked against the Linux networking stack** to **capture and process traffic**, **validated
>   correctness across a range of protocol cases**, and **profiled the pipeline to remove
>   bottlenecks and reduce per-packet latency**

Every bolded clause is a claim that must be *literally true* and *defensible out loud*.
So §2 decomposes the bullet into testable requirements, and each one names the interview
question it exists to survive.

### 1.1 The governing rule

> **No claim ships without a measurement or a test that proves it.**

"Cache-friendly" is not a vibe — it is a `static_assert` on `sizeof`. "No per-packet
allocation" is not an intention — it is a test that **intercepts `malloc` and fails if it is
called even once** on the hot path. "High throughput" is a number produced by a benchmark
committed to this repo, on hardware named in the README.

---

## 2. Requirements, derived from the bullet

| # | Clause | Requirement | The interview question it survives |
|---|--------|-------------|-------------------------------------|
| R1 | "in C and C++" | Data plane in **C11**; control plane in **C++17**. The split is deliberate, not decorative (§3.1). | *"Why both languages? Which parts are which, and why?"* |
| R2 | "parses network protocol headers across layers" | L2 Ethernet + VLAN/QinQ; L3 IPv4 (+options) / IPv6 (+extension-header chain); L4 TCP/UDP/ICMP; tunnel: VXLAN → recurse into inner L2. | *"What happens with QinQ? An IPv6 header chain? A fragment?"* |
| R3 | "applies configurable rules" | Rules loaded from a text file at startup, compiled into an immutable match structure. 5-tuple + CIDR prefixes + port ranges. Actions: `accept`/`drop`/`count`/`log`. | *"Configurable how? Reloadable? What's the match complexity?"* |
| R4 | "sustaining high throughput" | Benchmark reporting **Mpps** and **ns/packet** over a fixed corpus; committed numbers. (Was "cycles/packet" — see §7.6: the PMU is not available under virtualization, so that number cannot honestly be produced here.) | *"How fast? Measured how? On what?"* |
| R5 | "cache-friendly layout" | Parsed metadata is **one 64-byte cache line**, enforced by `static_assert`. Offsets (`uint16_t`) not pointers. Batch processing + software prefetch. | *"What's a cache line? Why does your struct fit one? Prove it."* |
| R6 | "avoiding per-packet allocation on the hot path" | **Zero** `malloc`/`free`/`new` per packet. All memory preallocated; arena for setup. Enforced by an allocation-interposing test. | *"How do you know there's no allocation? Did you verify?"* |
| R7 | "Worked against the Linux networking stack" | **`AF_PACKET`** raw socket + **`PACKET_MMAP`** (TPACKET_V3) ring buffer, run for real on a Linux kernel, with drop accounting from `PACKET_STATISTICS` and `/proc/net/dev`. | *"AF_PACKET or libpcap? How did you size the ring? Did you drop?"* |
| R8 | "capture and process traffic" | Three capture backends behind one vtable: pcap-file replay, libpcap live, AF_PACKET/MMAP. | *"How do you test capture deterministically?"* |
| R9 | "validated correctness across a range of protocol cases" | Unit suites per layer + malformed/truncated/hostile corpus + a fuzz target. | *"What does your parser do with a truncated IPv6 header chain?"* |
| R10 | "profiled … to remove bottlenecks and reduce per-packet latency" | Before/after profile with `perf` on Linux, a named bottleneck, a fix, and a measured delta. | *"What was the bottleneck? How did you find it? How much did it help?"* |

**Non-goals** (stated so they're deliberate cuts, not gaps — see §9): no TCP reassembly, no
flow state/connection tracking, no NAT/forwarding, no DPI/regex, no control-plane hot reload,
no hardware offload, no kernel bypass (DPDK/XDP).

---

## 3. Architecture

```
  ┌──────────────────────── CONTROL PLANE (C++17) ────────────────────────┐
  │  rules/*.rules ─► lexer ─► parser ─► semantic checks ─► rule compiler │
  │                                                            │           │
  │                                                            ▼           │
  │                                             immutable compiled ruleset │
  └────────────────────────────────────────────────────────────┬───────────┘
                                                               │ built ONCE at startup,
                                                               │ read-only thereafter
  ┌──────────────────────── DATA PLANE (C11) ──────────────────▼───────────┐
  │                                                                         │
  │  capture ──► batch ──► parse ──► classify ──► act ──► stats             │
  │  backend     (N=32)    (§3.3)     (§3.4)     accept/                    │
  │  (§3.2)                                       drop/count                │
  │                                                                         │
  │  invariants: no malloc · no memcpy of payload · no unbounded loops      │
  └─────────────────────────────────────────────────────────────────────────┘
```

Data flows left to right and **never allocates**. The control plane is allowed to allocate,
parse text, throw exceptions, and use STL freely — it runs once, before the first packet.

### 3.1 Why C for the data plane and C++ for the control plane (R1)

This split is the honest answer to *"why C and C++?"*, and it mirrors how real dataplane code
(DPDK, VPP, DPU firmware) is actually organized:

- **Data plane = C11.** Predictable codegen, no hidden allocation, no exceptions, no vtables
  on the hot path, no destructors running where I can't see them. When I claim "no allocation
  per packet", C makes that claim *auditable by reading the code* — there is no `std::string`
  quietly heap-allocating behind my back.
- **Control plane = C++17.** Rule parsing wants `std::string`, `std::vector`, `std::variant`,
  RAII and exceptions. This code runs once at startup where clarity beats cycles.
- **The boundary is a C ABI.** `extern "C"` headers, POD structs. The C++ side *builds* a
  `pp_ruleset` (a flat, POD, pointer-free-ish blob); the C side only ever *reads* it.

This also produces a genuinely good interview answer to *"what would you change to run this on
a DPU?"*: the C data plane is the part that ports; the C++ control plane stays on the host.

### 3.2 Capture backends (R7, R8)

One vtable, three implementations. The pipeline does not know which one it is fed by:

```c
typedef struct pp_source_ops {
    int  (*next_batch)(void *self, pp_rawpkt *out, int max);  /* returns count, 0=EOF, -1=err */
    void (*stats)(void *self, pp_capture_stats *out);
    void (*close)(void *self);
} pp_source_ops;
```

| Backend | Platform | Purpose |
|---------|----------|---------|
| `src_pcapfile` | portable | **Deterministic** replay of a `.pcap`. The backbone of tests + benchmarks: same bytes every run, so a throughput delta means a code change, not a traffic change. |
| `src_pcaplive` | macOS (`/dev/bpf`) + Linux | Live capture via libpcap. Convenience/dev path. |
| `src_afpacket` | **Linux only** | `AF_PACKET` + `PACKET_MMAP` TPACKET_V3 ring. **This is the R7 claim.** Built and run in Docker (§5). |

**Design decision:** the *deterministic file backend is primary*, not an afterthought. Live
capture is untestable in CI and unrepeatable in benchmarks. Correctness and performance are
both established on replay; AF_PACKET proves we can do it against a real kernel.

### 3.3 The parser (R2, R5)

**Zero-copy, offset-based, single forward pass, bounded.**

The parser never copies packet bytes and never allocates. It walks the headers once and
records **offsets** into the original buffer:

```c
typedef struct pp_meta {          /* MUST be exactly 64 bytes — static_assert'd */
    uint16_t l2_off, l3_off, l4_off, payload_off;
    uint16_t caplen, wirelen;
    uint16_t eth_type;            /* post-VLAN-stripping ethertype */
    uint16_t vlan_id;             /* outer VLAN, 0 = none */
    uint8_t  ip_ver, ip_proto, ttl, tcp_flags;
    uint16_t sport, dport;
    ...  /* 5-tuple, flags, parse-error code */
} pp_meta;
```

Why offsets (`uint16_t`) instead of pointers (`8 bytes` each)? Four pointers = 32 bytes; four
offsets = 8 bytes. That difference is *why the struct fits in a cache line*. Packets are
≤ 64 KiB so 16 bits is sufficient — and this is a real design trade-off with a real answer,
not a micro-optimization for its own sake.

**Rules the parser obeys, each of which is a defect class it prevents:**

1. **Bounds check before every header read.** Never read past `caplen`. (Truncated-packet
   crash / remote DoS.)
2. **Never cast raw bytes to a struct pointer.** Use `memcpy` into a local, or byte loads.
   Packet headers are **unaligned** and casting violates **strict aliasing** — that's UB, and
   on some ISAs a fault. The compiler turns the `memcpy` back into a single load anyway (§7.2).
3. **Every loop is bounded.** VLAN stacking, IPv6 extension headers, and tunnel recursion are
   all attacker-controlled and all get hard caps. (Infinite-loop DoS.)
4. **Errors are recorded, not thrown.** A malformed packet sets `meta->err` and stops parsing
   at the last good layer. It is never a crash and never an exception.

### 3.4 The classifier (R3)

Naive matching is `O(rules)` per packet — a linear scan. That is the honest baseline and it is
what we build first (T6), because **the interesting answer is the measured comparison**, not
skipping to the clever structure.

Then we make it sublinear where it matters:

- **Exact 5-tuple** → open-addressing hash table, precomputed hash, power-of-two mask.
- **CIDR prefix (LPM)** → **DIR-24-8** (the algorithm behind DPDK's `rte_lpm`): a 16 MiB
  flat table giving **O(1), usually single-memory-access** longest-prefix match for IPv4.
  A textbook space-vs-time trade, and squarely DPU-relevant.
- **Port ranges** → kept linear (small N), deliberately.

§7.5 pokes a hole in this.

### 3.5 The memory model (R6) — the heart of the project

Three allocation regions, all sized and reserved **before the first packet**:

| Region | Lifetime | Allocated by |
|--------|----------|--------------|
| Packet buffers | pinned for process lifetime | one arena `mmap` at startup (or the kernel's MMAP ring — kernel-owned) |
| Metadata array | one per in-flight packet, reused per batch | one arena block |
| Ruleset | immutable after compile | control plane, before the pipeline starts |

The hot path therefore performs **zero** allocations. §7.1 explains why "just don't call
malloc" is not sufficient evidence, and T9 is the test that turns it into proof.

---

## 4. The processing model: batching

The pipeline pulls **32 packets at a time**, not one. Three independent reasons, and an
interviewer may ask for any of them:

1. **Amortize the per-call cost.** One `next_batch()` per 32 packets, not 32 calls. On the
   AF_PACKET path this is what removes a syscall per packet.
2. **Instruction-cache locality.** Running "parse × 32" then "classify × 32" keeps the parser's
   code hot in L1i, instead of thrashing parse/classify/act/parse/classify/act.
3. **It enables prefetch.** While parsing packet `i`, issue `__builtin_prefetch` for packet
   `i+PREFETCH_DIST`. A DRAM miss is ~200-300 cycles; parsing a header is ~50. Without
   prefetch we stall on memory and the CPU idles.

Why 32? It's the DPDK default burst size and a defensible starting point — but a number I
should *measure*, not inherit. **T12 sweeps batch size and prefetch distance and reports the
curve**, so "why 32?" has a graph behind it.

---

## 5. The Linux story (R7)

This machine is macOS/arm64. `AF_PACKET` does not exist in the Darwin kernel — macOS captures
via `/dev/bpf`. Writing `#ifdef __linux__` code that never runs would be a bluff.

**So: Docker Desktop runs a real Linux kernel (arm64) in a VM.** Inside a container with
`--privileged` (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) we get genuine `AF_PACKET` sockets,
`PACKET_MMAP` rings, `veth` pairs, network namespaces, `tcpdump`, and `perf`.

Traffic generation without needing a physical NIC: a **`veth` pair** — two virtual interfaces
wired back-to-back inside the container. Blast frames in one end; capture with AF_PACKET on the
other. Real kernel, real driver path, real ring buffer, reproducible.

| Layer | Where it's built | Where it's tested |
|-------|------------------|-------------------|
| Parser, classifier, memory, rules | macOS + Linux | both (portable C) |
| pcap-file replay | macOS + Linux | both |
| libpcap live | macOS + Linux | macOS (`/dev/bpf`, needs sudo) |
| **AF_PACKET + PACKET_MMAP** | **Linux** | **Docker, for real, measured** |
| `perf` profiling | Linux | Docker |

**Honest scoping note for the interview:** this runs on a Linux kernel in a VM on arm64, not on
bare-metal x86 with a 100G NIC. The throughput numbers are real for what they measure —
userspace parse/classify cost — and the pipeline is not NIC-bound. Say that plainly; a fabricated
"100 Gbps" claim collapses under one follow-up question.

---

## 6. Repository layout

```
pktpipe/
├── include/pp/          # public headers (C ABI; C++ includes them via extern "C")
│   ├── pkt.h            # pp_rawpkt, pp_meta — the cache-line struct
│   ├── parse.h          # the zero-copy parser
│   ├── proto.h          # wire-format constants & header layouts
│   ├── arena.h          # bump allocator
│   ├── ruleset.h        # compiled, immutable ruleset (C-readable POD)
│   ├── classify.h       # match engine
│   ├── source.h         # capture backend vtable
│   └── pipeline.h       # the driver
├── src/                 # C11 data plane
├── src/control/         # C++17 control plane (rule parsing/compiling)
├── tests/               # per-layer suites + zero-alloc proof + fuzz
├── bench/               # throughput / cycles-per-packet harness
├── tools/               # pcap synthesis, traffic generator
├── docker/              # Linux dev environment (AF_PACKET + perf)
└── docs/                # SPEC.md (this), CHALLENGES.md (interview Q&A)
```

---

## 7. Poking holes in my own design

The point of this section: **find the weaknesses before the interviewer does.** Every entry is
a real objection to the design above.

### 7.1 "No allocation on the hot path" is unfalsifiable as written

**The hole.** I can read the code and see no `malloc`. That proves nothing. `std::string`,
`std::vector` growth, `std::function`, a C++ exception, even some `printf` paths allocate
*invisibly*. A reviewer is right to be skeptical of the claim, and "I checked" is not evidence.

**The fix.** Make it falsifiable: **interpose the allocator.** Provide our own `malloc`/`free`/
`operator new` that increments a counter, arm a flag after startup, and `assert` the counter
never moves while packets flow. If someone later adds a `std::vector` to the parser, **the test
fails**. That converts a claim into an enforced, regression-proof invariant. → **T9**

### 7.2 Casting packet bytes to a struct is undefined behavior

**The hole.** The obvious parser is `struct ip *h = (struct ip *)(pkt + off);`. Everyone writes
this. It has two real bugs: (a) `pkt+off` is **not aligned** to `alignof(struct ip)` — legal-ish
on x86/arm64, a **fault** on stricter targets and detectable by UBSan; (b) it violates **strict
aliasing** — accessing `char` bytes through an unrelated struct type is UB, and GCC/Clang at
`-O2` are permitted to miscompile it. This is not pedantry; it's a real class of
"works until you change the optimizer" bug.

**The fix.** `memcpy` into a local. It looks slower and **is not** — compilers turn a
fixed-size `memcpy` into the same single load. → verified by reading the disassembly (T2),
which is also a great thing to have actually done when asked.

### 7.3 The 64-byte cache line claim is wrong on this exact machine

**The hole.** I want to say "the metadata struct fits in one cache line." On this M1
(`T8103`, arm64) the L1 cache line is **128 bytes**, not 64. On x86-64 it is 64. So the
claim is machine-dependent, and stating "64 bytes" unqualified to an interviewer on a
hardware team is exactly the kind of thing that gets caught.

**The fix.** Don't hand-wave — **query it** (`sysctl hw.cachelinesize`, `getconf
LEVEL1_DCACHE_LINESIZE`), state the number for the machine, and design for **64** anyway
because it's the tighter constraint and the one that matters on x86 servers and DPU Arm cores.
→ **T1** (`tools/cacheinfo` probes it at runtime; the design target is `PP_CACHELINE`.)

**MEASURED — and the answer is stranger than the hole assumed.** The same physical M1, asked
from two sides of the hypervisor, gives two different answers:

| Asked from | Interface | Answer |
|------------|-----------|--------|
| macOS host | `sysctl hw.cachelinesize` | **128** |
| Linux guest (Docker, same silicon) | `getconf LEVEL1_DCACHE_LINESIZE` | **64** |

Virtualization.framework does not pass the host's real cache geometry through to the guest, so
the Linux kernel reports 64. Neither number is a lie; they are answers to different questions.

**The real lesson**, which is better than the one this hole started with: *the cache line size
you design against is not a property of the silicon alone — it is what the OS (or hypervisor)
tells you, and under virtualization that introspection is unreliable.*

The design consequence is concrete. Had the 128 from macOS been trusted, `pp_meta` would have
been built to 128 bytes — and would then be **two cache lines on the exact machine every
benchmark in this repo runs on**. Targeting the stricter 64 is correct on the host, correct in
the guest, and correct on the x86 servers and Arm DPU cores this would really ship to. The
honest sentence: *"64 bytes — one line on x86 and in the Linux guest, half a line as macOS
reports the M1. I designed to the tightest bound rather than to whichever number my laptop
happened to report."*

### 7.4 Batching does not obviously help — and may hurt latency

**The hole.** Batching improves *throughput* while **increasing worst-case latency**: packet 0
of a batch waits for packets 1..31 to arrive before it's processed. The bullet claims *"reduce
per-packet latency"*. These are in direct tension, and an interviewer who knows dataplanes will
absolutely push here.

**The fix.** Be precise about which latency. Amortized per-packet *processing* cost goes down;
*end-to-end* latency for the first packet of a batch goes up under low load. Real dataplanes
solve this with a **timeout/adaptive burst** (don't wait forever for a full batch). Measure
both, report both, and don't pretend the trade-off doesn't exist. → **T12**

**MEASURED (T12) — and §4 was wrong.** §4 gave three confident reasons batching wins. Two of
them do not apply to file replay, and the numbers say so:

| batch | uniform_tcp ns/pkt | mixed ns/pkt |
|------:|-------------------:|-------------:|
| 1     | 21.6               | 33.8         |
| 2     | 20.8               | **33.0** (best) |
| 4     | **20.6** (best)    | 33.5         |
| 32 (the inherited default) | 22.5 (**+4%**) | 36.9 (**+9%**) |
| 256   | 22.3               | 39.4 (**+16%**) |

Batching is **worthless here, and mildly harmful at large sizes**. The reason is that the two
mechanisms §4 claimed are absent on this path: there are **no syscalls to amortize** (the pcap
is `mmap`'d) and the **I-cache is already hot** (the parser is the only code running). 32 came
from DPDK, and inheriting a number is not justifying one.

**But batching is not therefore useless — it just pays somewhere else.** The same measurement
on the live AF_PACKET path, 50k frames offered at ~1 Mpps:

| | `recvfrom` (a syscall per packet) | `mmap` ring (batched by construction) |
|---|---|---|
| captured | 13,503 | **50,000** |
| **kernel drops** | **36,513 — 73% of the link lost** | **0** |
| syscalls / 3000 pkts | 743 | **7** |
| packets per syscall | ~0.5 | **~430** |

That is where the amortization argument was true all along. **Conclusion: batching's value is
about syscall amortization, not cache locality** — and it is worth 73 percentage points of
packet loss on the path that has syscalls. Building both modes is what made this sayable.

**Consequence for the design:** batch size stays a parameter with a measured curve behind it
rather than a folk constant, and the honest sentence is *"batching bought nothing on replay and
everything on the syscall path — here are both numbers."*

### 7.4b Software prefetch made it SLOWER

**Not a hole I predicted — a result that contradicted me.** §4 claimed software prefetch hides
DRAM latency. Measured:

| distance | uniform_tcp | mixed |
|---------:|------------:|------:|
| 0 (off)  | 22.7        | 36.9  |
| 4 (the default I chose) | 22.6 (−0.2%) | 37.1 (+0.7%) |
| 8        | 22.5        | 41.5 (**+12.5%**) |
| 32       | 22.5        | 53.7 (**+45.6%**) |

At best it does nothing; past distance 4 it is a **significant pessimization**.

**Why.** The reasoning in §4 assumed the loads would miss. They do not: the corpus is walked
sequentially through one `mmap`, which is the exact access pattern the **hardware prefetcher**
is built to recognise — it is already running ahead of us. The software prefetch adds no
information and is not free: it burns memory bandwidth and, at long distances, **evicts lines we
are about to need**, which is why the branchy mixed corpus degrades so much worse than the
uniform one.

**The fix.** `PP_PREFETCH_DEFAULT` changed from 4 to **0 (off)**, because the data says so. The
mechanism stays in the code as a tunable, since a real NIC ring with scattered frames is a
genuinely different access pattern where it may pay — but it is off until something measures it
being worth switching on.

**The lesson, and it is the most valuable one in this file:** I implemented prefetch because the
textbook says to, and it made things up to 45% worse. An optimization you have not measured is
a guess, and guesses are wrong in both directions.

### 7.5 DIR-24-8 is probably the wrong call, and I should say so

**The hole.** DIR-24-8 costs a flat **16 MiB** table. That table is *larger than L2*. For a
handful of rules, a linear scan over 8 rules living in one cache line will **beat** it, because
the linear scan hits L1 and DIR-24-8 takes a DRAM miss. "I used the fancy algorithm" is the
wrong instinct if the numbers say otherwise.

**The fix.** Build linear first, measure, and **only** adopt DIR-24-8 if the crossover justifies
it — then report *where the crossover is*. "It depends on rule count, and here's the graph" is a
far stronger answer than either "I used linear" or "I used DIR-24-8". → **T7, T12**

### 7.6 Throughput numbers from a VM on a laptop are soft — and the PMU is gone

**The hole.** Docker on macOS = Linux kernel in a VM on arm64. Numbers are affected by the
hypervisor; there is no real NIC; `perf` counters may be limited or absent under virtualization.
Quoting "X Mpps" without that context is misleading.

**MEASURED, not assumed** (this is why the environment got probed before any code was written
against it):

```
$ perf stat -e cycles true
   <not supported>      cycles          ← hardware PMU is NOT virtualized
$ perf stat -e cpu-clock true
        0.20 msec cpu-clock             ← software events DO work
$ perf --version
   perf version 6.1.176   (kernel 6.12.76-linuxkit)
```

Virtualization.framework does not expose the M1's performance-monitoring unit, so `cycles`,
`cache-misses`, `branch-misses` and `LLC-load-misses` are **unavailable and cannot be made
available**. This is not a configuration problem to solve; it is a property of the platform.

**The consequence, accepted honestly.** R4 originally said "cycles/packet". That number cannot
be produced here, so **the requirement changed rather than the truth**. What remains, all of it
real:

- `perf record -e cpu-clock` — statistical sampling still identifies which functions burn time,
  which is all T13 actually needs to find a bottleneck.
- **ns/packet** and **Mpps** from `clock_gettime(CLOCK_MONOTONIC)` on a fixed replay corpus:
  precise, virtualization-safe, and a direct measure of the thing we optimize.

Note the résumé bullet says *"profiled the pipeline to remove bottlenecks and reduce per-packet
latency"* — it never claims hardware counters. Software sampling plus ns/packet satisfies it
completely.

**The fix.** Report **ns/packet** and **Mpps** on a fixed replay corpus, name the hardware and
the kernel, and state the PMU caveat in the README. The honest sentence — *"the PMU isn't
exposed under virtualization, so I measured wall-clock ns/packet; on bare metal I'd confirm the
cache-layout win with `perf stat -e cache-misses`"* — is **stronger** than a fabricated cycle
count, because it demonstrates knowing what the PMU is and why it was missing. Never claim
line-rate, cache-miss counts, or cycle counts we did not measure.

### 7.6b The benchmark replays a corpus that fits in L2, and that flatters us

**The hole, found by chasing an unexplained number.** A single cold pass over `uniform_tcp.pcap`
costs **~68-111 ns/packet**. The same run with `--repeat 20` costs **~19 ns/packet**. Same code,
same bytes, **5.8x apart** — and it happens with a ruleset of **zero rules**, so the classifier
is not involved at all.

**The first hypothesis was wrong**, which is why it is worth writing down. "It must be page
faults on the mmap'd file" — 3.8 MB is 927 pages, so 927 faults. Measured with
`perf stat -e page-faults` (a *software* event, so it works despite the missing PMU):

```
COLD (repeat=1):   67.9 ns/pkt    172 page-faults
WARM (repeat=20):  19.9 ns/pkt    171 page-faults    <- identical
```

**172, not 927 — and the same either way.** Linux does **fault-around** on file-backed mappings:
one fault populates ~16 pages (64 KiB), so 3.8 MB costs ~58 faults, and the rest is the binary
and libc. "One fault per page" is simply wrong for file mappings.

**What the cold cost actually is.** First pass ≈ 3.4 ms; each subsequent pass ≈ 0.87 ms. The
~2.5 ms gap is the **memory system**, not the kernel: cold data cache (3.8 MB pulled from DRAM),
cold TLB (927 pages against ~1500 dTLB entries), cold i-cache, and untrained branch predictors.

**The flaw this exposes in the benchmark itself.** The corpus is **3.8 MB**; this machine's
**L2 is 4 MB**. So `--repeat 20` means 19 of 20 passes read packets **already resident in L2**.
That is not what a NIC does — a NIC hands you bytes that were *just DMA'd into memory* and are
**never** in cache. So:

- **~19 ns/pkt** = our code with a free memory system. Real, but optimistic.
- **~68 ns/pkt** = our code paying for cold memory. Closer to what a real NIC would produce.

**The fix.** Report both and say which is which. Neither is a lie; quoting only the warm one
would be. A more honest benchmark would use a corpus several times larger than L2 so that no
pass can be resident — that is a known improvement, not a solved one.

**The interview sentence:** *"19 ns warm, 68 ns cold, and the difference is L2 residency, not
page faults — I checked, it's 172 faults either way because of fault-around. My corpus is
3.8 MB against a 4 MB L2, so replaying it measures a warm memory system. A real NIC never gives
you warm packets, so the cold number is the more honest one to plan against."*

### 7.7 A `pcap` file replay is not "capturing traffic"

**The hole.** If the benchmark only replays a file, R8 ("capture and process traffic") is doing
a lot of work in that sentence.

**The fix.** That's precisely why AF_PACKET on a live `veth` (§5) is non-optional, and why we
also generate live traffic and capture it. File replay is for *determinism*; the live path is
for *truth*. Both exist. → **T10, T11**

### 7.8 The IPv6 extension-header chain is an unbounded loop

**The hole.** IPv6 says "next header" chains can be arbitrarily long, and each hop is
attacker-controlled. A naive `while (is_ext_header(nh))` is a **remote DoS**: a crafted packet
loops the parser forever. This is a real, historically-exploited class of bug.

**The fix.** Hard cap the chain (8), bounds-check each hop, and on exceeding the cap mark
`PP_ERR_TOO_MANY_EXTHDRS` and stop. Same defense for VLAN stacking and VXLAN recursion.
**Test it with a hostile packet.** → **T3, T14**

### 7.9 `caplen` vs `wirelen` will silently corrupt results

**The hole.** A capture snaplen truncates the packet. `caplen` (bytes we have) < `wirelen`
(bytes on the wire). If the parser trusts the IP header's *length field* rather than what was
actually captured, it reads past the buffer. The IP length field is **attacker-controlled data**.

**The fix.** Never trust a length field. Clamp every read to `caplen`, treat wirelen as
reporting-only, and fuzz it. → **T2, T14**

### 7.10 Nothing here is multi-threaded — is that a gap?

**The hole.** "High throughput" and single-threaded sit uneasily together. An interviewer may
ask "how would you scale this to 8 cores?"

**The decision.** Single-threaded is **deliberate** (§9). One core doing honest work with clean
numbers is more defensible than a racy thread pool. But the *answer* must be ready: RSS /
`PACKET_FANOUT` to shard flows across queues by 5-tuple hash, share-nothing per-core state, and
per-core stats to avoid a contended cache line. The design already supports it — the metadata
is per-packet and the ruleset is immutable/read-only, so it shards cleanly. Say that.

---

## 8. Task breakdown

Each task ships with tests and stays green. Ordered so the build never breaks.

| # | Task | Proves | Needs Linux? |
|---|------|--------|--------------|
| **T0** | Repo skeleton, CMake, C/C++ split, test harness | R1 | no |
| **T1** | `pp_rawpkt`/`pp_meta` layout + arena allocator + cache-line probe | R5, R6 | no |
| **T2** | L2: Ethernet, VLAN, QinQ + bounds discipline + disasm check | R2, R9 | no |
| **T3** | L3: IPv4 (+options), IPv6 (+bounded ext-header chain) | R2, R9 | no |
| **T4** | L4: TCP/UDP/ICMP + VXLAN tunnel recursion | R2 | no |
| **T5** | pcap-file backend + synthetic packet/pcap generator | R8, R9 | no |
| **T6** | Rule language: lexer, parser, sema, compiler (C++17) | R3, R1 | no |
| **T7** | Classifier: linear baseline → hash → LPM, *measured* | R3, R4 | no |
| **T8** | Pipeline driver: batching, prefetch, stats | R4, R5 | no |
| **T9** | **Zero-allocation proof** (malloc interposer) | R6 | no |
| **T10** | **AF_PACKET** raw-socket backend | **R7** | **yes** |
| **T11** | **PACKET_MMAP** TPACKET_V3 ring + drop accounting | **R7** | **yes** |
| **T12** | Benchmark: Mpps, cycles/pkt, batch & prefetch sweeps | R4 | partly |
| **T13** | Profile with `perf`, find bottleneck, fix, measure delta | R10 | **yes** |
| **T14** | Malformed/hostile corpus + fuzz target | R9 | no |
| **T15** | `README.md` + `docs/CHALLENGES.md` (interview Q&A) | all | no |

---

## 9. Deliberate scope cuts

Stated up front, as considered trade-offs rather than gaps:

- **No TCP reassembly / flow state.** Stateless per-packet classification only. Flow state
  means a hash table with eviction, timeouts, and memory limits — a project of its own.
- **No kernel bypass (DPDK/XDP/AF_XDP).** AF_PACKET+MMAP is the honest middle: real kernel
  networking with a shared ring, no 20-minute hugepage/driver-binding detour. *Know what the
  next step would be and why* (§7.10).
- **No multithreading.** §7.10 — deliberate; the scaling answer is prepared.
- **No hot rule reload.** Rules compile at startup. Hot reload needs RCU or double-buffering.
- **No IP defragmentation.** Fragments are *detected* and reported (L4 ports unavailable on
  non-first fragments), not reassembled.
- **No DPI/regex.** Header-only classification.

Each cut is defensible in the same sentence pattern: *"I chose not to, here's the cost, here's
what I'd do if it mattered."*
