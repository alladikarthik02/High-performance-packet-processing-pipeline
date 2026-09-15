# `pktpipe` — a high-performance packet processing pipeline

A from-scratch packet parser, rule engine and classifier in **C11 + C++17**, capturing against
the **Linux networking stack** via `AF_PACKET` and a `PACKET_MMAP` shared ring. No libpcap on
the capture path, no DPDK, no external libraries.

```
  wire ──► AF_PACKET + PACKET_MMAP ring ──┐
                                          ├──► parse ──► classify ──► verdict
  file ──► mmap'd pcap replay ────────────┘      ▲
                                                 │
             rules.txt ──► lex ─► parse ─► sema ─┘
                           (C++17 control plane, runs once)
```

The data plane parses **L2 → L4 plus VXLAN tunnels**, applies a compiled ruleset, and does it
**without allocating a single byte per packet** — a claim enforced by a test that intercepts
the allocator and fails if it is called even once.

---

## Results

Measured on the environment named below. Every number here is reproducible with the commands
in this README; none are estimates.

| | |
|---|---|
| **Zero-allocation hot path** | **0 allocations** across 50,000 packets (TCP, UDP, VLAN, IPv6 ext-header chains, VXLAN, malformed) — mechanically enforced |
| **Parse throughput** | **~15 ns/packet** ≈ **65 Mpps**, parse-only, warm |
| **Parse + classify (8 rules)** | **~23 ns/packet** ≈ **44 Mpps**, warm |
| **Classifier cost** | **~1.1 ns per rule**, flat from 8 to 512 rules |
| **`recvfrom` vs `mmap` ring** | **73% packet loss vs 0%** at ~1 Mpps offered |
| **Syscalls per 3,000 packets** | **743 (`recvfrom`) vs 7 (`mmap`)** — ~430 packets/syscall vs ~0.5 |
| **Fuzzing** | **41,085,992 inputs, 0 crashes**, ASan + UBSan armed |
| **Tests** | 10 suites, ~1,500 assertions, all green |

### The result that matters most

```
AF_PACKET, 50,000 frames offered on a veth pair at ~1 Mpps:

  recvfrom (a syscall per packet):   13,503 captured   36,513 KERNEL DROPS  (73% lost)
  mmap ring (TPACKET_V3):            50,000 captured        0 kernel drops
```

`recvfrom` did not merely run slower — **it lost three quarters of the link**, and the only
reason we know is that the pipeline reads `PACKET_STATISTICS`. A capture tool without drop
accounting would have reported *"13,503 packets processed, 0 errors"* and looked perfectly
healthy while silently discarding most of the traffic.

### Honest caveats — read these before quoting any number above

1. **Warm ≠ cold, and the gap is 3.5×.** The replay corpus is 3.8 MB; this machine's L2 is
   4 MB. Replaying it measures a **warm** memory system: ~19 ns/packet. A single cold pass is
   **~68 ns/packet**. A real NIC DMAs packets into memory that is *never* in cache, so **the
   cold number is the more honest one to plan against**. (The cause is cold cache/TLB, *not*
   page faults — measured at 172 faults either way, because Linux faults-around 16 pages at a
   time on file mappings. See `docs/SPEC.md` §7.6b.)
2. **No cycle counts, and no cache-miss counts.** The PMU is not virtualized under Docker on
   Apple silicon — `perf stat -e cycles` returns `<not supported>`. All timings are wall-clock
   `CLOCK_MONOTONIC`. On bare metal I would confirm the cache-layout wins with
   `perf stat -e cache-misses`. See §7.6.
3. **This is a Linux kernel in a VM on a laptop, not bare metal with a 100G NIC.** The
   AF_PACKET path, the ring, and the drops are all real kernel behaviour. The throughput is
   real for what it measures — userspace parse/classify cost — and the pipeline is not
   NIC-bound.

4. **These are medians, and they wobble by a few percent.** The benchmark runs each config 7
   times and reports the median (not the mean — one scheduler hiccup skews it; not the min —
   that's the luckiest run, not a typical one), and prints `[min..max]` so you can judge the
   noise yourself. Parse-only measured 14.9 ns one day and 15.3 ns the next; that's a VM, and
   quoting either to three significant figures would be false precision. Round numbers here
   are rounded on purpose.

**Environment:** Debian bookworm container, Linux **6.12.76-linuxkit** (arm64), **GCC 12.2**,
on Docker Desktop / Apple M1 (8 cores, 64 KiB L1d, 4 MiB L2). Reproduce with
`./docker/dev.sh build`.

### The rule-count sweep (the §7.5 question, settled)

```
   rules     bytes      ns/pkt      Mpps       ns/rule
       0         0        15.3    65.209          --      <- parse only
       8       256        22.9    43.713        0.94
      32      1024        57.0    17.533        1.30
     128      4096       165.6     6.039        1.17
     512     16384       594.4     1.682        1.13      <- still flat
```

Every rule is built to **fail**, so each packet walks the whole list — the worst case, which is
the only honest thing to quote a linear scan at. `ns/rule` stays ~1.1 out to 512 rules because
512 × 32 B = 16 KiB, still inside a 64 KiB L1d. **That flatness is what justifies not building
the fancy index**, and it's the answer to *"why didn't you use a hash table or an LPM trie?"*

---

## Build & run

Everything runs on Linux in a container, because the project targets Linux (see *Why Docker*
below).

```sh
./docker/dev.sh build     # build the image (~30 s)
./docker/dev.sh ci        # configure + build + run all 10 test suites
```

Generate the deterministic corpora and replay one:

```sh
./docker/dev.sh run ./build-linux/pktgen pcaps 50000
./docker/dev.sh run ./build-linux/pktpipe --pcap pcaps/mixed.pcap --rules rules/example.rules
```

Capture **live**, for real, against the Linux stack:

```sh
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$PWD":/work -w /work pktpipe-dev bash -c '
  ip link add veth0 type veth peer name veth1
  ip link set veth0 up; ip link set veth1 up
  ./build-linux/pktpipe --iface veth1 --rules rules/example.rules --count 50000 &
  sleep 1
  ./build-linux/pktsend --iface veth0 --count 50000
  wait'
```

Benchmark sweeps, and the fuzzer:

```sh
./docker/dev.sh run ./build-linux/bench pcaps/uniform_tcp.pcap 20
./docker/dev.sh run bash -c 'clang -std=c11 -g -O1 -fsanitize=fuzzer-no-link,address,undefined -Iinclude -c src/parse.c -o /tmp/p.o && \
  clang -std=c11 -g -O1 -fsanitize=fuzzer-no-link,address,undefined -Iinclude -c src/pkt.c -o /tmp/k.o && \
  clang++ -std=c++17 -g -O1 -fsanitize=fuzzer-no-link,address,undefined -Iinclude -c tests/fuzz_parse.cpp -o /tmp/f.o && \
  clang++ -fsanitize=fuzzer,address,undefined /tmp/f.o /tmp/p.o /tmp/k.o -o /tmp/fuzz && \
  /tmp/fuzz -max_total_time=60 pcaps/fuzz_corpus/'
```

---

## The rule language

```
default accept

count  tcp any any            -> any 443            # tally all HTTPS, keep going
drop   tcp any any            -> any 22             # no SSH
accept tcp 192.168.0.0/16 any -> 10.0.0.0/8 80-443
accept tcp 172.16.0.0/16 any  -> any 8080  vni 5000 # a tenant inside a VXLAN tunnel
count  any any any            -> any any   vlan 100
accept tcp any any            -> any 443   ip6
```

Evaluated top to bottom. `accept`/`drop`/`log` are terminal (first match wins);
`count` tallies and lets evaluation continue — so a monitoring rule can't silently become a
policy rule. Semantics deliberately match iptables, because a rule language that surprises its
author is a security bug.

The compiler rejects things that are almost certainly mistakes:

```
$ pktpipe --rules bad.rules --pcap x.pcap
rule error: bad.rules:3: 192.168.1.5/24 has host bits set; did you mean 192.168.1.0/24 ?
```

That one matters: `192.168.1.5/24` reads as "just .5" and actually matches the **whole /24** —
a silent widening of an access rule. Also rejected: inverted port ranges (`443-80` matches
nothing and is always a typo), and `ip6` combined with an IPv4 CIDR (can never fire).

---

## Architecture

The one idea: **two planes**, split by how often the code runs.

| | Control plane | Data plane |
|---|---|---|
| Language | **C++17** | **C11** |
| Runs | once, at startup | per packet, forever |
| Budget | milliseconds | **nanoseconds** |
| May allocate? | yes, freely | **never** |
| Files | `src/control/rules.cpp` | `src/parse.c`, `src/classify.c`, `src/pipeline.c`, `src/source_*.c` |

The boundary is a **C ABI**: the C++ side *builds* a flat POD `pp_ruleset`; the C side only
ever *reads* it. That's why "no per-packet allocation" is auditable by reading the code —
there's no `std::string` that might quietly heap-allocate. It's how DPDK and VPP are organised,
and it's the answer to *"how would this port to a DPU?"* — **the C data plane ports; the C++
control plane stays on the host.**

| Stage | Files | What it does |
|---|---|---|
| Capture | `source_pcapfile.c`, `source_afpacket.c` | One vtable, three backends: mmap'd pcap replay (deterministic, the measurement baseline), AF_PACKET `recvfrom`, AF_PACKET + `PACKET_MMAP` ring |
| Packet & memory | `pkt.h`, `arena.{h,c}` | `pp_meta` = **exactly one 64-byte cache line**; `mmap`-backed pre-faulted bump arena |
| Parse | `parse.c`, `proto.h` | Zero-copy, single forward pass, every attacker-controlled loop **bounded** |
| Rules | `ruleset.h`, `rules.cpp` | lex → parse → sema → compile to 32-byte PODs, addresses **pre-masked** |
| Classify | `classify.c` | Linear scan — the honest baseline, kept because it's measurably *right* here |
| Drive | `pipeline.c` | Batch of 32, two-stage (parse×N, then classify×N), per-rule stats |

### Design decisions worth defending

- **Offsets, not pointers.** Four pointers = 32 bytes; four `uint16_t` offsets = 8. That
  24-byte saving is the *only* reason `pp_meta` fits in a cache line. Sound because a packet
  is ≤ 64 KiB. Offsets also survive relocation and can be shipped to another core.
- **IPv6 addresses are not stored.** 32 bytes for a field read at most once — and the bytes
  are already in L1 because we just parsed them.
- **Byte-load field reads** (`p[0] << 8 | p[1]`) instead of casting to a header struct. Kills
  misalignment, strict-aliasing UB, *and* endianness in one move — and costs **nothing**:
  both GCC and Clang emit the identical `ldrh` + `rev16` as the unsafe cast. Verified in the
  disassembly, not assumed.
- **The tunnel walk is a loop, not recursion.** VXLAN's payload is another packet, so parsing
  is naturally recursive — and recursion depth would then be chosen by whoever sent the frame.
  A loop makes the memory cost constant and the depth cap auditable.
- **Every length field is untrusted.** `caplen` — what we actually captured — is the only
  bound. IP total length, TCP data offset, UDP length are all *claims by the sender*.

---

## Testing

10 suites, ~1,500 assertions, no framework (`tests/test.h` is ~80 lines). `./docker/dev.sh test`

| Suite | What it protects |
|---|---|
| `test_layout` | The 64-byte cache-line claim, *and* alignment — a 64-byte struct at offset 32 straddles two lines |
| `test_arena` | Integer overflow in the exhaustion check (`SIZE_MAX` allocation), alignment rejection, pre-faulting |
| `test_l2` / `test_l3` / `test_l4` | Every layer, plus the hostile cases: VLAN bombs, IPv6 ext-header bombs, truncation at **every** offset, lying length fields |
| `test_pcap` | Broken capture files: cooked-mode, truncated final record (what every `^C`'d tcpdump produces), absurd `incl_len` |
| `test_rules` | The compiler's sema checks and its error messages |
| `test_classify` | The dangerous cases — a port rule must **not** match a fragment whose ports we never read |
| **`test_noalloc`** | **The zero-allocation proof.** Interposes `malloc`/`free`/`new`/`delete`, arms after setup, asserts the counter never moves across 50,000 packets |
| `fuzz_parse` | 41M inputs, ASan + UBSan. Asserts invariants (no offset past `caplen`, layers monotonic, deterministic), so "wrong" becomes "crash" |

A few tests are unusual and deliberate:

- **`test_noalloc` tests itself first.** An interposer that silently failed to link would make
  every other check pass vacuously — a proof that proves nothing while looking green.
- **The parser tests sweep every prefix** of a valid packet rather than spot-checking one
  truncation. Truncation is where parsers die.
- **`suite_offsets_not_pointers` tests a *decision***, asserting that with pointers the struct
  could not fit.

---

## Why Docker

The résumé claim this project exists to back is *"worked against the Linux networking stack"*.
`AF_PACKET` is a Linux kernel interface — it **does not exist** on macOS, which captures via
`/dev/bpf`. Writing `#ifdef __linux__` code that never runs would be a bluff, so the whole
project builds and runs on Linux (kernel 6.12, in a VM), where the socket, the TPACKET_V3 ring
and the `veth` pair are all genuine kernel objects.

It paid for itself on the first Linux build: `MAP_ANONYMOUS` compiled clean on macOS and failed
instantly on Linux, because it is not POSIX and glibc hides it under `-std=c11` without
`_DEFAULT_SOURCE`. That's exactly the class of bug `#ifdef`-and-hope produces.

---

## Deliberate scope cuts

Stated up front as considered trade-offs, not gaps. Each has a real answer to *"what would you
do if it mattered?"* — see `docs/SPEC.md` §9.

- **No TCP reassembly or flow state.** Stateless per-packet classification only.
- **No kernel bypass (DPDK / XDP / AF_XDP).** AF_PACKET+MMAP is the honest middle: real kernel
  networking with a shared ring.
- **Single-threaded.** The scaling answer is prepared: `PACKET_FANOUT` to shard flows by
  5-tuple hash, share-nothing per-core state. The design already supports it — metadata is
  per-packet and the ruleset is immutable read-only, so it shards with no locking. (The hit
  counters live in their own array precisely so the ruleset stays clean read-only data and
  doesn't false-share.)
- **No hash/LPM index in the classifier.** Built the linear scan, measured it at ~1.1 ns/rule
  flat to 512 rules — 512 rules is 16 KiB and fits in a 64 KiB L1d. DIR-24-8 costs a 16 MiB
  table against a 4 MiB L2, so it would *lose* at these rule counts. **The measurement is the
  justification**; above ~32 rules the crossover starts to favour an index.
- **No hot rule reload.** Would need RCU or double-buffering.
- **No IP defragmentation.** Fragments are detected and reported, not reassembled.

---

## Docs

- **`docs/SPEC.md`** — the technical spec. §7 is *"poking holes in my own design"*: ten
  self-inflicted objections, several of which the measurements later proved right (batching and
  software prefetch both turned out to be worthless here — prefetch was **45% worse** at
  distance 32).
- **`docs/CHALLENGES.md`** — every non-obvious bug and decision, written as it happened, with
  the interview answer for each.
