# Challenges, decisions, and the questions they answer

Working log of every non-obvious problem hit while building `pktpipe`, what the
options were, what got chosen, and why. Written as it happened — a bug is only
interesting while the details are still exact.

Format per entry: **the problem → why it's subtle → what I did → what I'd say
if asked.**

---

## Setup: making the résumé bullet true instead of nearly true

**The problem.** The bullet says *"Worked against the Linux networking stack to
capture and process traffic."* The development machine is macOS on an Apple M1.
`AF_PACKET` — the Linux raw-socket interface that phrase refers to — **does not
exist in the Darwin kernel**. macOS captures through `/dev/bpf` character
devices instead. The two are not variants of one another; they are different
interfaces with different semantics.

**Why it's subtle.** There is a tempting middle path: use **libpcap**, which
wraps both, and call it done. But libpcap is *specifically the library you use
to avoid touching the stack directly*, so "I used libpcap" is close to the
opposite of the claim. The other tempting path is `#ifdef __linux__` around
AF_PACKET code that never executes — it compiles, it looks right in a diff, and
it collapses on the first follow-up question ("what happens when the ring
fills?").

**What I did.** Moved the whole project onto Linux via Docker, which runs a real
Linux kernel (6.12.76-linuxkit, arm64) in a VM. Then **verified the assumption
before building on it** — probing AF_PACKET, `veth`, and `perf` on day one
rather than discovering a wall at T10:

```
OK   socket(AF_PACKET, SOCK_RAW) -> fd 3
OK   setsockopt PACKET_VERSION = TPACKET_V3
OK   PACKET_RX_RING mapped: 4 blocks x 4 MiB = 16 MiB, 8192 frames
OK   created veth0 <-> veth1 pair
```

**If asked — "why Docker, and isn't that cheating?"**
> The opposite: it's what makes the claim real. AF_PACKET is a Linux kernel
> interface, and Docker gives me a real Linux kernel — the socket, the
> TPACKET_V3 ring, the veth pair are all genuine kernel objects, not
> simulations. What Docker does *not* give me is a real NIC or bare-metal
> timing, and I say so when quoting numbers. I'd rather run the real interface
> in a VM than ship `#ifdef`'d code I never executed.

---

## Setup: the PMU does not exist under virtualization

**The problem.** The spec originally promised **cycles/packet** as the headline
performance metric. Probing `perf` before relying on it:

```
$ perf stat -e cycles true
   <not supported>      cycles         ← hardware counters
$ perf stat -e cpu-clock true
        0.20 msec cpu-clock            ← software events work
```

**Why it's subtle.** `perf` *runs*. It prints a report. It looks like it worked.
Only the `<not supported>` on the specific event tells you the
performance-monitoring unit isn't there — Virtualization.framework doesn't
expose the M1's PMU to the guest. So `cycles`, `cache-misses`, `branch-misses`
and `LLC-load-misses` are unavailable, and no amount of configuration fixes it.
It would have been easy to not notice, or to quietly report a number computed
some other way and call it "cycles".

**What I did.** Changed the requirement instead of the truth. Dropped
cycles/packet; report **ns/packet** and **Mpps** from
`clock_gettime(CLOCK_MONOTONIC)` on a fixed replay corpus, and profile with
`perf record -e cpu-clock` software sampling — which still identifies hot
functions, which is what finding a bottleneck actually requires. Recorded in
SPEC §7.6.

**If asked — "did you measure cache misses?"**
> No, and I can tell you exactly why. The PMU isn't virtualized on Apple
> silicon under Virtualization.framework, so `perf stat -e cache-misses`
> returns `<not supported>`. I measured wall-clock ns/packet on a fixed corpus
> instead and profiled with perf's software sampler. On bare metal I'd confirm
> the cache-layout win directly with `perf stat -e cache-misses,LLC-load-misses`
> — that's the first thing I'd run if I had the hardware.

*(The willingness to say "I did not measure that" is the point. A fabricated
cycle count dies to one follow-up.)*

---

## T0: a preprocessor directive inside a macro argument list is undefined behavior

**The problem.** First version of `src/version.c` selected the platform string
inline:

```c
snprintf(buf, sizeof buf, "... %s ...",
#if defined(__APPLE__)
         "macOS",
#elif defined(__linux__)
         "Linux",
#endif
         ...);
```

`-Wpedantic` flagged it six times: *"embedding a directive within macro
arguments has undefined behavior"*.

**Why it's subtle.** It compiles. It produces the right string. And `snprintf`
*looks* like a function — but the C library is permitted to implement it as a
**function-like macro** (glibc does exactly this under `_FORTIFY_SOURCE`). C11
§6.10.3p11 says that if a preprocessing directive appears within the arguments
of a function-like macro invocation, the behavior is undefined. The preprocessor
gathers arguments before expanding, and the standard declines to define what
happens if a directive shows up mid-gather.

**What I did.** Hoisted the selection into object-like macros at file scope
(`PP_OS_NAME`, `PP_ARCH_NAME`, `PP_CC_NAME`) and passed those as ordinary
arguments. No directive ever appears inside the call.

**If asked — "why does that matter, it worked?"**
> It worked *on this compiler, today*. That's the definition of the UB trap:
> the failure is deferred to whenever the platform, libc, or optimization level
> changes. It's the same category as the type-punning bug I designed the parser
> to avoid — undefined behavior that happens to produce the answer you wanted.

---

## T1: `struct alignas(64) X {}` is valid C++ and invalid C11

**The problem.** `pp_meta` is declared with a cache-line alignment. Written as
`typedef struct PP_CACHE_ALIGNED pp_meta {...}`, it compiled as C++ and failed
as C with a cascade of `unknown type name 'pp_meta'`.

**Why it's subtle.** The error message points at every *use* of the type, not at
the cause. The real cause: in C++, `alignas` is an attribute specifier that may
sit between `struct` and the tag name. In C11, `_Alignas` is a **declaration
specifier** — legal on a declaration or a struct member, but C's grammar has no
slot for it between `struct` and its tag. So the typedef never parsed and
everything downstream cascaded.

**What I did.** Moved the specifier onto the **first member**, which is legal in
both languages. Both guarantee a struct's alignment is at least its strictest
member's, so the struct still lands 64-aligned and `sizeof` still rounds to 64.

**Root cause worth naming:** these headers are compiled by *both* a C11 and a
C++17 compiler, because the data plane is C and the control plane and all tests
are C++ (SPEC §3.1). A shared header cannot assume either language's spelling —
hence `PP_ALIGNAS` / `PP_ALIGNOF` / `PP_STATIC_ASSERT`. This is the tax for that
architecture, and it's cheap: pay it once, in `pp.h`.

**If asked — "why is the data plane C and the control plane C++?"**
> Predictability where it matters and expressiveness where it doesn't. The rule
> parser wants `std::string`, `std::vector`, RAII, exceptions — and runs once at
> startup, so cycles are irrelevant. The packet hot path wants no hidden
> allocation, no exceptions, no vtables; in C, "there is no allocation in this
> function" is auditable by reading it, because there's no `std::string` to
> quietly heap-allocate behind my back. It's how DPDK and VPP are split, and
> it's also the answer to "how would this port to a DPU?" — the C data plane
> ports, the C++ control plane stays on the host.

---

## T1: the cache-line claim, made unfalsifiable-proof

**The problem.** "Cache-friendly layout" is an adjective. Anyone can write it.
The question is what stops it from quietly becoming false in three months.

**What I did.** A `static_assert` in the header:

```c
PP_STATIC_ASSERT(sizeof(pp_meta) == 64, "pp_meta must be exactly one 64-byte cache line");
PP_STATIC_ASSERT(PP_ALIGNOF(pp_meta) == PP_CACHELINE, "...and cache-line aligned, not merely sized");
```

Then **tested the test** — injected an innocent-looking `uint32_t` into the
struct and compiled:

```
error: static assertion failed: pp_meta must be exactly one 64-byte cache line
note: expression evaluates to '128 == 64'
```

**The part that's worth the whole exercise:** adding **4 bytes** did not make the
struct 68 bytes. It made it **128** — because the struct is 64-aligned, `sizeof`
must round up to a multiple of 64. One innocuous field silently took `pp_meta`
from one cache line to **two**, doubling the metadata footprint of every packet
in flight (2 KiB instead of 1 KiB across a 32-packet batch).

**If asked — "how do you keep a performance property from rotting?"**
> Make the compiler enforce it. A reviewer skimming a PR that adds
> `uint32_t flow_label;` would never guess it doubles cache pressure — the
> rounding is invisible. The static_assert catches it every time, for free, at
> build time. Size *and* alignment both, incidentally: a 64-byte struct starting
> at offset 32 of a line straddles two lines and costs two misses per access,
> so size alone is a half-claim.

---

## T1: two bugs the arena tests exist to catch

**Integer overflow in the exhaustion check.** The natural way to write it is
`if (start + n > cap) return NULL;`. With a huge `n`, `start + n` **wraps**, the
check passes, and the allocator hands back a pointer that runs off the end of
the mapping. Written as `if (n > cap - start)` instead — which cannot wrap,
because `start <= cap` is established first. `suite_overflow_safety` calls
`pp_arena_alloc(&a, SIZE_MAX, 1)` to prove it.

**VLAN 0 is a legal VLAN ID.** `pp_meta_init` deliberately does *not* leave the
VLAN fields at zero after its `memset`. An 802.1Q tag with VID 0 is a
*priority-tagged* frame — real switches emit them. If 0 meant "no VLAN", a
priority-tagged frame would be indistinguishable from an untagged one, and a
rule matching `vlan 0` would silently match all untagged traffic. Hence
`PP_VLAN_NONE = 0xFFFF`, a value the 12-bit wire field cannot produce.

**If asked — "how do you pick a sentinel?"**
> It has to be a value the wire format cannot generate. Zero almost never is.
> The general shape of the bug: a sentinel that collides with legal data turns
> a parse into a silent misclassification, which is worse than a crash because
> nothing tells you.

---

## Environment: `MAP_ANONYMOUS` compiled on macOS and failed on Linux

**The problem.** `src/arena.c` built clean on macOS. First build inside the
Linux container:

```
error: 'MAP_ANONYMOUS' undeclared (first use in this function)
```

**Why it's subtle.** `MAP_ANONYMOUS` is **not ISO C and not POSIX** — it's a
BSD/GNU extension. The build uses `-std=c11`, not `-std=gnu11`
(`CMAKE_C_EXTENSIONS OFF`), and under strict ISO mode **glibc hides every
non-standard symbol**: `sys/mman.h` guards `MAP_ANONYMOUS` behind `__USE_MISC`.
Apple's SDK headers have no such guard and expose it unconditionally. So
identical source is clean on one platform and broken on the other — and nothing
about the code looks non-portable.

**What I did.** `#define _DEFAULT_SOURCE` **before any libc include** — feature
test macros are read by the headers as they're included, so defining it after
the first `#include` does nothing at all. Kept `-std=c11` rather than switching
to `-std=gnu11`, because strict mode forces every non-standard dependency to be
declared out loud instead of absorbed silently.

**If asked — "what did building on Linux catch that you'd have missed?"**
> This, on the first compile. It's the exact class of bug that `#ifdef
> __linux__`-and-hope produces: code that looks portable, compiles on the
> machine you're sitting at, and fails on the platform you claim to target. It's
> also a fair argument for feature test macros over `-std=gnu11` — the fix
> documents *which* extension is being relied on.

---

## T2: the type-punning UB every packet parser has — and proving the fix is free

**The problem.** The obvious way to read a wire field:

```c
const struct ethhdr *eth = (const struct ethhdr *)(pkt + off);
uint16_t type = ntohs(eth->h_proto);
```

Three defects at once, and it's what most parsers do:

1. **Alignment.** `pkt + off` is wherever the last header ended — offset 14 after
   Ethernet, even but not 4-aligned. Casting to a struct wanting 2/4-byte
   alignment yields a misaligned pointer. x86 and arm64 tolerate it; stricter
   targets fault, and UBSan flags it everywhere.
2. **Strict aliasing.** Reading `unsigned char` bytes through an unrelated
   struct type is UB. The compiler may assume a `struct ethhdr *` and a
   `uint8_t *` never alias, and at `-O2` reorder or cache loads accordingly.
   The "worked until we upgraded the compiler" class.
3. **Endianness.** Needs `ntohs()` at every field. Miss one and it's wrong only
   on little-endian — i.e. on every machine you'll test on.

**Why it's subtle.** It works. It has worked for decades in shipping code. The
failure is deferred to a compiler upgrade or a port.

**What I did.** Read every multi-byte field with byte loads composed by shifts:

```c
static uint16_t pp_rd_be16(const uint8_t *p) { return p[0] << 8 | p[1]; }
```

All three defects die at once: `uint8_t` is a character type and may alias any
object; byte loads have no alignment requirement; and big-endian is spelled out
*arithmetically*, so it's correct on any host with **no ntohs and no #ifdef** —
host byte order never enters the picture.

Notably I did **not** reach for `-fno-strict-aliasing`, which is the usual
"fix". That disables the optimization that exposes the bug rather than removing
the bug, and costs performance everywhere else in the program.

**The objection, and the proof** (`tools/disasm_check.sh`, checked in so it stays
true across compiler upgrades). "Byte-at-a-time must be slower":

```
gcc 12.2 -O2, arm64          clang 14 -O2, arm64
safe_byteload16:             safe_byteload16:
  ldrh  w0, [x0]               ldrh  w8, [x0]
  rev16 w0, w0                 rev   w8, w8
  ret                          lsr   w0, w8, #16
unsafe_cast16:               unsafe_cast16:
  ldrh  w0, [x0]               ldrh  w8, [x0]
  rev16 w0, w0                 rev   w8, w8
  ret                          lsr   w0, w8, #16
```

**Identical.** One unaligned load, one byte-reverse. The safe idiom is free —
both compilers recognise it. (Bonus finding from running both: gcc finds the
dedicated `rev16`; clang 14 does a 32-bit `rev` then shifts, one instruction
more. A real codegen difference, and an argument for building with both.)

**If asked — "isn't reading byte-by-byte slow?"**
> It compiles to the same two instructions as the cast — I checked the
> disassembly on gcc and clang, and the script is in the repo. So it isn't a
> correctness-vs-speed trade at all; the UB version is just a worse way to write
> the same machine code. It buys nothing and costs you a compiler upgrade.

---

## T2: I made the exact bug I had just written a test to prevent

**The problem.** `test_l2`'s every-prefix sweep failed on one check out of 327:
`CHECK(m.caplen <= n)` at `n == 0`.

**The cause.** My own test helper:

```cpp
pp_rawpkt view(uint32_t caplen = 0, ...) {
    p.caplen = caplen ? caplen : uint32_t(b_.size());   // 0 means "unspecified"
}
```

The sweep calls `view(0)` meaning *"capture zero bytes"*. The helper read 0 as
*"caller didn't say, use the full length"* and silently substituted 60.

**Why it's worth writing down.** This is **the same bug class as `PP_VLAN_NONE`**
— using 0 as a sentinel when 0 is a legal value. I had, in the same session,
written `pkt.c`'s comment explaining why VLAN 0 can't mean "no VLAN", and a test
named `suite_vlan_id_zero_is_legal`... and then did it again 200 lines later in
the test helper. Knowing a bug class evidently does not confer immunity to it.

**What saved it:** the test swept **the entire range including the boundary**
(`for n in 0..size`) rather than spot-checking a value in the middle. A test of
`n = 10` would have passed and the helper would still be wrong.

**What I did.** `static constexpr uint32_t UNSET = UINT32_MAX;` — a value the
domain cannot produce, so it can safely carry "absent".

**If asked — "tell me about a bug you caused":**
> I used 0 as a "not specified" sentinel in a test helper, for a field where 0
> is a legal value — which is the same mistake I'd written a test to catch in
> the parser an hour earlier. It's a good argument for two things: sentinels
> must be values the domain can't produce, and boundary sweeps beat spot checks.
> A test at n=10 would have passed happily.

---

## T2: three VLAN TPIDs, and the failure mode that doesn't crash

**The problem.** Which ethertypes indicate a VLAN tag? The obvious answer,
`0x8100`, is incomplete. Real traffic carries three:

| TPID | What |
|---|---|
| `0x8100` | 802.1Q — the ordinary C-tag |
| `0x88A8` | 802.1ad — S-tag, provider bridging (QinQ proper) |
| `0x9100` | pre-standard QinQ, still emitted by older gear |

**Why it's subtle — and this is the real lesson.** Matching only `0x8100` does
not crash. A QinQ frame's outer tag reads as "ethertype `0x88A8`", which matches
neither IPv4 nor IPv6, so the packet is quietly classified *not IP* and stops
matching every rule you wrote. **No crash, no log, no alert — it just silently
stops working.** That's strictly worse than a crash, because nothing tells you.

**Related, same shape:** an ethertype field `< 1536` is not an ethertype at all —
it's an 802.3 **length**, with LLC/SNAP following. Read a 1400-byte 802.3 frame
as "ethertype 0x0578" and you walk perfectly valid bytes as though they were IP,
producing garbage offsets. `pktpipe` checks `>= PP_ETH_TYPE_MIN` and declines to
decode rather than guess.

**If asked — "what's the worst kind of parser bug?"**
> Not the crash. The silent misparse — where valid bytes get read as a
> different structure and you get plausible-looking garbage. A crash tells you
> where it happened. A packet that quietly stops matching your rules is found
> weeks later by a customer.

---

## T2: bounded loops, because tag depth is attacker-controlled

**The problem.** `while (is_vlan_tpid(ethertype)) { ...consume tag... }` is the
natural loop and is a **remote DoS**. Nothing in the frame format limits the tag
count; a crafted frame carries a hundred stacked `0x8100` tags and the parser
walks all of them while the NIC keeps delivering more. It never crashes — it
just stops keeping up, which is the goal of the attack.

**What I did.** `PP_MAX_VLANS = 2` (a C-tag inside an S-tag is everything real
traffic has), refuse past the cap with `PP_ERR_TOO_MANY_VLANS`, and **keep the
tags already decoded** — a bounded parser reports what it learned instead of
discarding the packet. `suite_vlan_bomb_is_bounded` feeds it 100 tags;
`suite_exactly_max_vlans_is_ok` checks the cap doesn't reject legitimate QinQ,
because a bound that's too tight is also a bug and a more embarrassing one.

Same defence, same reason, at every attacker-controlled repetition: IPv6
extension-header chains (T3, `PP_MAX_IP6_EXTHDRS = 8`) and tunnel nesting (T4,
`PP_MAX_TUNNEL_DEPTH = 1`).

**If asked — "how do you make a parser safe against hostile input?"**
> Bound every loop whose trip count the sender controls, bound every read by
> the captured length rather than by any length field inside the packet, and
> treat malformed input as data rather than as an exception — on a real link,
> malformed traffic *is* normal traffic. Then test it: about half of my L2 suite
> is hostile frames, including feeding every prefix of a valid packet to prove
> no prefix crashes or over-reads.

---

## T3: a test failure that was an API design flaw, not a bug

**The problem.** `suite_ipv4_df_is_not_a_fragment` failed:
`CHECK_NE(rc, PP_ERR_UNSUPPORTED_L3)` — *"both 13"*.

**The diagnosis.** `pp_parse` was using **one error code for two unrelated
meanings**:

1. *"This packet is fine, but has no L4"* — a later fragment, ESP, ARP.
2. *"The L4 parser isn't written yet"* — a T4 stub.

The fragment test literally could not express what it meant, because the code it
needed to assert on was overloaded. The test didn't find a typo; it found that
**the function's contract was wrong**.

**What I did.** Split the two questions apart:

> The **return value** answers *"is this packet malformed?"*
> `m->layers` answers *"how deep did we get?"*

An ARP frame is the cleanest proof that these are different questions: a
perfectly good packet (`PP_OK`) with no L3 whatsoever (`layers == L2`). So is a
later IP fragment — valid, classifiable at L3, carrying no L4 because the L4
header was in fragment #1. So is an ESP packet whose payload is ciphertext. None
of those is an *error*, and a parser that reports them as errors forces its
caller to treat "fine" and "broken" identically.

**If asked — "tell me about a design mistake you caught":**
> I had one error code meaning both "this packet is broken" and "this packet is
> fine but has nothing more to parse". Those are different facts and callers
> need to act on them differently — a classifier wants to *match* a later
> fragment on its IP header, not discard it as malformed. The test caught it
> because I couldn't write the assertion I wanted. That's usually the signal:
> when a test is awkward to express, the API is usually the thing that's wrong.

---

## T3: three length rules for IPv6 extension headers, and only one is obvious

**The problem.** Every IPv6 extension header starts identically — `next_header`,
`hdr_ext_len` — and then the length rule is **not uniform**:

| Header | Length rule |
|---|---|
| Hop-by-Hop(0), Routing(43), DestOpts(60), Mobility(135) | `(hdr_ext_len + 1) * 8` — units of 8, excluding the first 8 |
| **Fragment(44)** | **Fixed 8.** The `hdr_ext_len` byte is **RESERVED**, not a length |
| **Auth Header(51)** | **`(hdr_ext_len + 2) * 4`** — units of **four**, and **+2** |
| ESP(50) | unparseable — the rest is encrypted, chain ends |

**Why it's subtle — and this is the good part.** Apply the general `(len+1)*8`
rule to a **Fragment** header and you get `(0+1)*8 = 8`, which is **correct** —
because the reserved byte is *usually* zero. So the bug works perfectly until
someone sends a fragment header with junk in that reserved byte, and then the
parser strides `(200+1)*8 = 1608` bytes into oblivion. A bug that passes every
test you'd naturally write.

**AH** is the one everyone gets wrong. With `hdr_ext_len=1`: correct is
`(1+2)*4 = 12`; the general rule gives `(1+1)*8 = 16`. Four bytes too far —
landing *inside* the TCP header and reading a byte of it as the next protocol
number. It doesn't crash. It produces confident nonsense.

**What I did.** One function, `ip6_ext_len()`, holding all three rules, so the
chain walk reads as a loop rather than a museum of special cases. Tests:
`suite_ipv6_ah_has_its_own_length_rule` and
`suite_ipv6_fragment_header_is_fixed_8` — the latter deliberately puts `200` in
the reserved byte to prove it's ignored.

**If asked — "what's the hardest part of parsing IPv6?"**
> The extension header chain, and specifically that the length rules aren't
> uniform. AH is `(len+2)*4` while everything else is `(len+1)*8`, and the
> Fragment header is fixed-8 with a reserved byte where the length would be. The
> nasty one is Fragment: the general rule *accidentally* computes the right
> answer whenever that reserved byte is zero, which it normally is — so the bug
> hides until someone sets it. I test that case with junk in the reserved byte.

---

## T3: the IPv4 mask bug that breaks most of the internet

**The problem.** The IPv4 flags/fragment word is 3 bits of flags then a 13-bit
offset. Read it without masking and `DF` (`0x4000`) makes `frag_off` come out as
**8192**.

**Why it matters.** Every DF-marked packet then looks like a mid-stream
fragment — and DF is set on essentially all modern TCP traffic (path MTU
discovery). So the parser decides most of the internet has no L4 header and
silently stops classifying it. No crash. `suite_ipv4_df_is_not_a_fragment` is
one line of setup and pins it forever.

**The companion fact:** only the **first** fragment (offset 0) carries the L4
header. Later fragments start mid-payload — the bytes at `l4_off` are user data,
and reading them as TCP invents port numbers out of somebody's HTTP body. That's
a real evasion technique: send a later fragment crafted so its payload bytes
look like ports your rules allow. `pktpipe` reports `sport`/`dport` as 0 and
sets no `PP_LAYER_L4`.

---

## T3: never trust a length field, and the two ways IHL lies

**The rule (SPEC §7.9).** Every length in an IP header is a **claim made by the
sender**. `pktpipe` reads them to *notice contradictions*, never to bound a read.
Reads are bounded by `caplen` — what we actually have — and nothing else.

**IHL fails in two different ways, and conflating them is itself a bug:**

- `IHL < 5` claims a header shorter than the fixed header itself. That's not a
  short header, it's a **lie** → `PP_ERR_BAD_IHL`. Believing it advances the
  cursor under 20 bytes and every later offset is wrong — src/dst get read out
  of the middle of the header.
- `IHL * 4 > caplen` is a **legal header we simply don't have all of** →
  `PP_ERR_TRUNC_L3`. Different cause, different diagnosis, same discipline.

**The one that surprises people:** `totlen = 60000` in a 54-byte capture is
**not an error**. That's what a snaplen-truncated capture looks like every single
day. A parser that "validates" it rejects normal traffic; a parser that *trusts*
it reads 60,000 bytes off the end of the buffer. The only correct move is to
ignore it for bounds entirely — which is what
`suite_ipv4_totlen_absurdly_large_is_harmless` pins down.

**If asked — "how do you handle a length field that disagrees with reality?"**
> Never let it bound a read — bound everything by the captured length instead.
> The length field is data from a stranger. I read it only to detect
> contradictions worth flagging, like a total length smaller than its own
> header. And I'm careful that "the field is bigger than my buffer" is *normal*,
> not hostile — that's just snaplen truncation, and treating it as an error
> would drop legitimate traffic.

---

## T4: a tunnel is recursion, and recursion on hostile input is a stack overflow

**The problem.** A VXLAN packet's payload is **a complete Ethernet frame** —
another packet, from the top. So parsing is naturally recursive:
`parse(pkt) -> ... -> parse(inner)`.

**Why it's subtle.** The recursion depth is **attacker-controlled**. Nest VXLAN
inside VXLAN inside VXLAN and a recursive parser pushes a stack frame per layer;
a deep enough nest blows the stack from a **single frame**. That's not a
slowdown, it's a crash — potentially an exploitable one.

**What I did.** Wrote the tunnel walk as a **loop**, not recursion:

```c
for (;;) {
    parse_l2(&c, m); parse_l3(&c, m); parse_l4(&c, m);
    if (!looks_like_vxlan(m)) break;
    if (depth >= PP_MAX_TUNNEL_DEPTH) return fail(m, PP_ERR_TOO_DEEP_TUNNEL);
    ... consume VXLAN header, reset_for_inner(m), depth++ ...
}
```

Memory cost is now **constant** — there is no stack to overflow because there
are no frames to push. The depth cap becomes purely a CPU question (SPEC §7.8),
which is a much easier thing to reason about than stack headroom.

**The second bug, which the loop introduces.** Re-entering means the inner parse
overwrites the outer's metadata. `reset_for_inner()` must clear *exactly* the
fields the next layer re-derives and nothing else — `vni`, `tunnel_depth`,
`outer_l3_off`, `caplen` all have to survive. Get it wrong and outer values leak
into the inner packet: an inner frame with **no** VLAN inherits the outer frame's
VLAN 77 and then matches a `vlan 77` rule it has nothing to do with. That's
`suite_vxlan_inner_vlan_does_not_leak`.

**The design decision worth defending.** `pp_meta` describes the **innermost**
headers, because the tenant's real 5-tuple is what a rule wants to match. But
then `inner_l3_off` would be a redundant copy of `l3_off`, so the field became
`outer_l3_off` — retaining the underlay, which is the thing that would otherwise
be lost. You can classify on the overlay (which tenant flow) *and* the underlay
(which physical hosts).

**If asked — "how would you parse a tunnelled packet?"**
> Iteratively, with a depth cap. The payload is another packet so it's naturally
> recursive, but recursion depth would then be controlled by whoever sent the
> frame — that's a stack overflow from one packet. A loop makes the memory cost
> constant and the cap auditable. And I'd be careful about what carries over
> between iterations: the inner packet must not inherit the outer's VLAN or
> ports, which is its own class of silent misclassification.

---

## T5: tcpdump found a bug my own tests could not

**The problem.** `pktgen` generates the benchmark corpora. All my tests passed. Then I opened
the file with tcpdump as a sanity check:

```
22:13:20.000000 IP 192.168.1.68 > 10.0.92.137: [|tcp]
```

`[|tcp]` means *tcpdump thinks the packet is truncated*. It wasn't.

**Why it's subtle — and why my tests couldn't see it.** The builder wrote IPv4 `totlen` = the
*header* length, because when the header is written the payload doesn't exist yet. pktpipe's
parser **deliberately ignores `totlen`** (SPEC §7.9 — never trust a length field), so it parsed
these packets perfectly and every test went green. tcpdump *does* trust `totlen`, so it saw
"total length 20" and concluded there was no TCP header.

**Both readers are behaving correctly.** Mine is arguably *more* robust. But my corpus was
unrealistic, and a benchmark on unrealistic packets measures the wrong thing.

**What I did.** Added `fix_ipv4_totlen()` / `fix_ipv6_plen()` / `fix_udp_len()` back-patchers —
a header's length describes bytes that don't exist yet when it's written, which is also why
real senders compute lengths and checksums in a second pass. tcpdump then decoded everything,
including the VXLAN tunnels (outer `10.0.0.1 → 10.0.0.2:4789 vni 5014`, inner
`172.16.0.218 → 172.16.1.1:8080`).

**If asked — "how do you know your test data is right?"**
> I didn't, until I checked it against an independent implementation. My tests passed on a
> broken corpus because my parser ignores the field that was wrong — a test suite that only
> checks my code against my code agrees with itself by construction. tcpdump found it in one
> command. The general lesson is that self-testing has a blind spot exactly the shape of your
> own assumptions, and the cheap fix is to cross-check against a tool that made different ones.

---

## T9: making "no allocation" falsifiable

**The problem.** The résumé says *"avoiding per-packet allocation on the hot path"*. Reading the
code and seeing no `malloc` proves **nothing**: `std::string` allocates, `std::vector` growth
allocates, a C++ exception allocates, some `printf` paths allocate. "I checked" is not evidence.

**What I did.** Replaced the process's allocator with one that counts. Define `malloc`, `free`,
`calloc`, `realloc` and `operator new`/`delete` in the test binary — the linker prefers our
strong symbols over libc's for every call site, **including calls from inside libstdc++**.
Then: build everything, **arm** the counter, run 50,000 packets, disarm, assert zero.

```
[proof] 50000 packets, 1563 batches, 4056106 bytes -> 0 allocations
```

**Three details that make it real rather than theatre:**

1. **Forwarding to the real allocator.** The textbook move is `dlsym(RTLD_NEXT, "malloc")` —
   which has a chicken-and-egg problem, because `dlsym` may itself allocate and would call our
   `malloc`. glibc exports `__libc_malloc` directly, sidestepping the whole dance.
2. **The test tests itself first.** `suite_interposer_actually_works` allocates deliberately and
   asserts the counter moved. An interposer that silently failed to link would make every other
   check pass **vacuously** — a proof that proves nothing while looking green.
3. **It asserts the work happened.** A pipeline that processed zero packets also allocates zero.
   So the test checks 50,000 packets, 1,563 batches, and that the malformed-packet paths were
   actually hit.

**The payoff:** if someone adds a `std::vector` to the parser in six months, **this test fails**.
The claim can't rot silently.

**If asked — "how do you know there's no allocation?"**
> I intercept the allocator and count. Not just `malloc` — `operator new` too, because
> libstdc++ isn't *required* to route it through `malloc`, and a claim shouldn't depend on an
> implementation detail of the C++ runtime. The counter arms after setup and asserts zero
> across 50,000 packets spanning every parser branch including the error paths. And the test
> verifies the interposer works before trusting it, because a silently-unlinked interposer
> would make the whole thing pass for the wrong reason.

---

## T10/T11: the result that justifies the whole ring

**The problem.** Is `PACKET_MMAP` actually worth the complexity — the shared mapping, the
ownership protocol, the memory barriers? The honest way to find out is to build the simple
thing too and measure both.

**The measurement.** 50,000 frames offered on a veth pair at ~1 Mpps:

| | `recvfrom` (a syscall per packet) | `mmap` ring (TPACKET_V3) |
|---|---|---|
| captured | 13,503 | **50,000** |
| **kernel drops** | **36,513 — 73% of the link** | **0** |
| syscalls / 3,000 packets | 743 | **7** |
| packets per syscall | ~0.5 | **~430** |

**`recvfrom` didn't run slower — it lost three quarters of the traffic.** And the only reason I
know is `PACKET_STATISTICS`. Without drop accounting the tool would have printed
*"13,503 packets processed, 0 errors"* and looked perfectly healthy.

**The subtlety in reading drops.** The kernel **resets** `tp_drops` when you read it. Writing
`st.kernel_drops = ts.tp_drops` looks right and reports only the drops since the last poll — so
a run that dropped steadily reports whatever happened in the final 100 ms and calls it the
total. It must be `+=`. Easy bug, and it under-reports in the direction that flatters you.

**If asked — "AF_PACKET or libpcap? How did you size the ring? Did you drop?"**
> AF_PACKET directly, with a PACKET_MMAP TPACKET_V3 ring — libpcap is the library you use to
> *avoid* touching the stack directly. I sized it at 16 MiB, 4 blocks of 4 MiB, 2 KiB frames:
> at ~1500 B/frame that's ~11k frames, about 11 ms of absorption at 1 Mpps, which is enough to
> ride out a scheduler hiccup without dropping — that's what the ring is *for*. And yes I
> measured drops, because I built the naive `recvfrom` path too: it lost **73%** of a 1 Mpps
> link where the ring lost nothing. About 430 packets per syscall versus half a packet per
> syscall.

**Hard follow-up — "what's `tp_retire_blk_tov` and what happens if you forget it?"**
> It's the timeout after which the kernel releases a partially-filled block to userspace. If
> you leave it at 0, a block that never fills is never handed over — so on a quiet link your
> packets simply never arrive and everything looks broken with no error. It's also the latency
> knob: bigger blocks mean fewer handoffs but more delay before a partial block is released.

---

## T11: the memory barrier, and why it isn't optional

**The problem.** The ring is memory shared with the kernel. Reading `block_status` and reading
the frames are two loads from that memory, and **both the compiler and the CPU may reorder
them**. The compiler can hoist a frame load above the status check, because as far as it can
see nothing in this thread writes either. The CPU can speculate them out of order. Neither
knows another agent — the kernel, possibly on another core — is writing this memory.

**What goes wrong.** If a frame load is reordered *before* the status load, you read the frame
**before the kernel finished writing it**: torn or stale packet data. No crash. No error. It
works in testing and fails under load — the worst failure mode there is.

**What I did.** A full barrier between "I observed `TP_STATUS_USER`" and "I read the frames",
and another between "I finished reading" and "I release the block". The second matters just as
much: releasing early lets the kernel overwrite frames you haven't read yet.

`__sync_synchronize()` — a full hardware **and** compiler barrier. On arm64 that's `dmb ish`;
on x86-64 `mfence`, where the strong memory model makes it nearly free. A plain
`asm volatile("" ::: "memory")` would stop the *compiler* reordering but not the *CPU* —
sufficient on x86, **wrong on arm64**. This runs on both, so it has to be the real thing.

The `block_status` read is also `volatile`, so the compiler re-loads it each time round instead
of caching it in a register and spinning forever on a stale value — a genuine hang.

**If asked — "why do you need a barrier there?"**
> It's the same acquire/release pairing as any lock-free queue; the only unusual part is that
> the other thread is the kernel. I need the frames to become visible after I observe the
> status flag, and I need my reads to complete before I hand the block back. Without it the
> CPU can reorder the loads and I read a frame the kernel hasn't finished writing — torn data,
> no crash, only under load. And it has to be a full barrier, not just a compiler barrier: on
> x86 the memory model would cover me, on arm64 it wouldn't, and this runs on arm64.

---

## T10: a bug the benchmark found by hanging

**The problem.** The `recvfrom` path used `MSG_DONTWAIT`. When no packet was ready it returned
`EAGAIN` → returned 0 → the caller looped and asked again → **busy-spun a core at 100% forever**
on an idle link. `--count` was only checked after a non-zero batch, so it never terminated.

Found because a benchmark **timed out after 7 minutes** instead of finishing — and left a
container running in the background for 23 minutes.

**Why it's subtle.** Returning 0 for "nothing right now" is *correct* — the caller has no way to
distinguish "no traffic yet" from "keep asking". The mmap path already had `poll()`; the
recvfrom path didn't, and it was never noticed because every test until then had traffic
waiting.

**What I did.** `poll()` on `EAGAIN`, mirroring the mmap path. The two modes should differ in
*how* they get frames, not in whether they melt a core when there are none.

**If asked — "how did you find that?"**
> A benchmark hung instead of finishing. That's a fair way to find it, and it's a reminder that
> "returns the right answer" and "behaves correctly" aren't the same property — the function was
> returning a perfectly correct 0 while burning a core.

---

## T12: two optimizations I implemented, measured, and turned off

**The problem.** SPEC §4 gave three confident reasons batching wins, and a latency-hiding
argument for software prefetch. Both are textbook. Both are wrong here.

**Batching, measured:**

| batch | uniform_tcp | mixed |
|---|---|---|
| 1 | 21.6 ns | 33.8 ns |
| **2–4** | **20.6 ns (best)** | **33.0 ns (best)** |
| 32 (DPDK's default, which I inherited) | 22.5 (**+4%**) | 36.9 (**+9%**) |
| 256 | 22.3 | 39.4 (**+16%**) |

**Prefetch, measured:**

| distance | uniform_tcp | mixed |
|---|---|---|
| 0 (off) | 22.7 ns | 36.9 ns |
| 4 (my default) | 22.6 | 37.1 |
| 8 | 22.5 | 41.5 (**+12.5%**) |
| 32 | 22.5 | 53.7 (**+45.6%**) |

**Why the reasoning failed.** Both arguments assumed conditions that don't hold on a replay
path: batching amortizes **syscalls** (there are none — the pcap is `mmap`'d) and keeps the
**I-cache** hot (it already is — the parser is the only code running). Prefetch hides **cache
misses** (there aren't any to hide — the corpus is walked sequentially, which is exactly what
the *hardware* prefetcher is built to predict, and it's already running ahead of us). The
software prefetch adds no information and isn't free: it burns bandwidth and, at distance,
**evicts lines we're about to need** — hence the branchy mixed corpus degrading twice as badly.

**But batching isn't useless — it pays somewhere else.** Same question on the live path:
`recvfrom` lost **73%** of the link where the batched ring lost **0%**, at ~430 packets/syscall
vs ~0.5. That's where the amortization argument was true all along.

**What I did.** Changed `PP_PREFETCH_DEFAULT` from 4 to **0**, because the data says so. Kept
batch at 32 — not from inheritance, but because the live path (the one the résumé claim is
about) needs it and the replay cost is a few percent. Left prefetch in as a tunable: a real NIC
ring with scattered frames is a genuinely different access pattern.

**If asked — "what optimizations did you do?"**
> The interesting ones are the two I *removed*. I implemented software prefetch because the
> textbook says to, measured it, and it was up to **45% worse** — the hardware prefetcher
> already handles sequential access, so mine just evicted useful lines. Same story with batch
> size: I'd inherited 32 from DPDK and it was 4-9% *slower* than 2 on replay. But batching
> turned out to matter enormously on the live path, where there are syscalls to amortize —
> 73% packet loss without it. So the honest answer is that batching's value is about syscall
> amortization, not cache locality, and I only know that because I built both and measured.

**Hard follow-up — "so why is your default still 32 if 4 is faster?"**
> Because the two paths disagree and one of them matters more. On replay, 32 costs me ~4%. On
> the live AF_PACKET path, batching is the difference between capturing the link and losing
> three quarters of it. I optimize for the path that's real; the replay is a measurement
> instrument, not the product.

---

## T13: an unexplained 5.8x, and a wrong hypothesis

**The problem.** A single pass over the corpus: **~68-111 ns/packet**. The same run with
`--repeat 20`: **~19 ns/packet**. Same code, same bytes. And it happened with **zero rules**, so
the classifier wasn't involved.

**My hypothesis was wrong**, which is the part worth keeping. "Page faults on the mmap'd file —
3.8 MB is 927 pages, so 927 faults." Measured with `perf stat -e page-faults` (a *software*
event, so it works despite the missing PMU):

```
COLD (repeat=1):   67.9 ns/pkt    172 page-faults
WARM (repeat=20):  19.9 ns/pkt    171 page-faults    <- identical
```

**172, not 927 — and the same either way.** Linux does **fault-around** on file-backed mappings:
one fault populates ~16 pages (64 KiB). So 3.8 MB costs ~58 faults; the rest is binary and libc.
"One fault per page" is simply wrong for file mappings.

**What it actually is.** First pass ≈ 3.4 ms, each later pass ≈ 0.87 ms. The gap is the
**memory system**: cold data cache (3.8 MB from DRAM), cold TLB (927 pages vs ~1500 dTLB
entries), cold I-cache, untrained branch predictors.

**And it exposes a flaw in my own benchmark.** The corpus is **3.8 MB**; L2 is **4 MB**. So
`--repeat 20` means 19 of 20 passes read packets **already in L2**. A real NIC DMAs packets into
memory that is **never** cached. So ~19 ns is our code with a free memory system; ~68 ns is
closer to reality.

**If asked — "what's your per-packet cost?"**
> About 19 ns warm and 68 ns cold, and the difference is L2 residency — not page faults, I
> checked, it's 172 either way because of fault-around. My corpus is 3.8 MB against a 4 MB L2,
> so replaying it measures a warm memory system, which flatters me. A real NIC never hands you
> warm packets, so 68 ns is the more honest number to plan against. The fix is a corpus several
> times larger than L2; that's a known gap, not a solved one.

---

## T14: 41 million inputs

**The problem.** ~1,500 hand-written assertions all check a case **I thought of**. That's a hard
limit — the bugs that survive review are the ones nobody imagined. And a packet parser's input
is chosen by a stranger.

**What I did.** A libFuzzer target with ASan + UBSan. Two design points:

1. **The first byte steers `caplen`**, independently of content — so the fuzzer can explore
   **truncation** as a dimension. Otherwise `caplen` would always equal the buffer size and it
   could only ever produce "complete" packets. Truncation is where parsers die.
2. **Invariants, not just crash-detection.** A fuzzer without assertions only finds segfaults.
   Mine asserts: no offset past `caplen`, layers monotonic (no L4 without L3), offsets ordered,
   depth caps respected, `ip_ver ∈ {0,4,6}`, and **determinism** (parse twice, `memcmp` the
   results — catches reads of uninitialized memory).

```
Done 41,085,992 runs in 91 seconds
average_exec_per_sec:  451,494
slowest_unit_time_sec: 0
```

**41 million inputs, zero crashes.** And `slowest_unit_time_sec: 0` is quietly the best line: no
input made the parser hang, which is direct evidence the DoS caps work. A VLAN bomb would have
shown up right there.

**If asked — "how do you know the parser is safe?"**
> Two ways that cover different things. ~1,500 hand-written assertions for the cases I could
> think of — including sweeping *every* prefix of a valid packet, because truncation is the
> killer. And a fuzzer for the cases I couldn't: 41 million inputs with ASan and UBSan armed,
> zero crashes. The sanitizers are the point — without them a one-byte over-read just returns
> whatever was next in memory and the fuzzer sails past it. I also assert invariants inside the
> fuzz target so that "wrong" becomes "crash" and the fuzzer can actually see it.

---

## Environment: the same CPU reports two different cache line sizes

**The problem.** `tools/cacheinfo` asks the OS for the L1 line size. Same
physical M1, two answers:

| Asked from | Interface | Answer |
|---|---|---|
| macOS host | `sysctl hw.cachelinesize` | **128** |
| Linux guest (Docker, same silicon) | `getconf LEVEL1_DCACHE_LINESIZE` | **64** |

**Why it's subtle.** Both are "the hardware cache line size". Neither is lying.
Virtualization.framework doesn't pass the host's real cache geometry to the
guest, so the guest kernel reports 64. Nothing warns you; each side is
internally consistent.

**What I did.** Nothing — the design was already right, and this is *why* it was
right. `PP_CACHELINE` is 64: the **stricter** of the two, and the value that
matters on x86-64 servers and Arm DPU cores regardless. Had the macOS 128 been
trusted, `pp_meta` would be 128 bytes and therefore **two cache lines on the
exact machine every benchmark runs on**.

**If asked — "what's your cache line size?"**
> Depends who you ask, which is the interesting part. macOS reports 128 for the
> M1; the Linux guest on the same chip reports 64. So I designed the struct to
> 64 — the tightest bound, correct in both, and correct on the x86 and Arm
> server cores this would actually ship to. The general lesson is that hardware
> introspection is OS- and hypervisor-mediated, so a performance claim should
> name the machine *and* the interface it was measured through.
