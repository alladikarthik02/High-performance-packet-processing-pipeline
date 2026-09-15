// fuzz_parse — throw arbitrary bytes at the parser and see if it breaks.
//
// WHY THIS EXISTS, given there are already ~1,500 hand-written assertions:
//
// Every test in this repo checks a case I THOUGHT OF. That is the limit of
// hand-written tests, and it is a hard limit — the bugs that survive review are
// exactly the ones nobody imagined. A fuzzer does not think; it tries millions
// of inputs per minute and is guided by coverage feedback toward the branches
// nobody reached. It finds the case I could not have written down.
//
// This matters more for a packet parser than for almost anything else, because
// the input is chosen by a stranger. Every byte the parser reads is a byte
// somebody else picked, possibly on purpose.
//
// Build & run:
//   ./docker/dev.sh run bash -c 'clang++ -std=c++17 -g -O1 \
//        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
//        -Iinclude tests/fuzz_parse.cpp src/parse.c src/pkt.c -o /tmp/fuzz'
//   ./docker/dev.sh run /tmp/fuzz -max_total_time=60 pcaps/fuzz_corpus/
//
// The sanitizers are the point. libFuzzer only supplies inputs; ASan and UBSan
// are what turn a silent memory bug into a loud crash:
//   ASan  — reads past the packet buffer. THE bug class for a parser.
//   UBSan — misaligned loads, shifts past width, signed overflow.
// Without them a one-byte over-read just returns whatever was next in memory
// and the fuzzer sails past it none the wiser.
#include "pp/parse.h"
#include "pp/pkt.h"

#include <cstdint>
#include <cstddef>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // libFuzzer hands us a buffer of arbitrary bytes and arbitrary length —
    // exactly what arrives on a wire from someone who does not like you.
    if (size < 1) return 0;

    // The first byte steers caplen so the fuzzer can explore TRUNCATION
    // independently of content. This matters: truncation is where parsers die,
    // and if caplen were always == size the fuzzer could only ever produce
    // "complete" packets. Now it can hand us "a 300-byte packet of which we
    // captured 4" — the snaplen case, which is real (SPEC §7.9).
    uint32_t declared_cap = data[0];
    const uint8_t *pkt = data + 1;
    size_t avail = size - 1;

    uint32_t caplen = declared_cap == 0 ? uint32_t(avail)
                                        : uint32_t(declared_cap % (avail + 1));

    pp_rawpkt raw{};
    raw.data    = pkt;
    raw.caplen  = caplen;
    // wirelen >= caplen, and deliberately allowed to be much larger. If the
    // parser ever trusts wirelen as a bound instead of caplen, ASan fires here
    // and not in production.
    raw.wirelen = uint32_t(avail) + declared_cap;
    raw.ts_ns   = 0;

    pp_meta m;
    int rc = pp_parse(&raw, &m);

    // ---- INVARIANTS ----------------------------------------------------
    //
    // A fuzzer without assertions only finds crashes. These turn "wrong" into
    // "crash" so the fuzzer can see it — each one is a bug class that would
    // otherwise be silent.

    // 1. Total: every input gets a known verdict. No wild error codes.
    if (rc < 0 || rc >= PP_ERR__COUNT) abort();
    if (m.err != rc) abort();               // return value and field must agree

    // 2. THE BIG ONE: no offset may point past the bytes we actually have.
    //    This is the over-read bug, caught as arithmetic rather than as a
    //    segfault that only happens when the page boundary lines up.
    if (m.caplen > caplen) abort();
    if (m.l2_off      > m.caplen) abort();
    if (m.l3_off      > m.caplen) abort();
    if (m.l4_off      > m.caplen) abort();
    if (m.payload_off > m.caplen) abort();
    if (uint32_t(m.payload_off) + m.payload_len > m.caplen) abort();

    // 3. Layers must be monotonic: you cannot reach L4 without passing L3.
    //    A parser that reports L4 on a packet whose L3 it never decoded has
    //    invented the ports from somewhere.
    if ((m.layers & PP_LAYER_L4) && !(m.layers & PP_LAYER_L3)) abort();
    if ((m.layers & PP_LAYER_L3) && !(m.layers & PP_LAYER_L2)) abort();

    // 4. Offsets must be ordered. l4 before l3 is nonsense.
    if (m.layers & PP_LAYER_L3) { if (m.l3_off < m.l2_off) abort(); }
    if (m.layers & PP_LAYER_L4) { if (m.l4_off < m.l3_off) abort(); }

    // 5. The caps from pkt.h are load-bearing, so assert them (SPEC §7.8).
    //    If a crafted input could exceed them, the DoS defence is decorative.
    if (m.tunnel_depth > PP_MAX_TUNNEL_DEPTH) abort();

    // 6. Sentinels survive. VLAN 0 is legal, so "no VLAN" cannot be 0.
    if (!(m.layers & PP_LAYER_VLAN)) {
        if (m.vlan_outer != PP_VLAN_NONE) abort();
    } else {
        if (m.vlan_outer > 4095 && m.vlan_outer != PP_VLAN_NONE) abort();
    }

    // 7. ip_ver is 0, 4 or 6. Never anything else.
    if (m.ip_ver != 0 && m.ip_ver != 4 && m.ip_ver != 6) abort();

    // 8. If L3 was decoded, a version must have been decided.
    if ((m.layers & PP_LAYER_L3) && m.ip_ver == 0) abort();

    // 9. Determinism. The parser is a pure function of its input, and if it
    //    is not — if it reads uninitialized memory, say — the two runs differ.
    //    Cheap to check and catches a whole category of "works on my machine".
    pp_meta m2;
    int rc2 = pp_parse(&raw, &m2);
    if (rc2 != rc) abort();
    if (__builtin_memcmp(&m, &m2, sizeof m) != 0) abort();

    return 0;
}
