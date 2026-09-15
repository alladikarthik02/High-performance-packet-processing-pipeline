// test_noalloc — THE proof that the hot path never allocates.
//
// The résumé claims "avoiding per-packet allocation on the hot path". SPEC §7.1
// pokes the obvious hole in that: reading the code and seeing no malloc proves
// nothing. std::string allocates. std::vector growth allocates. std::function
// allocates. A C++ exception allocates. Some printf paths allocate. "I checked"
// is not evidence, and a reviewer is right to be unconvinced.
//
// So make the claim FALSIFIABLE. This file replaces the process's allocator
// with one that counts, arms the counter after all setup is done, runs 50,000
// real packets through the full pipeline, and asserts the counter never moved.
//
// The consequence that matters: if someone adds a std::vector to the parser in
// six months, THIS TEST FAILS. The invariant cannot rot silently. That is the
// difference between a claim and an engineering control.
#include "test.h"
#include "pktbuild.h"
#include "pp/pipeline.h"
#include "pp/parse.h"
#include "pp/classify.h"
#include "pp/arena.h"
#include "pp/source.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <unistd.h>

// ===========================================================================
// The interposer
// ===========================================================================
//
// Defining malloc() in the executable makes the linker prefer OUR strong symbol
// over libc's for every call site in the program — including calls from inside
// libstdc++. Everything routes through here.
//
// Forwarding to the real allocator is the fiddly part. The textbook move is
// dlsym(RTLD_NEXT, "malloc"), which has a chicken-and-egg problem: dlsym itself
// may allocate, and it would call our malloc, which needs dlsym. People solve
// that with a static bootstrap buffer and a re-entrancy flag. glibc exports
// __libc_malloc and friends directly, which avoids the whole dance — this is
// glibc-specific, and the project is Linux-only (SPEC §5), so that is a cost we
// have already paid.

extern "C" {
void *__libc_malloc(size_t);
void  __libc_free(void *);
void *__libc_calloc(size_t, size_t);
void *__libc_realloc(void *, size_t);

// Zero-initialized (BSS), so these are correct from the very first allocation
// the C runtime makes before main() — no initialization-order hazard.
volatile int      g_alloc_armed = 0;
volatile uint64_t g_alloc_count = 0;
volatile uint64_t g_free_count  = 0;
volatile uint64_t g_alloc_bytes = 0;

void *malloc(size_t n) {
    if (g_alloc_armed) { g_alloc_count++; g_alloc_bytes += n; }
    return __libc_malloc(n);
}
void free(void *p) {
    if (g_alloc_armed && p) g_free_count++;
    __libc_free(p);
}
void *calloc(size_t a, size_t b) {
    if (g_alloc_armed) { g_alloc_count++; g_alloc_bytes += a * b; }
    return __libc_calloc(a, b);
}
void *realloc(void *p, size_t n) {
    if (g_alloc_armed) { g_alloc_count++; g_alloc_bytes += n; }
    return __libc_realloc(p, n);
}
} // extern "C"

// operator new is overridden as well as malloc, and not redundantly.
// libstdc++'s operator new does normally call malloc — but it is not REQUIRED
// to, and an allocator that bypassed malloc would slip through a malloc-only
// interposer. Catching both means the claim does not depend on an
// implementation detail of the C++ runtime.
void *operator new(size_t n) {
    if (g_alloc_armed) { g_alloc_count++; g_alloc_bytes += n; }
    void *p = __libc_malloc(n);
    if (!p) throw std::bad_alloc();
    return p;
}
void *operator new[](size_t n) { return operator new(n); }
void operator delete(void *p) noexcept { if (g_alloc_armed && p) g_free_count++; __libc_free(p); }
void operator delete[](void *p) noexcept { operator delete(p); }
void operator delete(void *p, size_t) noexcept { operator delete(p); }
void operator delete[](void *p, size_t) noexcept { operator delete(p); }

namespace {

void arm()    { g_alloc_count = 0; g_free_count = 0; g_alloc_bytes = 0; g_alloc_armed = 1; }
void disarm() { g_alloc_armed = 0; }

using namespace pktbuild;

uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|d;
}

// A file with a realistic protocol mix, so the armed run exercises every branch
// of the parser — VLAN, IPv6 extension headers, VXLAN re-entry, malformed
// frames. A proof that only covers the easy path proves very little.
struct Corpus {
    std::string path;
    explicit Corpus(size_t n) {
        char t[64];
        std::snprintf(t, sizeof t, "/tmp/ppnoalloc_%d.pcap", int(getpid()));
        path = t;
        std::FILE* f = std::fopen(path.c_str(), "wb");
        auto p32 = [&](uint32_t v){ uint8_t b[4]={uint8_t(v),uint8_t(v>>8),uint8_t(v>>16),uint8_t(v>>24)}; std::fwrite(b,1,4,f); };
        auto p16 = [&](uint16_t v){ uint8_t b[2]={uint8_t(v),uint8_t(v>>8)}; std::fwrite(b,1,2,f); };
        p32(0xa1b2c3d4); p16(2); p16(4); p32(0); p32(0); p32(65535); p32(1);

        for (size_t i = 0; i < n; ++i) {
            Pkt p;
            switch (i % 8) {
            case 0: case 1: case 2: {          // plain TCP
                p.eth(PP_ETHERTYPE_IPV4); size_t o = p.size();
                p.ipv4(PP_IPPROTO_TCP, ip4(192,168,1,uint8_t(i%254+1)), ip4(10,0,0,1))
                 .tcp(uint16_t(1024+i%60000), 443).fill(i % 64).fix_ipv4_totlen(o);
                break; }
            case 3: {                          // UDP
                p.eth(PP_ETHERTYPE_IPV4); size_t o = p.size();
                p.ipv4(PP_IPPROTO_UDP, ip4(192,168,1,1), ip4(8,8,8,8));
                size_t u = p.size();
                p.udp(1234, 53).fill(32).fix_udp_len(u).fix_ipv4_totlen(o);
                break; }
            case 4: {                          // VLAN
                p.eth(PP_ETHERTYPE_VLAN).vlan_tag(100, PP_ETHERTYPE_IPV4);
                size_t o = p.size();
                p.ipv4(PP_IPPROTO_TCP, ip4(192,168,2,1), ip4(10,1,1,1))
                 .tcp(2000, 22).fill(16).fix_ipv4_totlen(o);
                break; }
            case 5: {                          // IPv6 + ext header chain
                p.eth(PP_ETHERTYPE_IPV6); size_t o = p.size();
                p.ipv6(PP_IPPROTO_HOPOPTS, 0).ip6_ext(PP_IPPROTO_TCP, 0)
                 .tcp(3000, 443).fill(16).fix_ipv6_plen(o);
                break; }
            case 6: {                          // VXLAN: the tunnel RE-ENTRY path
                p.eth(PP_ETHERTYPE_IPV4); size_t o = p.size();
                p.ipv4(PP_IPPROTO_UDP, ip4(10,0,0,1), ip4(10,0,0,2));
                size_t u = p.size();
                p.udp(4000, PP_UDP_PORT_VXLAN).vxlan(5000).eth(PP_ETHERTYPE_IPV4);
                size_t i2 = p.size();
                p.ipv4(PP_IPPROTO_TCP, ip4(172,16,0,1), ip4(172,16,1,1))
                 .tcp(5000, 8080).fill(16)
                 .fix_ipv4_totlen(i2).fix_udp_len(u).fix_ipv4_totlen(o);
                break; }
            default: {                         // malformed: the ERROR path must
                p.eth(PP_ETHERTYPE_IPV4);      // not allocate either
                p.ipv4(PP_IPPROTO_TCP, ip4(1,1,1,1), ip4(2,2,2,2), /*ihl=*/0);
                break; }
            }
            p32(1700000000); p32(uint32_t(i)); p32(uint32_t(p.size())); p32(uint32_t(p.size()));
            std::fwrite(p.data(), 1, p.size(), f);
        }
        std::fclose(f);
    }
    ~Corpus() { ::unlink(path.c_str()); }
};

} // namespace

// ===========================================================================

static void suite_interposer_actually_works() {
    // Test the test. An interposer that silently is not linked in would make
    // every check below pass vacuously — the worst possible outcome, a proof
    // that proves nothing while looking green. So first: prove it counts.
    arm();
    void* p = std::malloc(64);
    void* q = ::operator new(128);
    disarm();

    std::free(p);
    ::operator delete(q);

    CHECK_EQ(uint64_t(g_alloc_count), uint64_t(2));   // it saw BOTH
    CHECK(uint64_t(g_alloc_bytes) >= 192);

    // ...and that disarming really stops it.
    uint64_t before = g_alloc_count;
    void* r = std::malloc(64);
    std::free(r);
    CHECK_EQ(uint64_t(g_alloc_count), before);
}

static void suite_parse_does_not_allocate() {
    // The parser alone, over every code path: VLAN, QinQ, IPv6 ext chains,
    // VXLAN re-entry, and malformed frames.
    Pkt pkts[6];
    pkts[0].eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2).tcp(1,2).fill(10);
    pkts[1].eth(PP_ETHERTYPE_QINQ).vlan_tag(1, PP_ETHERTYPE_VLAN)
           .vlan_tag(2, PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, 1, 2).udp(1,2).fill(8);
    pkts[2].eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_HOPOPTS, 0)
           .ip6_ext(PP_IPPROTO_ROUTING, 1).ip6_ext(PP_IPPROTO_TCP, 0).tcp(1,2).fill(8);
    pkts[3].eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, 1, 2)
           .udp(1, PP_UDP_PORT_VXLAN).vxlan(7).eth(PP_ETHERTYPE_IPV4)
           .ipv4(PP_IPPROTO_TCP, 3, 4).tcp(5,6).fill(8);
    pkts[4].eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, /*ihl=*/0);  // malformed
    pkts[5].fill(3, 0xAA);                                                  // runt

    pp_rawpkt views[6];
    for (int i = 0; i < 6; ++i) views[i] = pkts[i].view();

    pp_meta m;
    arm();
    for (int rep = 0; rep < 10000; ++rep)
        for (int i = 0; i < 6; ++i)
            pp_parse(&views[i], &m);
    disarm();

    // 60,000 parses across every branch in the parser.
    CHECK_EQ(uint64_t(g_alloc_count), uint64_t(0));
    CHECK_EQ(uint64_t(g_alloc_bytes), uint64_t(0));
}

static void suite_classify_does_not_allocate() {
    pp_arena a{}; pp_arena_init(&a, 1 << 20);
    pp_ruleset rs{}; char err[256];
    std::string rules = "default drop\n";
    for (int i = 0; i < 32; ++i)
        rules += "accept tcp any any -> any " + std::to_string(400 + i) + "\n";
    CHECK_EQ(pp_rules_compile_str(rules.c_str(), "t", &a, &rs, err, sizeof err), 0);

    pp_classifier cl{};
    CHECK_EQ(pp_classifier_init(&cl, &rs, &a), 0);

    Pkt p; p.eth(PP_ETHERTYPE_IPV4);
    size_t o = p.size();
    p.ipv4(PP_IPPROTO_TCP, 1, 2).tcp(1000, 431).fill(8).fix_ipv4_totlen(o);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    arm();
    for (int i = 0; i < 50000; ++i) pp_classify(&cl, &m, nullptr);
    disarm();

    CHECK_EQ(uint64_t(g_alloc_count), uint64_t(0));
    pp_arena_destroy(&a);
}

static void suite_full_pipeline_does_not_allocate() {
    // THE headline test: source -> parse -> classify -> stats, 50,000 real
    // packets from a real file, with a real ruleset. Everything the résumé
    // bullet describes, with the allocator watching.
    const size_t N = 50000;
    Corpus corpus(N);

    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 8 << 20), 0);

    pp_ruleset rs{}; char err[256];
    CHECK_EQ(pp_rules_compile_str(
        "default accept\n"
        "drop   tcp any any -> any 22\n"
        "count  udp any any -> any 53\n"
        "accept tcp 192.168.0.0/16 any -> any 443\n"
        "accept tcp any any -> any 8080 vni 5000\n"
        "count  any any any -> any any vlan 100\n",
        "t.rules", &a, &rs, err, sizeof err), 0);

    pp_classifier cl{};
    CHECK_EQ(pp_classifier_init(&cl, &rs, &a), 0);

    pp_source src{};
    CHECK_EQ(pp_source_pcapfile_open(&src, corpus.path.c_str()), 0);

    pp_pipeline pipe{};
    CHECK_EQ(pp_pipeline_init(&pipe, &src, &cl, &a, PP_BATCH_DEFAULT,
                              PP_PREFETCH_DEFAULT), 0);

    // Warm up anything that lazily initializes — stdio buffers, the mmap'd
    // file's page tables, the vDSO for clock_gettime. A first-use allocation
    // inside some libc corner would otherwise be blamed on the pipeline, and
    // the point of this test is to be precise about who allocated.
    pp_now_ns();
    std::fflush(stdout);
    std::fflush(stderr);

    arm();
    uint64_t processed = pp_pipeline_run(&pipe);
    disarm();

    // Zero. Not "few". Not "amortized". Zero — across 50,000 packets spanning
    // TCP, UDP, VLAN, IPv6 + extension headers, VXLAN decapsulation, and
    // malformed frames.
    CHECK_EQ(uint64_t(g_alloc_count), uint64_t(0));
    CHECK_EQ(uint64_t(g_alloc_bytes), uint64_t(0));
    CHECK_EQ(uint64_t(g_free_count), uint64_t(0));

    // And it must have actually done the work — a pipeline that processed
    // nothing would also allocate nothing, and would pass this test while
    // proving the opposite of what we want.
    CHECK_EQ(processed, uint64_t(N));
    CHECK_EQ(pipe.st.packets, uint64_t(N));
    CHECK(pipe.st.batches >= N / PP_BATCH_DEFAULT);

    std::fprintf(stderr,
        "  [proof] %llu packets, %llu batches, %llu bytes -> %llu allocations\n",
        (unsigned long long)pipe.st.packets,
        (unsigned long long)pipe.st.batches,
        (unsigned long long)pipe.st.bytes,
        (unsigned long long)g_alloc_count);

    // Sanity on the work actually performed, so the numbers above mean something.
    uint64_t acts = 0;
    for (int i = 0; i < PP_ACTION__COUNT; ++i) acts += pipe.st.action[i];
    CHECK_EQ(acts, uint64_t(N));

    uint64_t errs = 0;
    for (int i = 1; i < PP_ERR__COUNT; ++i) errs += pipe.st.parse_err[i];
    CHECK(errs > 0);            // the corpus HAS malformed packets by construction
    CHECK(errs < N / 2);        // ...but they are the minority
    CHECK(pipe.st.parse_err[PP_ERR_BAD_IHL] >= N / 16);   // the ihl=0 ones

    pp_source_close(&src);
    pp_arena_destroy(&a);
}

static void suite_arena_is_not_malloc() {
    // The arena must be mmap-backed, not built on malloc — otherwise the proof
    // above would need an exception carved out for it, and an invariant with an
    // exception is a weaker invariant (SPEC §7.1).
    pp_arena a{};
    arm();
    int rc = pp_arena_init(&a, 1 << 20);
    uint64_t during_init = g_alloc_count;
    for (int i = 0; i < 100; ++i) pp_arena_alloc(&a, 64, 64);
    uint64_t after_allocs = g_alloc_count;
    disarm();

    CHECK_EQ(rc, 0);
    CHECK_EQ(during_init, uint64_t(0));    // init went straight to mmap
    CHECK_EQ(after_allocs, uint64_t(0));   // and carving never touches malloc

    pp_arena_destroy(&a);
}

int main() {
    suite_interposer_actually_works();
    suite_arena_is_not_malloc();
    suite_parse_does_not_allocate();
    suite_classify_does_not_allocate();
    suite_full_pipeline_does_not_allocate();
    TEST_SUMMARY("test_noalloc");
}
