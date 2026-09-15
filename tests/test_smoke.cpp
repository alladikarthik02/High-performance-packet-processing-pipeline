// test_smoke — proves the scaffolding works before anything is built on it.
//
// The interesting assertion here is not "1 == 1". It is that this C++ file
// links against a C library through an extern "C" header. That boundary is the
// architecture (SPEC §3.1: C data plane, C++ control plane), so a test that
// fails the moment it breaks belongs in the suite from day one.
#include "test.h"
#include "pp/pp.h"

static void suite_abi_boundary() {
    // Calling a C11-compiled function from C++17. If the extern "C" wrapping in
    // pp.h regressed, this would fail at link time, not here.
    const char* v = pp_version();
    CHECK(v != nullptr);
    CHECK_EQ(std::string(v), std::string("0.1.0"));
}

static void suite_hw_probe() {
    // We ask the OS for the cache line rather than assuming 64 (SPEC §7.3).
    // Whatever it reports must at least be a sane power of two.
    size_t line = pp_hw_cacheline();
    std::fprintf(stderr, "  [info] %s\n", pp_build_info());
    CHECK(line != 0);                       // 0 means "we could not probe it"
    CHECK(line >= 32 && line <= 256);
    CHECK((line & (line - 1)) == 0);        // power of two

    // The design targets 64B because it is the tighter constraint: a struct
    // that fits 64 also fits this machine's 128. Asserting PP_CACHELINE <= line
    // documents that direction of the inequality on purpose.
    CHECK(PP_CACHELINE <= line);
}

int main() {
    suite_abi_boundary();
    suite_hw_probe();
    TEST_SUMMARY("test_smoke");
}
