// test_arena — the allocator that lets the hot path never allocate.
#include "test.h"
#include "pp/arena.h"
#include "pp/pkt.h"

#include <cstring>

static void suite_init_and_destroy() {
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 1 << 20), 0);
    CHECK(a.base != nullptr);
    CHECK(a.cap >= size_t(1 << 20));      // rounded up to a page multiple
    CHECK_EQ(a.used, size_t(0));

    // mmap always returns page-aligned memory; downstream alignment reasoning
    // depends on that being true, so assert it rather than assume it.
    CHECK_EQ(reinterpret_cast<uintptr_t>(a.base) % 4096, uintptr_t(0));

    pp_arena_destroy(&a);
    CHECK(a.base == nullptr);
    pp_arena_destroy(&a);   // must be idempotent; double-destroy is not a crash
}

static void suite_bump_and_align() {
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 64 * 1024), 0);

    // A deliberately awkward size, to force the next allocation to be realigned
    // rather than landing on a boundary by luck.
    void* p1 = pp_arena_alloc(&a, 3, 1);
    CHECK(p1 != nullptr);
    CHECK_EQ(a.used, size_t(3));

    void* p2 = pp_arena_alloc(&a, 8, 8);
    CHECK(p2 != nullptr);
    CHECK_EQ(reinterpret_cast<uintptr_t>(p2) % 8, uintptr_t(0));
    CHECK(reinterpret_cast<uint8_t*>(p2) >= reinterpret_cast<uint8_t*>(p1) + 3);

    // Cache-line alignment is the case the pipeline actually depends on: a
    // batch of pp_meta must start on a line boundary or the layout work in T1
    // is wasted.
    void* p3 = pp_arena_alloc(&a, sizeof(pp_meta) * 32, PP_CACHELINE);
    CHECK(p3 != nullptr);
    CHECK_EQ(reinterpret_cast<uintptr_t>(p3) % PP_CACHELINE, uintptr_t(0));

    CHECK_EQ(a.n_allocs, uint32_t(3));
    CHECK(a.high_water >= a.used);

    pp_arena_destroy(&a);
}

static void suite_rejects_bad_alignment() {
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 4096), 0);
    // Non-power-of-two alignment is a programming error. align_up()'s bit trick
    // silently produces garbage for it, so it must be rejected at the door
    // rather than corrupting the cursor.
    CHECK(pp_arena_alloc(&a, 8, 3) == nullptr);
    CHECK(pp_arena_alloc(&a, 8, 0) == nullptr);
    CHECK(pp_arena_alloc(&a, 8, 6) == nullptr);
    CHECK_EQ(a.used, size_t(0));   // rejected calls must not move the cursor
    pp_arena_destroy(&a);
}

static void suite_exhaustion_returns_null() {
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 4096), 0);
    const size_t cap = a.cap;

    void* p = pp_arena_alloc(&a, cap, 1);
    CHECK(p != nullptr);                       // exactly full is fine
    CHECK(pp_arena_alloc(&a, 1, 1) == nullptr); // one more is not

    pp_arena_reset(&a);
    CHECK_EQ(a.used, size_t(0));
    CHECK(pp_arena_alloc(&a, cap, 1) != nullptr);  // reusable after reset

    pp_arena_destroy(&a);
}

static void suite_overflow_safety() {
    // The bug this guards against: writing the exhaustion check as
    // `start + n > cap`. With a huge n, start+n WRAPS, the check passes, and
    // the arena hands back a pointer that runs off the end of the mapping.
    // The implementation uses `n > cap - start` instead, which cannot wrap.
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 4096), 0);

    CHECK(pp_arena_alloc(&a, SIZE_MAX, 1) == nullptr);
    CHECK(pp_arena_alloc(&a, SIZE_MAX - 64, 64) == nullptr);
    CHECK_EQ(a.used, size_t(0));

    // Same trap one step in: a small offset plus a wrapping size.
    CHECK(pp_arena_alloc(&a, 16, 1) != nullptr);
    CHECK(pp_arena_alloc(&a, SIZE_MAX, 8) == nullptr);

    pp_arena_destroy(&a);
}

static void suite_memory_is_usable_and_prefaulted() {
    // Pre-faulting is a performance property and cannot be timed reliably in a
    // unit test, so this asserts the part that IS checkable: every page is
    // mapped, writable, and independent. If pre-faulting were broken we would
    // find out via a SIGBUS/SIGSEGV here rather than mid-benchmark.
    pp_arena a{};
    const size_t sz = 1 << 20;
    CHECK_EQ(pp_arena_init(&a, sz), 0);

    uint8_t* p = static_cast<uint8_t*>(pp_arena_alloc(&a, sz, 1));
    CHECK(p != nullptr);

    for (size_t i = 0; i < sz; i += 4096) p[i] = uint8_t(i / 4096);
    bool ok = true;
    for (size_t i = 0; i < sz; i += 4096) if (p[i] != uint8_t(i / 4096)) ok = false;
    CHECK(ok);

    pp_arena_destroy(&a);
}

static void suite_high_water_survives_reset() {
    // high_water is how "we reserved N MiB" gets justified with a number
    // instead of a guess, so it must track the peak across resets.
    pp_arena a{};
    CHECK_EQ(pp_arena_init(&a, 64 * 1024), 0);
    CHECK(pp_arena_alloc(&a, 1000, 1) != nullptr);
    CHECK_EQ(a.high_water, size_t(1000));
    pp_arena_reset(&a);
    CHECK_EQ(a.used, size_t(0));
    CHECK_EQ(a.high_water, size_t(1000));   // peak is remembered, not rewound
    CHECK(pp_arena_alloc(&a, 10, 1) != nullptr);
    CHECK_EQ(a.high_water, size_t(1000));
    pp_arena_destroy(&a);
}

int main() {
    suite_init_and_destroy();
    suite_bump_and_align();
    suite_rejects_bad_alignment();
    suite_exhaustion_returns_null();
    suite_overflow_safety();
    suite_memory_is_usable_and_prefaulted();
    suite_high_water_survives_reset();
    TEST_SUMMARY("test_arena");
}
