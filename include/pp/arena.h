/* arena.h — a bump allocator, and the reason the hot path never calls malloc.
 *
 * The résumé claim is "avoiding per-packet allocation on the hot path" (SPEC
 * R6). The way to make that true is not discipline; it is to have nothing to
 * allocate. Everything the pipeline needs is carved out of one arena, once,
 * before the first packet arrives. After that the data plane only reads and
 * writes memory it already owns.
 *
 * What this deliberately does NOT support:
 *   - freeing an individual allocation. There is no pp_arena_free(ptr). A bump
 *     allocator that can free individual blocks is just malloc with extra steps.
 *     Lifetime here is "the whole pipeline", so the only free is destroy().
 *   - thread safety. Single-threaded by design (SPEC §7.10). A per-core arena
 *     is the answer when we shard; a lock on the allocator would defeat it.
 */
#ifndef PP_ARENA_H
#define PP_ARENA_H

#include "pp/pp.h"

PP_BEGIN_DECLS

typedef struct pp_arena {
    uint8_t *base;      /* start of the mmap'd region                        */
    size_t   cap;       /* total bytes reserved                              */
    size_t   used;      /* bump cursor                                        */
    size_t   high_water;/* peak `used`; reported so sizing can be justified   */
    uint32_t n_allocs;  /* how many carve-outs happened (all at startup)      */
} pp_arena;

/* Reserve `bytes` up front.
 *
 * Backed by mmap, NOT malloc, on purpose. If the arena were built on malloc,
 * the zero-allocation proof in T9 would have to carve out an exception for it,
 * and an invariant with an exception is a weaker invariant. Going straight to
 * the kernel means the data plane never touches the C allocator at all — a
 * claim the T9 interposer can then check without qualification.
 *
 * Also PRE-FAULTS every page. mmap hands back address space, not memory: the
 * kernel does not attach physical pages until each is first touched, and each
 * of those first touches is a page fault costing microseconds. Reserve 64 MiB
 * and skip this step, and you have queued ~16k page faults to be paid by your
 * first few thousand packets — which shows up as a garbage warm-up region in
 * every benchmark and as latency spikes that look like a code bug but are not.
 * Faulting them in here moves that cost to startup, where it belongs.
 *
 * Returns 0 on success, -1 on failure (errno set). */
int pp_arena_init(pp_arena *a, size_t bytes);

/* Carve `n` bytes aligned to `align` (must be a power of two).
 * Returns NULL if the arena is exhausted — callers check, because the
 * alternative is a silent overwrite.
 *
 * Intended to be called at startup only. Calling it per packet would compile
 * and run correctly, and would also be exactly the mistake this project claims
 * not to make; T9 is what stops that from happening quietly. */
void *pp_arena_alloc(pp_arena *a, size_t n, size_t align);

/* Rewind the cursor to empty, keeping the mapping (and its faulted-in pages).
 * Cheap: one store. This is the "free everything" that a bump allocator is for. */
void pp_arena_reset(pp_arena *a);

/* Unmap. After this the arena is unusable until re-init. */
void pp_arena_destroy(pp_arena *a);

/* Bytes still available at the current cursor for a given alignment. */
size_t pp_arena_remaining(const pp_arena *a, size_t align);

PP_END_DECLS

#endif /* PP_ARENA_H */
