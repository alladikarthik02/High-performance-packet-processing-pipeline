/* arena.c — bump allocator over an mmap'd, pre-faulted region. */

/* MUST come before any libc header. Feature test macros are read by the headers
 * as they are included, so defining this later has no effect at all.
 *
 * Why it is needed: MAP_ANONYMOUS is not ISO C and not POSIX — it is a BSD/GNU
 * extension. We compile with -std=c11 rather than -std=gnu11 (CMAKE_C_EXTENSIONS
 * OFF), and under strict ISO mode glibc hides every non-standard symbol behind
 * internal guards; MAP_ANONYMOUS sits behind __USE_MISC. _DEFAULT_SOURCE is the
 * documented way to ask glibc for the usual BSD/SVID set.
 *
 * This file compiled cleanly on macOS and failed instantly on Linux, because
 * Apple's SDK headers expose MAP_ANONYMOUS unconditionally while glibc does not.
 * Textbook case for why the project builds on its target platform rather than
 * cross-fingers-and-#ifdef (SPEC §5). Harmless on macOS: the macro is simply
 * ignored there. */
#define _DEFAULT_SOURCE

#include "pp/arena.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* MAP_POPULATE tells Linux to build the page tables and attach physical pages
 * during mmap() itself, which is precisely the pre-faulting we want and is done
 * in one syscall rather than by touching pages in a loop. macOS has no
 * equivalent, so there we fall back to touching each page by hand below.
 * Defining it to 0 when absent keeps the mmap() call site free of #ifdefs. */
#ifndef MAP_POPULATE
#  define MAP_POPULATE 0
#endif

static size_t page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    return ps > 0 ? (size_t)ps : 4096u;
}

static int is_pow2(size_t x) { return x != 0 && (x & (x - 1)) == 0; }

/* Round `v` up to the next multiple of `align`. Requires align to be a power of
 * two, which lets the whole thing be two ALU ops instead of a division:
 * (v + align-1) & ~(align-1). Worth writing out because "why is this not a %"
 * is a fair question and the answer is that div is ~20-40 cycles and this is 2. */
static size_t align_up(size_t v, size_t align)
{
    return (v + (align - 1)) & ~(align - 1);
}

int pp_arena_init(pp_arena *a, size_t bytes)
{
    if (!a || bytes == 0) { errno = EINVAL; return -1; }

    memset(a, 0, sizeof *a);

    const size_t ps = page_size();
    bytes = align_up(bytes, ps);

    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED) return -1;   /* errno already set by mmap */

    a->base = (uint8_t *)p;
    a->cap  = bytes;
    a->used = 0;

    /* Pre-fault. On Linux MAP_POPULATE already did this inside mmap(); doing it
     * again would be wasted work, so only walk the pages when we had no
     * MAP_POPULATE to ask for.
     *
     * The write (not just a read) matters: these are MAP_ANONYMOUS pages, and
     * Linux backs a *read* of an untouched anonymous page with the shared
     * zero page copy-on-write. A read would therefore fault it in and then
     * fault AGAIN on the first real write — paying the cost twice and paying
     * the second half exactly where we were trying not to. Writing forces the
     * private page to be allocated now. `volatile` stops the optimizer from
     * deleting a store it can prove nobody reads. */
    if (MAP_POPULATE == 0) {
        for (size_t off = 0; off < bytes; off += ps)
            ((volatile uint8_t *)a->base)[off] = 0;
    }

    return 0;
}

void *pp_arena_alloc(pp_arena *a, size_t n, size_t align)
{
    if (!a || !a->base) return NULL;
    if (!is_pow2(align)) return NULL;

    size_t start = align_up(a->used, align);

    /* Overflow-safe exhaustion check. Writing `start + n > a->cap` would be the
     * natural thing and is wrong: if n is huge, start + n wraps and the check
     * passes, handing back a pointer that runs off the end. Subtracting instead
     * cannot wrap because start <= cap is established first. */
    if (start > a->cap || n > a->cap - start) return NULL;

    void *p = a->base + start;
    a->used = start + n;
    if (a->used > a->high_water) a->high_water = a->used;
    a->n_allocs++;
    return p;
}

void pp_arena_reset(pp_arena *a)
{
    if (a) { a->used = 0; a->n_allocs = 0; }
    /* Note: pages stay mapped and stay faulted-in. That is the point — a reset
     * costs one store, and the next run does not re-pay the fault cost. */
}

void pp_arena_destroy(pp_arena *a)
{
    if (!a || !a->base) return;
    munmap(a->base, a->cap);
    a->base = NULL;
    a->cap = a->used = a->high_water = 0;
    a->n_allocs = 0;
}

size_t pp_arena_remaining(const pp_arena *a, size_t align)
{
    if (!a || !a->base || !is_pow2(align)) return 0;
    size_t start = align_up(a->used, align);
    return start >= a->cap ? 0 : a->cap - start;
}
