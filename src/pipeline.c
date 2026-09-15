/* pipeline.c — the hot loop. */
#define _DEFAULT_SOURCE

#include "pp/pipeline.h"
#include "pp/parse.h"
#include "pp/arena.h"

#include <string.h>
#include <time.h>

uint64_t pp_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int pp_pipeline_init(pp_pipeline *p, pp_source *src, pp_classifier *cl,
                     struct pp_arena *a, int batch_size, int prefetch_dist)
{
    memset(p, 0, sizeof *p);

    if (batch_size <= 0)          batch_size = PP_BATCH_DEFAULT;
    if (batch_size > PP_BATCH_MAX) batch_size = PP_BATCH_MAX;
    if (prefetch_dist < 0)        prefetch_dist = 0;

    p->src           = src;
    p->cl            = cl;
    p->batch_size    = batch_size;
    p->prefetch_dist = prefetch_dist;

    /* ALL per-batch memory, allocated once, here, before any packet arrives.
     * The hot path below never allocates — not because it is careful, but
     * because there is nothing left for it to allocate (R6, proven by T9). */
    p->raw = (pp_rawpkt *)pp_arena_alloc(a, (size_t)batch_size * sizeof(pp_rawpkt),
                                         PP_CACHELINE);
    if (!p->raw) return -1;

    /* Cache-line aligned, so the metadata array TILES cache lines: entry i sits
     * at exactly i*64 bytes. That is what makes the hardware prefetcher able to
     * follow the linear walk in stage 2, and it is why T1 bothered making
     * pp_meta exactly 64 bytes rather than merely small. */
    p->meta = (pp_meta *)pp_arena_alloc(a, (size_t)batch_size * sizeof(pp_meta),
                                        PP_CACHELINE);
    if (!p->meta) return -1;

    return 0;
}

int pp_pipeline_step(pp_pipeline *p)
{
    /* The source call is OUTSIDE the busy timer, deliberately.
     *
     * On a live capture this blocks in poll() until the kernel has traffic —
     * that wait is the sender's pace, not our processing cost. Counting it was
     * the bug: it turned a quiet link into "48,720 ns per packet". Whatever
     * time is spent in here belongs to the network, not to us. */
    int n = pp_source_next(p->src, p->raw, p->batch_size);
    if (n <= 0) return n;

    p->st.batches++;

    /* From here down is OUR work, and the only part it is honest to charge to
     * a per-packet cost. See pp_pipeline.measure_busy for why this is opt-in. */
    uint64_t busy_t0 = p->measure_busy ? pp_now_ns() : 0;

    /* ------------------------------------------------------------------
     * STAGE 1: parse the whole batch.
     *
     * Two separate loops (parse x N, then classify x N) rather than one
     * interleaved loop. This looks like more work and is not — it is SPEC §4:
     *
     *  - INSTRUCTION CACHE. Running the parser N times back to back keeps its
     *    code hot in L1i. Alternating parse/classify/parse/classify evicts each
     *    with the other, and on a small core an I-cache miss costs as much as
     *    the work it interrupted.
     *
     *  - PREFETCH IS ONLY POSSIBLE HERE. You cannot prefetch packet i+4 if you
     *    do not yet know it exists. Pulling a batch first is what makes the
     *    addresses available early enough to be useful.
     * ------------------------------------------------------------------ */
    for (int i = 0; i < n; i++) {
        /* Prefetch a packet we will parse in a few iterations' time.
         *
         * The packet bytes live in the mmap'd file or in the kernel's ring —
         * either way, memory we have not touched, so the first byte-load will
         * miss to DRAM at ~200-300 cycles. Parsing one packet's headers is
         * ~50-100 cycles, so issuing the prefetch ~4 packets ahead gives the
         * load time to land. Without it the core stalls on memory and does
         * nothing while it waits.
         *
         * Only the FIRST line is prefetched: the headers we parse live in the
         * first ~54 bytes, and the payload is never touched. Prefetching the
         * whole packet would evict useful lines to fetch bytes nobody reads. */
        int pf = i + p->prefetch_dist;
        if (pf < n)
            PP_PREFETCH(p->raw[pf].data);

        pp_parse(&p->raw[i], &p->meta[i]);

        p->st.packets++;
        p->st.bytes += p->raw[i].wirelen;
        p->st.parse_err[p->meta[i].err]++;
    }

    /* ------------------------------------------------------------------
     * STAGE 2: classify the whole batch.
     *
     * Walks p->meta linearly — 64 bytes per entry, cache-line aligned, so the
     * hardware prefetcher recognises the stride and runs ahead on its own. No
     * software prefetch needed here: this is exactly the access pattern the
     * hardware is built to predict, and that is not luck, it is what the T1
     * layout work bought.
     * ------------------------------------------------------------------ */
    for (int i = 0; i < n; i++) {
        uint8_t act = pp_classify(p->cl, &p->meta[i], NULL);
        p->st.action[act]++;
    }

    if (p->measure_busy) p->st.ns_busy += pp_now_ns() - busy_t0;

    return n;
}

uint64_t pp_pipeline_run(pp_pipeline *p)
{
    uint64_t t0 = pp_now_ns();
    for (;;) {
        int n = pp_pipeline_step(p);
        if (n <= 0) break;
    }
    p->st.ns_total += pp_now_ns() - t0;
    return p->st.packets;
}
