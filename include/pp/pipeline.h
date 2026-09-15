/* pipeline.h — the driver: pull a batch, parse it, classify it, count it.
 *
 * This is where the "sustaining high throughput ... cache-friendly layout ...
 * avoiding per-packet allocation" clause (R4/R5/R6) is actually cashed out.
 * Everything before it was structure; this is the loop that runs forever.
 */
#ifndef PP_PIPELINE_H
#define PP_PIPELINE_H

#include "pp/source.h"
#include "pp/classify.h"

PP_BEGIN_DECLS

struct pp_arena;

/* Default burst.
 *
 * 32 came from DPDK. T12 MEASURED it and the number does not survive contact:
 * on file replay, batch 2-4 is fastest and 32 is 4-9% SLOWER, because there are
 * no syscalls to amortize and the I-cache is already hot (SPEC §7.4).
 *
 * It stays at 32 anyway, and for a reason that is measured rather than
 * inherited: on the LIVE AF_PACKET path the same comparison is not close —
 * `recvfrom` (a syscall per packet) lost 73% of a 1 Mpps link to kernel drops
 * while the batched mmap ring lost none, at ~430 packets per syscall instead of
 * ~0.5. Batching is worth nothing on replay and everything where syscalls
 * exist, and the live path is what the résumé claim is about.
 *
 * The honest summary: the cost on replay is a few percent; the benefit on the
 * real path is the difference between capturing the link and losing it. */
#define PP_BATCH_DEFAULT 32
#define PP_BATCH_MAX    256

/* How far ahead to prefetch, in packets. 0 = off, and off is the default.
 *
 * This was 4, on the standard reasoning: a DRAM miss costs ~200-300 cycles,
 * parsing a header costs ~50-100, so issue the load ~4 packets early and it
 * lands just in time.
 *
 * T12 measured it. The reasoning is wrong here, and expensively so:
 *
 *     distance   uniform_tcp   mixed corpus
 *     0 (off)       22.7 ns       36.9 ns
 *     4             22.6 ns       37.1 ns   (+0.7%)
 *     8             22.5 ns       41.5 ns   (+12.5%)
 *     32            22.5 ns       53.7 ns   (+45.6%)
 *
 * The premise was that the loads miss. They do not: the corpus is walked
 * sequentially through one mmap, which is exactly the pattern the HARDWARE
 * prefetcher already recognises and runs ahead of. So the software prefetch
 * adds no information, and it is not free — it burns bandwidth and, at
 * distance, evicts lines we are about to need. Hence the branchy mixed corpus
 * degrading nearly twice as badly as the uniform one.
 *
 * Default 0 because that is what the data says. The mechanism stays as a
 * tunable: a real NIC ring with scattered frames is a genuinely different
 * access pattern where it might pay — but it stays off until a measurement
 * says otherwise, rather than on because a textbook says so. */
#define PP_PREFETCH_DEFAULT 0

typedef struct pp_pipeline_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t batches;
    uint64_t parse_err[PP_ERR__COUNT];   /* histogram, not a single counter:
                                          * "12,000 packets were bad" is not
                                          * actionable; "12,000 had truncated L4
                                          * headers" points at a snaplen. */
    uint64_t action[PP_ACTION__COUNT];

    /* TWO clocks, because they answer different questions and conflating them
     * is a bug I actually shipped.
     *
     * ns_total — wall clock from first pull to last. For a pcap replay this is
     *   the whole story: the source never blocks, so elapsed == working.
     *
     * ns_busy  — time spent inside parse+classify ONLY, excluding however long
     *   the source blocked waiting for traffic. Only accumulated when
     *   `measure_busy` is set (see below).
     *
     * The bug: the first version reported ns_total/packets as "ns per packet"
     * for LIVE capture too. On a link that is quiet for 0.95 of a second, that
     * divides ~1 second of sleeping by 20,000 packets and reports 48,720 ns per
     * packet and 0.021 Mpps — numbers that describe how long the program was
     * running, not how fast it processes. It looked like a catastrophic result
     * and was actually a measurement error, which is the worst kind: a bad
     * number that gets quoted. */
    uint64_t ns_total;
    uint64_t ns_busy;
} pp_pipeline_stats;

typedef struct pp_pipeline {
    pp_source     *src;
    pp_classifier *cl;

    /* Both arrays are carved from the arena ONCE at init, and reused for every
     * batch forever. This is the whole of R6: there is nothing to allocate per
     * packet because everything was allocated before the first one. */
    pp_rawpkt *raw;    /* batch_size entries */
    pp_meta   *meta;   /* batch_size entries, cache-line aligned */

    int batch_size;
    int prefetch_dist;

    /* Accumulate st.ns_busy? Off by default, and that is a measurement decision
     * rather than laziness.
     *
     * Timing each batch costs two clock_gettime() calls. Even through the vDSO
     * that is ~20-25 ns, and at batch 32 it works out to ~1.6 ns per packet —
     * about 7% of the ~22 ns the pipeline actually takes. Instrumenting the hot
     * path to measure the hot path would corrupt the very number we are trying
     * to read.
     *
     * So: LIVE capture turns it on (the process is blocked in poll() most of
     * the time; 25 ns is noise there, and ns_busy is the only honest way to
     * report per-packet cost). The benchmark leaves it OFF and times the whole
     * run from outside instead. Each measures what it can measure without
     * disturbing it. */
    int measure_busy;

    pp_pipeline_stats st;
} pp_pipeline;

/* Returns 0, or -1 if the arena cannot fit the batch arrays. */
int pp_pipeline_init(pp_pipeline *p, pp_source *src, pp_classifier *cl,
                     struct pp_arena *a, int batch_size, int prefetch_dist);

/* Process one batch. Returns the packet count, 0 at end of stream, -1 on a
 * source error. */
int pp_pipeline_step(pp_pipeline *p);

/* Drain the source. Returns total packets processed. */
uint64_t pp_pipeline_run(pp_pipeline *p);

/* Nanoseconds from CLOCK_MONOTONIC.
 *
 * NOT the PMU. The hardware performance counters are unavailable under
 * virtualization (SPEC §7.6 — measured, not assumed), so cycles/packet cannot
 * honestly be reported from this environment. CLOCK_MONOTONIC is
 * virtualization-safe, is not perturbed by NTP steps the way CLOCK_REALTIME is,
 * and measures exactly the thing we optimize: elapsed time per packet. */
uint64_t pp_now_ns(void);

PP_END_DECLS

#endif /* PP_PIPELINE_H */
