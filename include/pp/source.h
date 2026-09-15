/* source.h — where packets come from.
 *
 * One vtable, several backends. The pipeline never knows which one it is fed
 * by, which is the point: the parser and classifier are identical whether the
 * bytes came off a real NIC through an AF_PACKET ring or out of a file.
 *
 * The backends (SPEC §3.2):
 *
 *   pcapfile   portable   Deterministic replay of a .pcap. THE PRIMARY backend
 *                         for tests and benchmarks — same bytes every run, so a
 *                         throughput delta means a code change and not a
 *                         traffic change. Live capture is unrepeatable and
 *                         therefore useless as a measurement baseline.
 *   afpacket   Linux      AF_PACKET + PACKET_MMAP ring. The real thing (T10/11).
 *   pcaplive   both       libpcap live capture. Convenience.
 *
 * Deliberate design point: the FILE backend is primary, not an afterthought.
 * Correctness and performance are both established on replay; AF_PACKET proves
 * we can do it against a real kernel. Trying to do both jobs with live capture
 * gives you neither.
 */
#ifndef PP_SOURCE_H
#define PP_SOURCE_H

#include "pp/pkt.h"

PP_BEGIN_DECLS

typedef struct pp_capture_stats {
    uint64_t packets;     /* delivered to the caller                          */
    uint64_t bytes;       /* sum of wirelen                                    */
    uint64_t truncated;   /* caplen < wirelen: snaplen cut them short          */
    uint64_t kernel_drops;/* dropped by the kernel before we saw them (T11).
                           * The most important number in a capture pipeline
                           * and the one most often not reported: without it,
                           * "we processed 10M packets" is meaningless because
                           * you do not know what the denominator was.         */
    uint64_t errors;      /* malformed records in the source itself            */
} pp_capture_stats;

typedef struct pp_source pp_source;

typedef struct pp_source_ops {
    const char *name;

    /* Fill up to `max` entries of `out`. Returns the count, 0 at end of
     * stream, or -1 on error.
     *
     * BATCH, not one-at-a-time, and that is the whole reason this returns an
     * array (SPEC §4): it amortizes the per-call cost, keeps the parser's code
     * hot in L1i by doing "parse x32" instead of parse/classify/parse/classify,
     * and it is what makes software prefetch possible — you cannot prefetch
     * packet i+4 if you do not know it exists yet.
     *
     * The pp_rawpkt entries BORROW their bytes. They stay valid until the next
     * call to next_batch() (for a ring backend, the frames may be returned to
     * the kernel at that point). Nobody may hold them past that. */
    int (*next_batch)(pp_source *s, pp_rawpkt *out, int max);

    void (*stats)(const pp_source *s, pp_capture_stats *out);
    void (*close)(pp_source *s);
} pp_source_ops;

struct pp_source {
    const pp_source_ops *ops;
    void                *impl;
};

static PP_ALWAYS_INLINE int pp_source_next(pp_source *s, pp_rawpkt *out, int max)
{
    return s->ops->next_batch(s, out, max);
}
static PP_ALWAYS_INLINE void pp_source_stats(const pp_source *s, pp_capture_stats *o)
{
    s->ops->stats(s, o);
}
static PP_ALWAYS_INLINE void pp_source_close(pp_source *s)
{
    if (s && s->ops) s->ops->close(s);
}

/* ---------------------------------------------------------------------------
 * Backend: pcap file replay.
 *
 * mmap-backed, so pp_rawpkt.data points DIRECTLY into the file mapping. Genuine
 * zero copy from disk to parser: no read() buffer, no memcpy, no allocation per
 * packet. The kernel's page cache does the work and we just walk it.
 *
 * Returns 0 on success, -1 on error (errno set; pp_pcapfile_error() explains).
 * ------------------------------------------------------------------------- */
int pp_source_pcapfile_open(pp_source *s, const char *path);

/* Human-readable reason the last pp_source_pcapfile_open() failed. */
const char *pp_pcapfile_error(void);

/* Rewind to the first packet. Benchmarks replay the same corpus repeatedly;
 * re-opening per iteration would measure the filesystem instead of the code. */
void pp_source_pcapfile_rewind(pp_source *s);

PP_END_DECLS

#endif /* PP_SOURCE_H */
