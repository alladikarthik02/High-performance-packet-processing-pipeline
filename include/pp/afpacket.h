/* afpacket.h — capture against the Linux networking stack.
 *
 * THIS IS THE R7 CLAIM: "Worked against the Linux networking stack to capture
 * and process traffic."
 *
 * AF_PACKET is the Linux raw-socket family. It delivers complete Ethernet
 * frames from below the IP stack — the same door tcpdump uses, except tcpdump
 * reaches it through libpcap and this reaches it directly. It does not exist on
 * macOS or the BSDs, which capture through /dev/bpf instead; the two are not
 * variants of one another. That is why this project builds and runs on Linux
 * rather than #ifdef'ing a path that never executes (SPEC §5).
 *
 * TWO MODES, and the difference between them is the whole point:
 *
 *   RECVFROM (T10)  — one syscall per packet. The obvious implementation and
 *                     the honest baseline. At 1 Mpps that is 1M syscalls/sec,
 *                     each crossing the user/kernel boundary.
 *
 *   MMAP RING (T11) — a buffer shared between kernel and userspace via
 *                     PACKET_RX_RING + mmap(). The kernel writes frames into
 *                     it; we read them from the SAME memory. Steady state:
 *                     ZERO syscalls and ZERO copies. The kernel and the
 *                     process pass ownership of each block through a status
 *                     flag rather than through a system call.
 *
 * Both are implemented because the comparison is the interesting result, and
 * you cannot report a speedup against a baseline you never built. T12 measures
 * it.
 */
#ifndef PP_AFPACKET_H
#define PP_AFPACKET_H

#include "pp/source.h"

#ifdef __linux__

PP_BEGIN_DECLS

typedef enum pp_afp_mode {
    PP_AFP_RECVFROM = 0,   /* T10: a syscall per packet — the baseline   */
    PP_AFP_MMAP     = 1    /* T11: TPACKET_V3 shared ring — the real one */
} pp_afp_mode;

typedef struct pp_afp_cfg {
    pp_afp_mode mode;

    /* --- ring geometry (MMAP mode only) ---
     *
     * These three numbers are the whole art of PACKET_MMAP, and "how did you
     * size the ring?" is the question an interviewer asks to find out whether
     * you actually ran this.
     *
     * block_size:  the unit the kernel hands to userspace. Must be a multiple
     *              of PAGE_SIZE and a power of two. Bigger blocks = fewer
     *              handoffs = less overhead, but a block is only released to
     *              us when it FILLS or when its timeout expires — so a big
     *              block on a quiet link adds latency.
     * block_nr:    how many blocks. total ring = block_size * block_nr, and
     *              that is the entire buffer standing between a traffic burst
     *              and a drop.
     * frame_size:  the per-packet slot. Must be >= the largest frame plus
     *              TPACKET3_HDRLEN. Too small silently truncates; too large
     *              wastes ring on empty space.
     * timeout_ms:  how long the kernel waits before releasing a partial block.
     *              THIS IS THE LATENCY KNOB, and forgetting it is the classic
     *              PACKET_MMAP bug: set it to 0 and a partially filled block is
     *              never released, so on a quiet link your packets simply never
     *              arrive and everything looks broken.
     *
     * Defaults below: 16 MiB total (4 x 4 MiB), 2 KiB frames, 60 ms.
     */
    unsigned block_size;
    unsigned block_nr;
    unsigned frame_size;
    unsigned timeout_ms;

    int promisc;      /* put the interface in promiscuous mode */
    int poll_ms;      /* poll() wait when the ring is empty; -1 = block forever */
} pp_afp_cfg;

void pp_afp_cfg_default(pp_afp_cfg *c);

/* Open a capture on `ifname` (e.g. "veth0", or NULL for every interface).
 *
 * Requires CAP_NET_RAW. Returns 0, or -1 with a reason from pp_afp_error().
 */
int pp_source_afpacket_open(pp_source *s, const char *ifname, const pp_afp_cfg *cfg);

const char *pp_afp_error(void);

/* Kernel-side drop count, from PACKET_STATISTICS.
 *
 * The most important number in a capture pipeline and the one most often not
 * reported. "We processed 10M packets" is meaningless without it: you do not
 * know whether the denominator was 10M or 40M. A capture tool that cannot say
 * how much it MISSED is not measuring anything.
 *
 * Note the kernel resets this counter on read — so it must be accumulated, not
 * sampled. Reading it twice and reporting the second value is a real bug and an
 * easy one to write. */
void pp_source_afpacket_update_drops(pp_source *s);

PP_END_DECLS

#endif /* __linux__ */
#endif /* PP_AFPACKET_H */
