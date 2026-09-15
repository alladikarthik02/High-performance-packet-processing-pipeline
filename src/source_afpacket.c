/* source_afpacket.c — AF_PACKET capture, with and without a shared ring.
 *
 * The R7 claim, made real. See afpacket.h for the two modes and why both exist.
 */
#define _GNU_SOURCE

#include "pp/afpacket.h"

#ifdef __linux__

#include <arpa/inet.h>   /* htons — omitted at first and only caught by
                         * -Wimplicit-function-declaration; without a prototype
                         * the compiler assumes it returns int, which is exactly
                         * how a byte-order bug gets in silently. */
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

/* ------------------------------------------------------------------------- */

static char g_err[256];
const char *pp_afp_error(void) { return g_err[0] ? g_err : "no error"; }

static void set_err(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
}

void pp_afp_cfg_default(pp_afp_cfg *c)
{
    memset(c, 0, sizeof *c);
    c->mode       = PP_AFP_MMAP;
    /* 4 x 4 MiB = 16 MiB of ring.
     *
     * Sizing rationale, since "why those numbers?" is the question:
     *   - 16 MiB at ~1500 B/frame is ~11k frames of buffer. At 1 Mpps that is
     *     ~11 ms of absorption — enough to ride out a scheduler hiccup or a
     *     page fault without dropping, which is what the ring is FOR.
     *   - 4 MiB blocks are large enough that block handoffs are rare, and few
     *     enough that a partial block's timeout still bounds latency.
     *   - Both are powers of two and multiples of the page size, which the
     *     kernel requires.
     * These are a starting point measured in T12, not received wisdom. */
    c->block_size = 1u << 22;   /* 4 MiB */
    c->block_nr   = 4;
    c->frame_size = 2048;       /* > 1518 MTU + TPACKET3_HDRLEN, power of two */
    c->timeout_ms = 60;         /* release partial blocks; see afpacket.h */
    c->promisc    = 1;
    c->poll_ms    = 100;
}

/* ------------------------------------------------------------------------- */

typedef struct {
    int fd;
    pp_afp_cfg cfg;
    int ifindex;

    /* --- recvfrom mode --- */
    uint8_t *stage;         /* staging buffer, allocated once at open() */

    /* --- MMAP mode --- */
    uint8_t *ring;          /* the shared mapping */
    size_t   ring_len;
    unsigned n_blocks;
    unsigned cur_block;     /* which block we are draining */

    /* Position inside the current block, so next_batch() can return a partial
     * block and resume exactly where it left off on the next call. Without
     * this, a block containing more packets than the batch size would lose the
     * remainder — a silent, data-dependent packet loss that only shows up under
     * load. */
    struct tpacket3_hdr *cur_pkt;
    unsigned cur_pkt_idx;
    unsigned cur_pkt_num;
    int      in_block;

    pp_capture_stats st;
} afp;

/* ------------------------------------------------------------------------- */
/* Mode 1: recvfrom — one syscall per packet (T10, the baseline)              */
/* ------------------------------------------------------------------------- */

/* A staging buffer, because recvfrom() COPIES: the kernel has the frame in its
 * own memory and hands us a copy. That copy is not optional and is precisely
 * what the MMAP ring exists to eliminate.
 *
 * Note this buffer is allocated ONCE at open() and reused for every packet — so
 * even the "slow" mode still honours R6 (no per-packet allocation). Slow here
 * means a syscall and a copy per packet, not a malloc per packet. */
#define AFP_SNAPLEN 2048
#define PP_BATCH_MAX_FRAMES 256   /* == PP_BATCH_MAX; the staging buffer must cover a full batch */

static int afp_next_recvfrom(pp_source *s, pp_rawpkt *out, int max)
{
    afp *a = (afp *)s->impl;
    int n = 0;

    while (n < max) {
        /* Each packet costs: one recvfrom syscall (~1-2 us of boundary
         * crossing) plus one memcpy of the frame. At 1 Mpps that is 1M
         * syscalls per second and the syscalls alone will not fit in a
         * second. This is the wall the ring is built to get past. */
        ssize_t r = recv(a->fd, a->stage + (size_t)n * AFP_SNAPLEN, AFP_SNAPLEN,
                         MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Nothing queued right now.
                 *
                 * Returning 0 here and letting the caller loop again is what
                 * the first version did, and it BUSY-SPINS a core at 100% on an
                 * idle link — the caller has no way to tell "no traffic yet"
                 * from "keep asking". Found by a benchmark that hung rather
                 * than finished, which is a fair way to find it.
                 *
                 * poll() blocks until the kernel has something, so an idle
                 * capture costs no CPU. Mirrors what the mmap path already did;
                 * the two modes should differ in HOW they get frames, not in
                 * whether they melt a core when there are none. */
                if (n > 0) break;   /* hand back what we have */
                struct pollfd pfd = { .fd = a->fd, .events = POLLIN, .revents = 0 };
                int pr = poll(&pfd, 1, a->cfg.poll_ms);
                if (pr < 0 && errno != EINTR) { a->st.errors++; return -1; }
                if (pr == 0) return 0;   /* genuine timeout: no traffic */
                continue;
            }
            if (errno == EINTR) continue;
            a->st.errors++;
            return n ? n : -1;
        }
        out[n].data    = a->stage + (size_t)n * AFP_SNAPLEN;
        out[n].caplen  = (uint32_t)r;
        out[n].wirelen = (uint32_t)r;   /* recv() cannot tell us the true wire
                                         * length if it truncated — another
                                         * thing the ring gives us for free. */
        out[n].ts_ns   = 0;
        a->st.packets++;
        a->st.bytes += (uint64_t)r;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* Mode 2: PACKET_MMAP TPACKET_V3 — the shared ring (T11)                     */
/* ------------------------------------------------------------------------- */

/*
 * HOW THE RING WORKS, and why the barrier below is not optional.
 *
 * The ring is one mmap'd region visible to BOTH the kernel and this process.
 * It is divided into blocks; each block has a header whose `block_status` field
 * is the ownership token:
 *
 *      TP_STATUS_KERNEL (0)  -- the kernel owns this block; do not touch it
 *      TP_STATUS_USER        -- the kernel has finished with it; it is ours
 *
 * The protocol is:
 *   1. We poll block_status until it reads TP_STATUS_USER.
 *   2. We walk the packets inside the block.
 *   3. We write TP_STATUS_KERNEL back, handing the block over.
 *
 * No syscall in the steady state. No copy, ever: out[].data points INTO the
 * ring, which is the same physical memory the NIC's DMA landed in. That is why
 * this is fast, and it is also why the caller must not hold a pp_rawpkt past
 * the next next_batch() call — by then we may have given the block back.
 *
 * THE MEMORY BARRIER (the part that is easy to get wrong and hard to debug):
 *
 * Reading block_status and reading the frames are two loads from shared memory,
 * and BOTH the compiler and the CPU are allowed to reorder them. The compiler
 * can hoist a frame load above the status check because, as far as it can see,
 * nothing in this thread writes either. The CPU can speculate the loads out of
 * order. Neither knows another agent — the kernel, possibly on another core —
 * is writing this memory.
 *
 * If a frame load is reordered before the status load, we read the frame BEFORE
 * the kernel finished writing it: torn or stale packet data, on a machine with
 * plenty of memory, with no crash and no error. It would work in testing and
 * fail under load, which is the worst failure mode there is.
 *
 * So: a full barrier between "I observed TP_STATUS_USER" and "I read the
 * frames", and another between "I finished reading" and "I release the block".
 * The second matters just as much — releasing early lets the kernel overwrite
 * frames we have not read yet.
 *
 * This is the same acquire/release pairing as any lock-free queue. The only
 * unusual part is that the other thread is the kernel.
 */

static PP_ALWAYS_INLINE void barrier(void)
{
    /* __sync_synchronize() is a full hardware memory barrier AND a compiler
     * barrier. On arm64 it lowers to `dmb ish`; on x86-64 to `mfence` (where
     * the strong memory model makes it nearly free). A plain
     * `asm volatile("" ::: "memory")` would stop the COMPILER reordering but
     * not the CPU — sufficient on x86, wrong on arm64. Since this runs on both,
     * it has to be the real thing. */
    __sync_synchronize();
}

static struct tpacket_block_desc *block_at(afp *a, unsigned i)
{
    return (struct tpacket_block_desc *)(a->ring + (size_t)i * a->cfg.block_size);
}

static int afp_next_mmap(pp_source *s, pp_rawpkt *out, int max)
{
    afp *a = (afp *)s->impl;
    int n = 0;

    while (n < max) {
        /* Resume mid-block if the last call filled the caller's batch before
         * the block ran out. */
        if (!a->in_block) {
            struct tpacket_block_desc *bd = block_at(a, a->cur_block);

            /* THE OWNERSHIP CHECK. Volatile so the compiler actually re-loads
             * it each time round rather than caching it in a register and
             * spinning forever on a stale value — a genuine hang, not a
             * theoretical one. */
            volatile uint32_t *status = &bd->hdr.bh1.block_status;
            if (!((*status) & TP_STATUS_USER)) {
                if (n > 0) break;   /* return what we have rather than block */

                struct pollfd pfd = { .fd = a->fd, .events = POLLIN, .revents = 0 };
                int pr = poll(&pfd, 1, a->cfg.poll_ms);
                if (pr < 0 && errno != EINTR) { a->st.errors++; return -1; }
                if (pr == 0) return 0;   /* timeout: no traffic, not an error */
                continue;
            }

            /* We have observed TP_STATUS_USER. Everything the kernel wrote into
             * this block must become visible BEFORE we read any of it. */
            barrier();

            a->in_block    = 1;
            a->cur_pkt_num = bd->hdr.bh1.num_pkts;
            a->cur_pkt_idx = 0;
            a->cur_pkt     = (struct tpacket3_hdr *)
                             ((uint8_t *)bd + bd->hdr.bh1.offset_to_first_pkt);

            if (a->cur_pkt_num == 0) {
                /* An empty block: the timeout fired with nothing in it. Release
                 * it and move on. */
                barrier();
                bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
                a->in_block = 0;
                a->cur_block = (a->cur_block + 1) % a->n_blocks;
                continue;
            }
        }

        /* Drain packets out of the current block. */
        while (a->cur_pkt_idx < a->cur_pkt_num && n < max) {
            struct tpacket3_hdr *h = a->cur_pkt;

            out[n].data    = (const uint8_t *)h + h->tp_mac;
            out[n].caplen  = h->tp_snaplen;
            /* tp_len is the TRUE wire length even when tp_snaplen truncated the
             * capture. The recvfrom path cannot distinguish these at all; the
             * ring gives us both, which is exactly the caplen/wirelen split the
             * parser depends on (SPEC §7.9). */
            out[n].wirelen = h->tp_len;
            out[n].ts_ns   = (uint64_t)h->tp_sec * 1000000000ull + h->tp_nsec;

            a->st.packets++;
            a->st.bytes += h->tp_len;
            if (h->tp_snaplen < h->tp_len) a->st.truncated++;

            n++;
            a->cur_pkt_idx++;
            if (a->cur_pkt_idx < a->cur_pkt_num)
                a->cur_pkt = (struct tpacket3_hdr *)((uint8_t *)h + h->tp_next_offset);
        }

        if (a->cur_pkt_idx >= a->cur_pkt_num) {
            /* Block drained. Everything we read must be complete BEFORE the
             * kernel is told it may reuse this memory — otherwise it can
             * overwrite frames while we are still reading them. */
            barrier();
            block_at(a, a->cur_block)->hdr.bh1.block_status = TP_STATUS_KERNEL;
            a->in_block  = 0;
            a->cur_block = (a->cur_block + 1) % a->n_blocks;
        } else {
            break;   /* caller's batch is full; resume here next call */
        }
    }

    return n;
}

/* ------------------------------------------------------------------------- */

void pp_source_afpacket_update_drops(pp_source *s)
{
    afp *a = (afp *)s->impl;
    struct tpacket_stats_v3 ts;
    socklen_t len = sizeof ts;

    if (getsockopt(a->fd, SOL_PACKET, PACKET_STATISTICS, &ts, &len) == 0) {
        /* ACCUMULATE, do not assign.
         *
         * The kernel RESETS this counter when it is read. Writing
         * `st.kernel_drops = ts.tp_drops` looks right and reports only the
         * drops since the last poll — so a run that dropped steadily reports
         * whatever happened in the final 100 ms and calls it the total. Real
         * bug, easy to write, and it under-reports in the direction that
         * flatters you. */
        a->st.kernel_drops += ts.tp_drops;
    }
}

static void afp_stats(const pp_source *s, pp_capture_stats *o)
{
    *o = ((const afp *)s->impl)->st;
}

static void afp_close(pp_source *s)
{
    afp *a = (afp *)s->impl;
    if (!a) return;
    pp_source_afpacket_update_drops(s);   /* catch the final interval's drops */
    if (a->ring) munmap(a->ring, a->ring_len);
    if (a->stage) free(a->stage);
    if (a->fd >= 0) close(a->fd);
    free(a);
    s->impl = NULL;
}

static const pp_source_ops afp_ops_recvfrom = {
    .name = "afpacket-recvfrom", .next_batch = afp_next_recvfrom,
    .stats = afp_stats, .close = afp_close,
};
static const pp_source_ops afp_ops_mmap = {
    .name = "afpacket-mmap", .next_batch = afp_next_mmap,
    .stats = afp_stats, .close = afp_close,
};

/* ------------------------------------------------------------------------- */

int pp_source_afpacket_open(pp_source *s, const char *ifname, const pp_afp_cfg *cfg)
{
    g_err[0] = 0;

    afp *a = (afp *)calloc(1, sizeof *a);
    if (!a) { set_err("out of memory"); return -1; }
    a->fd = -1;
    a->cfg = *cfg;

    /* THE SOCKET.
     *
     * AF_PACKET   — the Linux packet family: raw frames from below the IP stack.
     * SOCK_RAW    — complete frames INCLUDING the Ethernet header. (SOCK_DGRAM
     *               would strip L2 and hand us cooked packets, which would make
     *               our L2 parser meaningless.)
     * ETH_P_ALL   — every protocol, not just IP. In NETWORK byte order, hence
     *               the htons: a real and classic bug is omitting it, which on
     *               a little-endian machine asks for protocol 0x0300 and
     *               silently captures nothing at all. */
    a->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (a->fd < 0) {
        set_err("socket(AF_PACKET, SOCK_RAW): %s%s", strerror(errno),
                errno == EPERM ? " (needs CAP_NET_RAW — run with --cap-add=NET_RAW)" : "");
        goto fail;
    }

    if (ifname && *ifname) {
        a->ifindex = (int)if_nametoindex(ifname);
        if (a->ifindex == 0) {
            set_err("interface '%s' not found: %s", ifname, strerror(errno));
            goto fail;
        }
    }

    if (cfg->mode == PP_AFP_MMAP) {
        /* TPACKET_V3, requested BEFORE the ring is set up — the version
         * determines the ring's layout, so asking afterwards is too late and
         * the kernel would hand us a V1/V2 layout we would then misparse. */
        int ver = TPACKET_V3;
        if (setsockopt(a->fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
            set_err("setsockopt(PACKET_VERSION, TPACKET_V3): %s", strerror(errno));
            goto fail;
        }

        struct tpacket_req3 req;
        memset(&req, 0, sizeof req);
        req.tp_block_size      = cfg->block_size;
        req.tp_frame_size      = cfg->frame_size;
        req.tp_block_nr        = cfg->block_nr;
        req.tp_frame_nr        = (cfg->block_size * cfg->block_nr) / cfg->frame_size;
        req.tp_retire_blk_tov  = cfg->timeout_ms;   /* THE latency knob */
        req.tp_feature_req_word = 0;

        if (setsockopt(a->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
            set_err("setsockopt(PACKET_RX_RING): %s "
                    "(block_size=%u must be a power of two and a multiple of PAGE_SIZE; "
                    "frame_size=%u must exceed the MTU + TPACKET3_HDRLEN)",
                    strerror(errno), cfg->block_size, cfg->frame_size);
            goto fail;
        }

        a->ring_len = (size_t)cfg->block_size * cfg->block_nr;

        /* MAP_SHARED, not MAP_PRIVATE. This is the entire point: the mapping
         * must be the SAME physical pages the kernel writes into. MAP_PRIVATE
         * would give us a copy-on-write view and we would sit staring at a
         * snapshot, seeing no packets ever, with no error to explain it. */
        a->ring = (uint8_t *)mmap(NULL, a->ring_len, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_LOCKED, a->fd, 0);
        if (a->ring == MAP_FAILED) {
            a->ring = NULL;
            set_err("mmap(ring, %zu bytes): %s%s", a->ring_len, strerror(errno),
                    errno == EPERM || errno == EAGAIN
                        ? " (MAP_LOCKED needs CAP_IPC_LOCK or a raised RLIMIT_MEMLOCK)"
                        : "");
            goto fail;
        }
        a->n_blocks = cfg->block_nr;
        s->ops = &afp_ops_mmap;
    } else {
        /* recvfrom mode: one staging buffer for a whole batch, allocated ONCE.
         * Slow means a syscall and a copy per packet — never a malloc. */
        a->stage = (uint8_t *)calloc(PP_BATCH_MAX_FRAMES, AFP_SNAPLEN);
        if (!a->stage) { set_err("out of memory for staging buffer"); goto fail; }
        s->ops = &afp_ops_recvfrom;
    }

    /* BIND LAST, and bind deliberately.
     *
     * The socket starts receiving the moment it is bound, so binding after the
     * ring exists means no frames arrive before there is somewhere to put them.
     * Binding first would drop whatever arrived in between — a small, real,
     * timing-dependent hole. */
    /* A UNION, not the (struct sockaddr *)&sll cast every networking tutorial
     * on earth uses.
     *
     * That cast reads a sockaddr_ll object through a sockaddr lvalue, which
     * violates strict aliasing — gcc says so out loud here
     * (-Wstrict-aliasing). It is UB that has worked for thirty years, and it is
     * the SAME defect this project refuses in the parser (SPEC §7.2). Waving it
     * through in the socket code because "everyone does it" would make that
     * principle decorative.
     *
     * A union is the standard-blessed way to type-pun in C: writing one member
     * and reading another is explicitly permitted. It costs nothing, silences
     * the warning honestly rather than by suppressing it, and the generated
     * code is identical. */
    union {
        struct sockaddr    sa;
        struct sockaddr_ll sll;
    } addr;
    memset(&addr, 0, sizeof addr);
    addr.sll.sll_family   = AF_PACKET;
    addr.sll.sll_protocol = htons(ETH_P_ALL);
    addr.sll.sll_ifindex  = a->ifindex;   /* 0 == every interface */
    if (bind(a->fd, &addr.sa, sizeof addr.sll) < 0) {
        set_err("bind(%s): %s", ifname ? ifname : "<any>", strerror(errno));
        goto fail;
    }

    if (cfg->promisc && a->ifindex) {
        /* PACKET_MR_PROMISC via setsockopt rather than ioctl(SIOCSIFFLAGS).
         * The ioctl route sets a global flag on the interface and leaves it set
         * if we crash; the membership route is refcounted by the kernel and
         * released automatically when the socket closes. Not tidiness — the
         * ioctl version leaves the operator's NIC in promiscuous mode after a
         * crash, which is a real thing to inflict on someone. */
        struct packet_mreq mr;
        memset(&mr, 0, sizeof mr);
        mr.mr_ifindex = a->ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(a->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) {
            set_err("setsockopt(PACKET_ADD_MEMBERSHIP, PROMISC): %s", strerror(errno));
            goto fail;
        }
    }

    s->impl = a;
    return 0;

fail:
    if (a->ring) munmap(a->ring, a->ring_len);
    if (a->stage) free(a->stage);
    if (a->fd >= 0) close(a->fd);
    free(a);
    return -1;
}

#endif /* __linux__ */
