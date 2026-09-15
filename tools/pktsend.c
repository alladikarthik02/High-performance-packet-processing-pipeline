/* pktsend — blast raw Ethernet frames onto an interface.
 *
 * The other half of the AF_PACKET proof. Capturing is only interesting if
 * something is sending, and `ping` gives you a handful of packets a second with
 * no control over their contents.
 *
 * This uses AF_PACKET in the TRANSMIT direction — the same socket family as the
 * capture side, which is a neat demonstration that AF_PACKET is a full raw L2
 * interface and not just a tap: we build a complete Ethernet frame in userspace
 * and hand it to the driver.
 *
 * Linux only, and unapologetically: this whole tool is a Linux kernel interface.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* One TCP-over-IPv4-over-Ethernet frame, built byte by byte.
 *
 * Checksums are left zero. Nothing on the receive path validates them: the NIC
 * would normally offload the check, and pktpipe deliberately does not verify
 * checksums (it classifies headers, it does not terminate connections). Worth
 * being explicit that this is a decision and not an oversight — a real sender
 * must compute them. */
static size_t build_frame(uint8_t *buf, size_t cap, uint16_t sport, uint16_t dport,
                          uint32_t src_ip, uint32_t dst_ip, size_t payload)
{
    if (cap < 54 + payload) return 0;
    size_t o = 0;

    /* Ethernet: dst, src, ethertype */
    static const uint8_t dmac[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
    static const uint8_t smac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    memcpy(buf + o, dmac, 6); o += 6;
    memcpy(buf + o, smac, 6); o += 6;
    buf[o++] = 0x08; buf[o++] = 0x00;              /* 0x0800 IPv4 */

    size_t ip0 = o;
    buf[o++] = 0x45;                                /* v4, IHL=5 */
    buf[o++] = 0x00;
    buf[o++] = 0x00; buf[o++] = 0x00;               /* total length, patched below */
    buf[o++] = 0x12; buf[o++] = 0x34;               /* id */
    buf[o++] = 0x40; buf[o++] = 0x00;               /* DF, offset 0 */
    buf[o++] = 64;                                  /* TTL */
    buf[o++] = 6;                                   /* TCP */
    buf[o++] = 0x00; buf[o++] = 0x00;               /* checksum: see note above */
    buf[o++] = (uint8_t)(src_ip>>24); buf[o++] = (uint8_t)(src_ip>>16);
    buf[o++] = (uint8_t)(src_ip>>8);  buf[o++] = (uint8_t)src_ip;
    buf[o++] = (uint8_t)(dst_ip>>24); buf[o++] = (uint8_t)(dst_ip>>16);
    buf[o++] = (uint8_t)(dst_ip>>8);  buf[o++] = (uint8_t)dst_ip;

    /* TCP */
    buf[o++] = (uint8_t)(sport>>8); buf[o++] = (uint8_t)sport;
    buf[o++] = (uint8_t)(dport>>8); buf[o++] = (uint8_t)dport;
    buf[o++] = 0; buf[o++] = 0; buf[o++] = 0x10; buf[o++] = 0x00;   /* seq */
    buf[o++] = 0; buf[o++] = 0; buf[o++] = 0x20; buf[o++] = 0x00;   /* ack */
    buf[o++] = 0x50;                                /* data offset 5 */
    buf[o++] = 0x10;                                /* ACK */
    buf[o++] = 0xFF; buf[o++] = 0xFF;               /* window */
    buf[o++] = 0x00; buf[o++] = 0x00;               /* checksum */
    buf[o++] = 0x00; buf[o++] = 0x00;               /* urgent */

    for (size_t i = 0; i < payload; i++) buf[o++] = 0x41;

    uint16_t totlen = (uint16_t)(o - ip0);
    buf[ip0 + 2] = (uint8_t)(totlen >> 8);
    buf[ip0 + 3] = (uint8_t)totlen;
    return o;
}

int main(int argc, char **argv)
{
    const char *iface = NULL;
    long count = 10000;
    size_t payload = 6;      /* -> a 60-byte minimum-size frame */
    uint16_t dport = 80;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--iface")   && i+1 < argc) iface   = argv[++i];
        else if (!strcmp(argv[i], "--count")   && i+1 < argc) count   = atol(argv[++i]);
        else if (!strcmp(argv[i], "--payload") && i+1 < argc) payload = (size_t)atol(argv[++i]);
        else if (!strcmp(argv[i], "--dport")   && i+1 < argc) dport   = (uint16_t)atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: pktsend --iface NAME [--count N] [--payload N] [--dport N]\n");
            return 2;
        }
    }
    if (!iface) { fprintf(stderr, "pktsend: --iface is required\n"); return 2; }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket(AF_PACKET)"); return 1; }

    unsigned ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "pktsend: no interface '%s'\n", iface); return 1; }

    /* Union rather than the (struct sockaddr*) cast, for the same
     * strict-aliasing reason as the capture side. */
    union { struct sockaddr sa; struct sockaddr_ll sll; } addr;
    memset(&addr, 0, sizeof addr);
    addr.sll.sll_family   = AF_PACKET;
    addr.sll.sll_protocol = htons(ETH_P_ALL);
    addr.sll.sll_ifindex  = (int)ifindex;
    addr.sll.sll_halen    = ETH_ALEN;
    memcpy(addr.sll.sll_addr, "\x02\x00\x00\x00\x00\x02", 6);

    uint8_t frame[2048];
    uint64_t sent = 0, failed = 0;
    uint64_t t0 = now_ns();

    for (long i = 0; i < count; i++) {
        /* Vary the source port so the capture side sees distinct flows rather
         * than one repeated packet — a classifier fed identical packets tells
         * you nothing about whether it classifies. */
        size_t len = build_frame(frame, sizeof frame,
                                 (uint16_t)(1024 + (i % 60000)), dport,
                                 0xC0A80101u + (uint32_t)(i % 250),
                                 0x0A000001u, payload);
        ssize_t r = sendto(fd, frame, len, 0, &addr.sa, sizeof addr.sll);
        if (r < 0) {
            if (errno == ENOBUFS || errno == EAGAIN) {
                /* The TX queue is full. Not an error — it is backpressure, and
                 * it means we are sending faster than the driver drains. Retry
                 * rather than count it as a failure. */
                i--;
                continue;
            }
            failed++;
        } else {
            sent++;
        }
    }

    uint64_t dt = now_ns() - t0;
    fprintf(stderr, "pktsend: %llu frames on %s in %.3f s (%.3f Mpps offered), %llu failed\n",
            (unsigned long long)sent, iface, (double)dt / 1e9,
            dt ? (double)sent / ((double)dt / 1e9) / 1e6 : 0.0,
            (unsigned long long)failed);
    close(fd);
    return 0;
}
