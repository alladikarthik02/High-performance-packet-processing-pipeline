/* source_pcapfile.c — deterministic .pcap replay, zero-copy via mmap.
 *
 * The classic libpcap file format (not pcapng). Deliberately hand-rolled rather
 * than linked against libpcap:
 *
 *   - It is ~40 lines of format. The dependency is not worth it.
 *   - libpcap's pcap_next_ex() hands back ONE packet per call and copies into
 *     its own buffer. This backend mmaps the file and points straight into the
 *     page cache, which is both zero-copy and batchable — the two properties
 *     the whole pipeline is built around.
 *   - The byte-order handling is a good demonstration of why proto.h reads
 *     fields the way it does.
 */
#define _DEFAULT_SOURCE

#include "pp/source.h"
#include "pp/proto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 * Format.
 *
 * Global header, 24 bytes:
 *   magic[4] major[2] minor[2] thiszone[4] sigfigs[4] snaplen[4] linktype[4]
 *
 * Then, per packet:
 *   ts_sec[4] ts_subsec[4] incl_len[4] orig_len[4] then incl_len bytes
 *
 * incl_len == caplen (what we have), orig_len == wirelen (what was on the
 * wire). They differ when the capture used a snaplen — the distinction the
 * parser cares about most (SPEC §7.9).
 * ------------------------------------------------------------------------- */
#define PCAP_GHDR_LEN 24u
#define PCAP_RHDR_LEN 16u

/* The magic number does double duty: it identifies the format AND announces the
 * writer's byte order, by whether it reads forwards or backwards.
 *   0xa1b2c3d4  same endianness as the writer, timestamps in MICROseconds
 *   0xa1b23c4d  same endianness, timestamps in NANOseconds  (note: 3c4d)
 * ...and the byte-reversed forms mean "written by the other endianness".
 * A file written on a big-endian capture box and read on this little-endian one
 * is completely normal and must just work. */
#define PCAP_MAGIC_US     0xa1b2c3d4u
#define PCAP_MAGIC_US_SWAP 0xd4c3b2a1u
#define PCAP_MAGIC_NS     0xa1b23c4du
#define PCAP_MAGIC_NS_SWAP 0x4d3cb2a1u

#define PCAP_LINKTYPE_ETHERNET 1u

/* Sanity bound on a single record. The pcap header's length fields are, like
 * every length field in this project, UNTRUSTED (SPEC §7.9) — a corrupt or
 * malicious file can claim a 4 GiB packet. Nothing on Ethernet is above ~64 KiB
 * even with jumbo frames, so anything past this is a broken file rather than a
 * big packet. */
#define PCAP_MAX_CAPLEN 262144u

typedef struct {
    const uint8_t *map;      /* mmap'd file, borrowed by every pp_rawpkt */
    size_t         map_len;
    size_t         pos;      /* cursor: offset of the next record header */
    size_t         first;    /* offset of the first record (== PCAP_GHDR_LEN) */

    int            swapped;  /* writer's byte order differs from ours */
    int            nanosec;  /* timestamps are ns, not us */
    uint32_t       linktype;
    uint32_t       snaplen;

    pp_capture_stats st;
} pcapfile;

static char g_err[160];
const char *pp_pcapfile_error(void) { return g_err[0] ? g_err : "no error"; }

static void set_err(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
}

/* Read a 32-bit field in the FILE's byte order.
 *
 * No #ifdef, no bswap, no ntohl. Two functions that differ only in the order of
 * their shifts, chosen by a runtime flag. Each is obviously correct on any
 * host by inspection, which is exactly the property the parser's readers have
 * and for the same reason. */
static PP_ALWAYS_INLINE uint32_t rd32(const pcapfile *f, const uint8_t *p)
{
    return f->swapped ? pp_rd_be32(p) : pp_rd_le32(p);
}

static int pcapfile_next_batch(pp_source *s, pp_rawpkt *out, int max)
{
    pcapfile *f = (pcapfile *)s->impl;
    int n = 0;

    while (n < max) {
        /* Enough left for a record header? */
        if (f->pos + PCAP_RHDR_LEN > f->map_len)
            break;   /* clean EOF (or a trailing partial header — same action) */

        const uint8_t *rh = f->map + f->pos;
        uint32_t ts_sec  = rd32(f, rh + 0);
        uint32_t ts_sub  = rd32(f, rh + 4);
        uint32_t incl    = rd32(f, rh + 8);
        uint32_t orig    = rd32(f, rh + 12);

        /* incl_len is a claim by whoever wrote the file. Two ways it lies, and
         * they are the same two shapes as every other length in this project:
         * absurdly large (a corrupt/hostile file), or larger than the bytes
         * that actually remain (a truncated file — extremely common, e.g. a
         * capture killed with ^C mid-write). Neither may be trusted into a
         * pointer. */
        if (incl > PCAP_MAX_CAPLEN) {
            f->st.errors++;
            break;   /* the file is corrupt from here on; stop rather than guess */
        }
        if (f->pos + PCAP_RHDR_LEN + incl > f->map_len) {
            /* Truncated final record. Not an error worth shouting about — it is
             * what every ^C'd capture looks like — but we must not hand out a
             * pp_rawpkt pointing past the mapping. Doing so would segfault on
             * a file that tcpdump produces every day. */
            f->st.errors++;
            break;
        }

        out[n].data    = rh + PCAP_RHDR_LEN;   /* straight into the mapping */
        out[n].caplen  = incl;
        out[n].wirelen = orig;
        out[n].ts_ns   = (uint64_t)ts_sec * 1000000000ull +
                         (f->nanosec ? (uint64_t)ts_sub : (uint64_t)ts_sub * 1000ull);

        f->st.packets++;
        f->st.bytes += orig;
        if (incl < orig) f->st.truncated++;

        f->pos += PCAP_RHDR_LEN + incl;
        n++;
    }

    return n;
}

static void pcapfile_stats(const pp_source *s, pp_capture_stats *o)
{
    *o = ((const pcapfile *)s->impl)->st;
}

static void pcapfile_close(pp_source *s)
{
    pcapfile *f = (pcapfile *)s->impl;
    if (!f) return;
    if (f->map) munmap((void *)f->map, f->map_len);
    free(f);
    s->impl = NULL;
}

static const pp_source_ops pcapfile_ops = {
    .name       = "pcapfile",
    .next_batch = pcapfile_next_batch,
    .stats      = pcapfile_stats,
    .close      = pcapfile_close,
};

void pp_source_pcapfile_rewind(pp_source *s)
{
    pcapfile *f = (pcapfile *)s->impl;
    if (!f) return;
    f->pos = f->first;
    memset(&f->st, 0, sizeof f->st);
}

int pp_source_pcapfile_open(pp_source *s, const char *path)
{
    g_err[0] = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) { set_err("open(%s): %s", path, strerror(errno)); return -1; }

    struct stat sb;
    if (fstat(fd, &sb) < 0) { set_err("fstat: %s", strerror(errno)); close(fd); return -1; }

    if ((size_t)sb.st_size < PCAP_GHDR_LEN) {
        set_err("file is %lld bytes, too short for a %u-byte pcap header",
                (long long)sb.st_size, PCAP_GHDR_LEN);
        close(fd);
        return -1;
    }

    void *map = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    /* The fd can be closed immediately: the mapping keeps its own reference to
     * the underlying file. Holding it open would just leak a descriptor. */
    close(fd);
    if (map == MAP_FAILED) { set_err("mmap: %s", strerror(errno)); return -1; }

    pcapfile *f = (pcapfile *)calloc(1, sizeof *f);
    if (!f) { munmap(map, (size_t)sb.st_size); set_err("out of memory"); return -1; }

    f->map     = (const uint8_t *)map;
    f->map_len = (size_t)sb.st_size;

    /* Byte order and timestamp resolution, both from the magic number.
     * Read it big-endian first purely as a fixed frame of reference; the four
     * constants below are then just four distinct bit patterns to compare
     * against, and the host's own endianness never enters into it. */
    uint32_t magic = pp_rd_be32(f->map);
    switch (magic) {
    case PCAP_MAGIC_US:      f->swapped = 1; f->nanosec = 0; break;
    case PCAP_MAGIC_NS:      f->swapped = 1; f->nanosec = 1; break;
    case PCAP_MAGIC_US_SWAP: f->swapped = 0; f->nanosec = 0; break;
    case PCAP_MAGIC_NS_SWAP: f->swapped = 0; f->nanosec = 1; break;
    default:
        set_err("not a pcap file (magic = 0x%08x); pcapng is not supported", magic);
        munmap(map, f->map_len);
        free(f);
        return -1;
    }

    f->snaplen  = rd32(f, f->map + 16);
    f->linktype = rd32(f, f->map + 20);

    if (f->linktype != PCAP_LINKTYPE_ETHERNET) {
        /* Refuse rather than mis-parse. A Linux cooked-mode (SLL) capture has a
         * 16-byte pseudo-header where the Ethernet header would be; parsing it
         * as Ethernet yields plausible garbage rather than an error, which is
         * the worst possible outcome. `tcpdump -i any` produces exactly this,
         * so it is a mistake a user WILL make. */
        set_err("linktype %u is not Ethernet (1); "
                "captures from `-i any` are cooked-mode and unsupported",
                f->linktype);
        munmap(map, f->map_len);
        free(f);
        return -1;
    }

    f->first = PCAP_GHDR_LEN;
    f->pos   = PCAP_GHDR_LEN;

    s->ops  = &pcapfile_ops;
    s->impl = f;
    return 0;
}
