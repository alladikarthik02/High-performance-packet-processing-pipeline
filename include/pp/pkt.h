/* pkt.h — the packet handle and the parsed-metadata struct.
 *
 * This header is where the "cache-friendly layout" claim (SPEC R5) either holds
 * or falls apart, so the reasoning is written down rather than assumed.
 */
#ifndef PP_PKT_H
#define PP_PKT_H

#include "pp/pp.h"

PP_BEGIN_DECLS

/* ---------------------------------------------------------------------------
 * Bounds on attacker-controlled repetition.
 *
 * Every one of these caps exists because the corresponding header structure can
 * be nested by whoever sends the packet. Without a cap, "parse until done" is a
 * remote denial of service: a crafted packet spins the parser forever while the
 * NIC keeps delivering more (SPEC §7.8). A cap turns an unbounded loop into a
 * bounded one and a crash into a counter.
 * ------------------------------------------------------------------------- */
#define PP_MAX_VLANS        2   /* 802.1Q, then QinQ. A third tag is not real traffic. */
#define PP_MAX_IP6_EXTHDRS  8   /* RFC 8200 sets no limit; the real world does. */
#define PP_MAX_TUNNEL_DEPTH 1   /* One VXLAN decap. Nested tunnels are a DoS vector. */

/* Which layers the parser successfully reached. A bitmask, not a set of bools,
 * because it costs one byte and one test instruction. */
enum pp_layer_bits {
    PP_LAYER_L2      = 1u << 0,
    PP_LAYER_VLAN    = 1u << 1,
    PP_LAYER_L3      = 1u << 2,
    PP_LAYER_L4      = 1u << 3,
    PP_LAYER_PAYLOAD = 1u << 4,
    PP_LAYER_TUNNEL  = 1u << 5
};

/* Parse outcomes.
 *
 * Note what is NOT here: there is no "throw" and no "abort". A malformed packet
 * is *data*, not an exceptional condition — on a real link a measurable fraction
 * of traffic is malformed, truncated, or hostile. The parser records where it
 * stopped and why, keeps whatever it already decoded, and returns. The pipeline
 * counts it and moves on. (SPEC §3.3 rule 4.) */
enum pp_err {
    PP_OK = 0,
    PP_ERR_TRUNC_L2,          /* ran out of captured bytes inside the L2 header  */
    PP_ERR_TRUNC_VLAN,
    PP_ERR_TRUNC_L3,
    PP_ERR_TRUNC_L4,
    PP_ERR_TRUNC_TUNNEL,
    PP_ERR_BAD_IHL,           /* IPv4 IHL < 5 or beyond captured length          */
    PP_ERR_BAD_IP_VERSION,
    PP_ERR_BAD_TCP_DOFF,      /* TCP data offset < 5: header shorter than itself */
    PP_ERR_BAD_LEN,           /* a length field contradicts the captured bytes   */
    PP_ERR_TOO_MANY_VLANS,    /* VLAN stack deeper than PP_MAX_VLANS             */
    PP_ERR_TOO_MANY_EXTHDRS,  /* IPv6 next-header chain bomb                     */
    PP_ERR_TOO_DEEP_TUNNEL,   /* tunnel recursion bomb                           */
    PP_ERR_UNSUPPORTED_L3,    /* not IPv4/IPv6 — not an error, just not decoded  */
    PP_ERR__COUNT
};

const char *pp_err_str(int err);

/* ---------------------------------------------------------------------------
 * pp_rawpkt — a borrowed view of bytes we did not allocate and do not own.
 *
 * `data` points into a pcap file mapping, a libpcap buffer, or a kernel MMAP
 * ring frame. The pipeline never copies it and never frees it. It is `const`
 * because the data plane is read-only over packet bytes: we classify traffic,
 * we do not rewrite it. Making that a type-system fact rather than a convention
 * means the compiler rejects a whole class of mistake.
 * ------------------------------------------------------------------------- */
typedef struct pp_rawpkt {
    const uint8_t *data;    /* borrowed; NOT owned, NOT freed, NOT copied */
    uint32_t       caplen;  /* bytes actually available at `data`         */
    uint32_t       wirelen; /* bytes that were on the wire (may exceed caplen) */
    uint64_t       ts_ns;   /* capture timestamp, nanoseconds             */
} pp_rawpkt;

/* ---------------------------------------------------------------------------
 * pp_meta — everything the parser learned about one packet. EXACTLY one
 * 64-byte cache line, enforced below by a static_assert that fails the build.
 *
 * Two decisions carry this budget, and both are the interesting answer to
 * "what makes it cache-friendly?":
 *
 * 1. OFFSETS, NOT POINTERS. Four pointers to the layer starts would cost 32
 *    bytes on a 64-bit machine; four uint16 offsets cost 8. That 24-byte saving
 *    is why this fits in a line at all. It is sound because a packet is at most
 *    64 KiB, so 16 bits always suffices. A free bonus: offsets survive the
 *    buffer being relocated, and can be handed to another core alongside the
 *    packet without fixing up addresses. Pointers could not.
 *
 * 2. NO IPv6 ADDRESSES. IPv4 src+dst is 8 bytes and earns its place. IPv6
 *    src+dst is 32 bytes — half the line for a field the classifier reads at
 *    most once. So IPv6 addresses are NOT copied here; they are read from the
 *    packet at `l3_off + 8` and `l3_off + 24` when needed. This is zero-copy
 *    applied honestly: those bytes are already in L1, because we just parsed
 *    them a few nanoseconds ago. Copying them would be pure loss.
 *
 * Fields are ordered widest-first (u32s, then u16s, then u8s) so the compiler
 * inserts no padding between them. The only padding is the explicit tail.
 * ------------------------------------------------------------------------- */
typedef struct pp_meta {
    /* --- 32-bit fields (16 bytes) ---
     *
     * The alignment specifier rides on the FIRST MEMBER rather than on the
     * struct tag. `struct alignas(64) pp_meta {...}` is valid C++ and is NOT
     * valid C11 — C's grammar has no slot for a declaration specifier between
     * `struct` and its tag. Member position is legal in both languages, and
     * both guarantee a struct's alignment is at least its strictest member's,
     * so the whole struct still lands on a 64-byte boundary and sizeof still
     * rounds up to 64. (Another instalment of the shared-header tax; see the
     * PP_ALIGNAS/PP_STATIC_ASSERT note in pp.h.) */
    PP_CACHE_ALIGNED uint32_t ip_src;  /* IPv4 only, network byte order. IPv6: see note 2. */
    uint32_t ip_dst;
    uint32_t flow_hash;     /* 5-tuple hash; classifier input, computed once    */
    uint32_t vni;           /* VXLAN VNI when PP_LAYER_TUNNEL, else 0           */

    /* --- 16-bit fields (28 bytes) --- */
    uint16_t caplen;        /* mirrored from pp_rawpkt: the bound for EVERY read */
    uint16_t wirelen;       /* reporting only — never a bound (SPEC §7.9)        */
    uint16_t l2_off;        /* always 0 today; explicit for tunnels/inner frames */
    uint16_t l3_off;
    uint16_t l4_off;
    uint16_t payload_off;
    uint16_t payload_len;
    uint16_t eth_type;      /* host order, AFTER VLAN tags are stripped         */
    uint16_t vlan_outer;    /* VID, or PP_VLAN_NONE                             */
    uint16_t vlan_inner;    /* QinQ inner VID, or PP_VLAN_NONE                  */
    uint16_t sport;         /* host order; 0 when no L4 ports (e.g. fragment)   */
    uint16_t dport;
    uint16_t frag_off;      /* IPv4 fragment offset in 8-byte units             */

    /* When PP_LAYER_TUNNEL: the OUTER (underlay) L3 offset.
     *
     * Everything else in this struct describes the INNERMOST headers, because
     * that is the tenant's real traffic and the thing a rule wants to match. So
     * an "inner_l3_off" field would just be a copy of l3_off and earn nothing.
     * The outer L3 is what would otherwise be lost, so that is what is kept —
     * it lets a rule still classify on the underlay (which physical hosts are
     * talking) as well as on the overlay (which tenant flow). */
    uint16_t outer_l3_off;

    /* --- 8-bit fields (9 bytes) --- */
    uint8_t ip_ver;         /* 0 (none), 4, or 6                                */
    uint8_t ip_proto;       /* FINAL L4 proto, after walking IPv6 ext headers   */
    uint8_t ttl;            /* IPv4 TTL / IPv6 hop limit                        */
    uint8_t tcp_flags;
    uint8_t ip_hlen;        /* IPv4 header length in bytes (IHL * 4)            */
    uint8_t l4_hlen;
    uint8_t layers;         /* bitmask of pp_layer_bits                         */
    uint8_t err;            /* enum pp_err — where parsing stopped, and why     */
    uint8_t tunnel_depth;

    /* --- explicit tail padding (11 bytes) ---
     * Named, not implicit. It is headroom for later fields, and it makes the
     * 64-byte total a deliberate design point rather than an accident of the
     * current field list. Anything added here must keep the assert below true. */
    uint8_t _reserved[11];
} pp_meta;

/* The claim from the résumé bullet, mechanically enforced.
 *
 * This is the difference between "cache-friendly" as a adjective and as an
 * invariant. Add a field that pushes past 64 bytes and the BUILD FAILS — nobody
 * has to notice in review, and the claim cannot silently rot. */
PP_STATIC_ASSERT(sizeof(pp_meta) == 64,
                 "pp_meta must be exactly one 64-byte cache line (SPEC R5)");

/* Size alone is not enough. A 64-byte struct that starts at offset 32 of a
 * cache line straddles TWO lines, and then every access costs two cache misses
 * instead of one — the exact opposite of what the layout was for. Size plus
 * alignment together are what make the one-line claim true. */
PP_STATIC_ASSERT(PP_ALIGNOF(pp_meta) == PP_CACHELINE,
                 "pp_meta must be cache-line aligned, not merely cache-line sized");

#define PP_VLAN_NONE 0xFFFFu   /* VID 0 is legal (priority-tagged), so 0 cannot mean "absent" */

/* Reset metadata to a known-empty state. Deliberately not memset(0): ip_ver 0
 * and layers 0 are correct zeros, but vlan_* must init to PP_VLAN_NONE because
 * VLAN ID 0 is a *legal* VID used for priority tagging — using 0 as the "no
 * VLAN" sentinel would make a priority-tagged frame indistinguishable from an
 * untagged one. A subtle wire-format detail that a memset would get wrong. */
void pp_meta_init(pp_meta *m, const pp_rawpkt *pkt);

PP_END_DECLS

#endif /* PP_PKT_H */
