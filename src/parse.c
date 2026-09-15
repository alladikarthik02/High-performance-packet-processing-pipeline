/* parse.c — the packet parser.
 *
 * Grows one layer per task: T2 = L2, T3 = L3, T4 = L4 + tunnels.
 */
#include "pp/parse.h"
#include "pp/proto.h"

/* ---------------------------------------------------------------------------
 * The cursor.
 *
 * One place that knows "how many bytes do I actually have left", so that the
 * bounds check exists once instead of being retyped at every header — retyped
 * bounds checks are where the off-by-one lives.
 *
 * The invariant is `off <= len` at all times. It is maintained by only ever
 * advancing through cur_advance(), which refuses to step past len.
 * ------------------------------------------------------------------------- */
typedef struct {
    const uint8_t *base;
    uint16_t       len;   /* == caplen: bytes we ACTUALLY have. Never wirelen. */
    uint16_t       off;   /* current position; invariant: off <= len           */
} pp_cursor;

/* Bytes remaining. Written defensively rather than as `len - off` because if
 * the invariant were ever broken, `len - off` on unsigned types underflows to
 * ~65535 and every subsequent bounds check silently passes. That is a buffer
 * overread built out of two correct-looking subtractions. */
static PP_ALWAYS_INLINE uint16_t cur_avail(const pp_cursor *c)
{
    return c->off <= c->len ? (uint16_t)(c->len - c->off) : 0u;
}

static PP_ALWAYS_INLINE int cur_has(const pp_cursor *c, uint16_t n)
{
    return cur_avail(c) >= n;
}

static PP_ALWAYS_INLINE const uint8_t *cur_ptr(const pp_cursor *c)
{
    return c->base + c->off;
}

static PP_ALWAYS_INLINE void cur_advance(pp_cursor *c, uint16_t n)
{
    /* Saturating, not wrapping. If n would step past len, land exactly on len
     * so cur_avail() reports 0 and the next cur_has() fails cleanly. */
    c->off = (uint16_t)(cur_has(c, n) ? c->off + n : c->len);
}

/* Record where parsing stopped and why, then stop. Every error path in this
 * file funnels through here so that "set err, keep what we have, return" cannot
 * be got subtly wrong in one branch out of twenty. */
static PP_ALWAYS_INLINE int fail(pp_meta *m, int err)
{
    m->err = (uint8_t)err;
    return err;
}

/* ---------------------------------------------------------------------------
 * L2 — Ethernet II, with 802.1Q / QinQ tag stacking.
 * ------------------------------------------------------------------------- */

/* Is this ethertype a VLAN tag of some kind?
 *
 * Three TPIDs, not one, and all three are real:
 *   0x8100  802.1Q      — the ordinary C-tag
 *   0x88A8  802.1ad     — the S-tag, provider bridging (QinQ proper)
 *   0x9100  pre-standard QinQ — predates 802.1ad, still emitted by older gear
 *
 * Recognising only 0x8100 is the common bug: a QinQ frame's outer tag is then
 * read as an ethertype, 0x88A8 doesn't match IPv4 or IPv6, and the packet is
 * silently classified as "not IP". It doesn't crash — it just quietly stops
 * matching your rules, which is worse. */
static PP_ALWAYS_INLINE int is_vlan_tpid(uint16_t t)
{
    return t == PP_ETHERTYPE_VLAN || t == PP_ETHERTYPE_QINQ ||
           t == PP_ETHERTYPE_QINQ9100;
}

static int parse_l2(pp_cursor *c, pp_meta *m)
{
    m->l2_off = c->off;

    if (PP_UNLIKELY(!cur_has(c, PP_ETH_HLEN)))
        return fail(m, PP_ERR_TRUNC_L2);

    /* Skip dst[6] and src[6]. We deliberately do not record the MAC addresses:
     * nothing in the rule language matches on them, and copying 12 bytes into
     * pp_meta would cost a fifth of the cache line to serve no reader. If MAC
     * matching is ever added, l2_off is already stored and the addresses are
     * two byte-loads away — that is the whole point of keeping offsets. */
    uint16_t ethertype = pp_rd_be16(cur_ptr(c) + 2 * PP_ETH_ALEN);
    cur_advance(c, PP_ETH_HLEN);

    m->layers |= PP_LAYER_L2;

    /* Walk the VLAN stack.
     *
     * BOUNDED ON PURPOSE (SPEC §7.8). The tag count is attacker-controlled: a
     * frame can carry an arbitrary run of 0x8100 tags, and `while (is_vlan())`
     * would happily walk all of them. That is a remote DoS — not by crashing,
     * but by making the parser slow while the NIC keeps delivering. Two tags is
     * everything real traffic has (C-tag inside S-tag); a third is an attack or
     * a bug, and either way we would rather count it than chase it. */
    unsigned depth = 0;
    while (is_vlan_tpid(ethertype)) {
        if (PP_UNLIKELY(depth >= PP_MAX_VLANS))
            return fail(m, PP_ERR_TOO_MANY_VLANS);

        if (PP_UNLIKELY(!cur_has(c, PP_VLAN_HLEN)))
            return fail(m, PP_ERR_TRUNC_VLAN);

        /* The tag is TCI[2] then the next ethertype[2]. Note the TPID we just
         * matched was the PREVIOUS ethertype field — the tag does not repeat
         * it. Getting this wrong shifts every subsequent offset by two. */
        uint16_t tci = pp_rd_be16(cur_ptr(c));
        uint16_t vid = tci & PP_VLAN_VID_MASK;

        if (depth == 0) m->vlan_outer = vid;
        else            m->vlan_inner = vid;

        ethertype = pp_rd_be16(cur_ptr(c) + 2);
        cur_advance(c, PP_VLAN_HLEN);

        m->layers |= PP_LAYER_VLAN;
        depth++;
    }

    /* Ethernet II vs 802.3.
     *
     * >= 1536 means the field is an ethertype. < 1536 means it is an 802.3
     * LENGTH and an LLC/SNAP header follows — a completely different parse.
     * Without this check, a 1400-byte 802.3 frame is read as "ethertype 0x0578"
     * and walked as if it were IP, producing garbage offsets from valid-looking
     * bytes. We decline to decode it rather than guess. */
    if (PP_UNLIKELY(ethertype < PP_ETH_TYPE_MIN)) {
        m->eth_type = ethertype;
        m->l3_off = c->off;
        return fail(m, PP_ERR_UNSUPPORTED_L3);
    }

    m->eth_type = ethertype;
    m->l3_off   = c->off;
    return PP_OK;
}

/* ---------------------------------------------------------------------------
 * L3 — IPv4
 * ------------------------------------------------------------------------- */
static int parse_ipv4(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!cur_has(c, PP_IP4_HLEN_MIN)))
        return fail(m, PP_ERR_TRUNC_L3);

    const uint8_t *h = cur_ptr(c);

    /* IHL is the header length in 32-bit words, and it is ATTACKER-CONTROLLED.
     * Two independent things must be checked and they fail differently:
     *
     *   1. IHL < 5 claims the header is shorter than the fixed part of the
     *      header itself. That is not a short header, it is a lie. If we
     *      believed it, the cursor would advance less than 20 bytes and every
     *      subsequent offset would be wrong — src/dst would be read out of the
     *      middle of the options field.
     *
     *   2. IHL * 4 > what we captured. Perfectly legal header, we just do not
     *      have all of it. Different cause, different error, same discipline:
     *      never advance past caplen. */
    uint8_t ihl = h[PP_IP4_OFF_VER_IHL] & 0x0Fu;
    if (PP_UNLIKELY(ihl < PP_IP4_IHL_MIN))
        return fail(m, PP_ERR_BAD_IHL);

    uint16_t hlen = (uint16_t)(ihl * 4u);
    if (PP_UNLIKELY(!cur_has(c, hlen)))
        return fail(m, PP_ERR_TRUNC_L3);

    m->ip_ver   = 4;
    m->ip_hlen  = (uint8_t)hlen;
    m->ttl      = h[PP_IP4_OFF_TTL];
    m->ip_proto = h[PP_IP4_OFF_PROTO];
    m->ip_src   = pp_rd_be32(h + PP_IP4_OFF_SRC);
    m->ip_dst   = pp_rd_be32(h + PP_IP4_OFF_DST);

    /* Total Length is a length field inside the packet, therefore a claim by
     * the sender, therefore not trusted (SPEC §7.9). We read it only to notice
     * when it contradicts reality; the cursor is never advanced by it. A packet
     * claiming totlen=60000 in a 64-byte capture is either a snaplen-truncated
     * capture (normal) or an attack (also normal). Neither may move a bound. */
    uint16_t totlen = pp_rd_be16(h + PP_IP4_OFF_TOTLEN);
    if (PP_UNLIKELY(totlen < hlen)) {
        /* totlen must cover at least its own header. This one is unambiguously
         * malformed rather than merely truncated. */
        m->l4_off = (uint16_t)(c->off + hlen);
        m->layers |= PP_LAYER_L3;
        return fail(m, PP_ERR_BAD_LEN);
    }

    /* Fragmentation.
     *
     * The 16-bit word is 3 bits of flags then a 13-bit offset measured in
     * EIGHT-BYTE units. Forgetting the mask makes every DF-marked packet look
     * like a fragment at offset 8192.
     *
     * The consequence that matters for classification: only the FIRST fragment
     * (offset == 0) carries the L4 header. Later fragments start mid-payload —
     * the bytes at l4_off are user data, and reading them as a TCP header
     * produces confident nonsense: ports invented out of somebody's HTTP body.
     * This is a real evasion technique, not a hypothetical. */
    uint16_t fragword = pp_rd_be16(h + PP_IP4_OFF_FRAG);
    uint16_t frag_off = fragword & PP_IP4_FRAG_MASK;
    m->frag_off = frag_off;

    int is_first_frag = (frag_off == 0);
    int more_frags    = (fragword & PP_IP4_FLAG_MF) != 0;

    cur_advance(c, hlen);
    m->l4_off  = c->off;
    m->layers |= PP_LAYER_L3;

    /* A non-first fragment carries no L4 header — but that is a FACT about the
     * packet, not an error, and L3 is fully valid and fully classifiable. The
     * caller learns there is no L4 from `layers`, not from a return code.
     * parse_l4() checks frag_off and declines; nothing to do here.
     *
     * (An earlier cut returned PP_ERR_UNSUPPORTED_L3 here, which conflated
     * "this packet is broken" with "this packet is fine and has no L4". The
     * fragment test could not then express what it meant — see CHALLENGES T3.) */
    (void)is_first_frag;
    (void)more_frags;

    return PP_OK;
}

/* ---------------------------------------------------------------------------
 * L3 — IPv6, and the extension header chain.
 * ------------------------------------------------------------------------- */

/* Length of one extension header, or 0 for "cannot determine — stop".
 *
 * The three different length rules (see proto.h) live here in one place so the
 * chain walk below reads as a loop rather than as a special-case museum. */
static PP_ALWAYS_INLINE uint16_t ip6_ext_len(uint8_t type, uint8_t hdr_ext_len)
{
    switch (type) {
    case PP_IPPROTO_FRAGMENT:
        /* FIXED 8. The second byte is RESERVED, not a length. Applying the
         * general (len+1)*8 rule happens to give 8 whenever that reserved byte
         * is 0 — which it usually is. So the bug hides until someone sets it,
         * and then the parser strides off into the payload. */
        return 8u;
    case PP_IPPROTO_AH:
        /* (len + 2) * 4 — units of FOUR bytes, and +2 rather than +1. AH is
         * the odd one out and is the extension header everyone gets wrong. */
        return (uint16_t)((hdr_ext_len + 2u) * 4u);
    case PP_IPPROTO_HOPOPTS:
    case PP_IPPROTO_ROUTING:
    case PP_IPPROTO_DSTOPTS:
    case PP_IPPROTO_MH:
        /* (len + 1) * 8 — units of 8 bytes, excluding the first 8. */
        return (uint16_t)((hdr_ext_len + 1u) * 8u);
    default:
        return 0u;
    }
}

static int parse_ipv6(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!cur_has(c, PP_IP6_HLEN)))
        return fail(m, PP_ERR_TRUNC_L3);

    const uint8_t *h = cur_ptr(c);

    m->ip_ver  = 6;
    m->ip_hlen = (uint8_t)PP_IP6_HLEN;   /* fixed — no IHL to lie about */
    m->ttl     = h[PP_IP6_OFF_HLIM];     /* "hop limit"; same field, new name */

    /* NOTE: the 128-bit addresses are deliberately NOT copied into pp_meta.
     * 32 bytes would eat half the cache line to serve a reader that looks at
     * them at most once. They live at l3_off+8 and l3_off+24 and are two byte
     * loads away — already in L1, because we are touching this header right
     * now. See the layout note in pkt.h. */

    uint8_t next = h[PP_IP6_OFF_NXT];
    cur_advance(c, PP_IP6_HLEN);
    m->layers |= PP_LAYER_L3;

    /* Walk the extension header chain.
     *
     * BOUNDED (SPEC §7.8). RFC 8200 places no limit on chain length, and every
     * hop is attacker-controlled, so `while (is_ext(next))` is a remote DoS:
     * a crafted packet with hundreds of 8-byte Destination Options headers
     * makes the parser walk all of them, forever, while the NIC delivers more.
     * This is a real, historically exploited bug class — not a hypothetical.
     *
     * Eight is generous: real traffic has zero or one. */
    unsigned hops = 0;
    while (pp_ip6_is_ext(next)) {
        if (PP_UNLIKELY(hops >= PP_MAX_IP6_EXTHDRS)) {
            m->ip_proto = next;
            m->l4_off   = c->off;
            return fail(m, PP_ERR_TOO_MANY_EXTHDRS);
        }

        if (PP_UNLIKELY(!cur_has(c, PP_IP6_EXT_HLEN_MIN))) {
            m->ip_proto = next;
            return fail(m, PP_ERR_TRUNC_L3);
        }

        const uint8_t *e = cur_ptr(c);
        uint8_t  this_type = next;
        uint8_t  nxt       = e[0];
        uint8_t  hel       = e[1];
        uint16_t elen      = ip6_ext_len(this_type, hel);

        /* Zero-length would mean "advance nothing", i.e. an infinite loop that
         * the hop counter would eventually stop but only after 8 wasted passes.
         * Refuse it outright: it is not a length any real header has. */
        if (PP_UNLIKELY(elen < PP_IP6_EXT_HLEN_MIN)) {
            m->ip_proto = this_type;
            return fail(m, PP_ERR_BAD_LEN);
        }

        if (PP_UNLIKELY(!cur_has(c, elen))) {
            m->ip_proto = this_type;
            return fail(m, PP_ERR_TRUNC_L3);
        }

        /* A fragment header whose offset is non-zero means this is NOT the
         * first fragment, so no L4 header follows — same rule as IPv4, just
         * carried in an extension header instead of the base header. The
         * offset is the top 13 bits of the word at e[2..3]. */
        if (this_type == PP_IPPROTO_FRAGMENT) {
            uint16_t fo = (uint16_t)(pp_rd_be16(e + 2) >> 3);
            m->frag_off = fo;
            /* Non-zero offset => not the first fragment => no L4 follows. Same
             * rule as IPv4, just carried in an extension header. Recorded in
             * frag_off; parse_l4() acts on it. Not an error. */
        }

        cur_advance(c, elen);
        next = nxt;
        hops++;
    }

    /* ESP means the rest is encrypted; NONE means nothing follows. Neither is
     * an error — there is genuinely nothing further to parse, and inventing
     * ports out of ciphertext would be worse than reporting none. ip_proto
     * records which, so the caller can tell why L4 is absent. */
    m->ip_proto = next;   /* the FINAL protocol, after the whole chain */
    m->l4_off   = c->off;
    return PP_OK;
}

static int parse_l3(pp_cursor *c, pp_meta *m)
{
    switch (m->eth_type) {
    case PP_ETHERTYPE_IPV4: {
        /* The ethertype says IPv4; the version nibble is a second, independent
         * claim. When two fields disagree, believe neither — a mismatch means
         * either a broken sender or someone probing for a parser that trusts
         * one over the other. */
        if (PP_UNLIKELY(!cur_has(c, 1)))
            return fail(m, PP_ERR_TRUNC_L3);
        if (PP_UNLIKELY((cur_ptr(c)[0] >> 4) != 4))
            return fail(m, PP_ERR_BAD_IP_VERSION);
        return parse_ipv4(c, m);
    }
    case PP_ETHERTYPE_IPV6: {
        if (PP_UNLIKELY(!cur_has(c, 1)))
            return fail(m, PP_ERR_TRUNC_L3);
        if (PP_UNLIKELY((cur_ptr(c)[0] >> 4) != 6))
            return fail(m, PP_ERR_BAD_IP_VERSION);
        return parse_ipv6(c, m);
    }
    default:
        /* ARP, MPLS, LLDP, ... Not an error: not everything is IP, and a
         * classifier that only writes IP rules does not care. */
        return fail(m, PP_ERR_UNSUPPORTED_L3);
    }
}

/* ---------------------------------------------------------------------------
 * L4 — TCP, UDP, ICMP.
 * ------------------------------------------------------------------------- */
static int parse_tcp(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!cur_has(c, PP_TCP_HLEN_MIN)))
        return fail(m, PP_ERR_TRUNC_L4);

    const uint8_t *h = cur_ptr(c);

    /* Ports first: they are at fixed offsets and we have already proven 20
     * bytes are present, so they are valid regardless of what the data offset
     * turns out to say. Recording them before validating the rest means a
     * packet with a corrupt data offset still yields a usable 5-tuple. */
    m->sport = pp_rd_be16(h + PP_TCP_OFF_SPORT);
    m->dport = pp_rd_be16(h + PP_TCP_OFF_DPORT);
    m->tcp_flags = h[PP_TCP_OFF_FLAGS];

    /* Data offset: the header length in 32-bit words, in the HIGH nibble.
     * Same two independent failures as IPv4's IHL:
     *   < 5   => claims a header shorter than the fixed header. A lie.
     *   > cap => legal header, we just don't have it all. Truncation. */
    uint8_t doff = (uint8_t)(h[PP_TCP_OFF_DOFF] >> 4);
    if (PP_UNLIKELY(doff < PP_TCP_DOFF_MIN))
        return fail(m, PP_ERR_BAD_TCP_DOFF);

    uint16_t hlen = (uint16_t)(doff * 4u);
    if (PP_UNLIKELY(!cur_has(c, hlen)))
        return fail(m, PP_ERR_TRUNC_L4);

    m->l4_hlen = (uint8_t)hlen;
    cur_advance(c, hlen);
    m->layers |= PP_LAYER_L4;
    return PP_OK;
}

static int parse_udp(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!cur_has(c, PP_UDP_HLEN)))
        return fail(m, PP_ERR_TRUNC_L4);

    const uint8_t *h = cur_ptr(c);
    m->sport   = pp_rd_be16(h + PP_UDP_OFF_SPORT);
    m->dport   = pp_rd_be16(h + PP_UDP_OFF_DPORT);
    m->l4_hlen = (uint8_t)PP_UDP_HLEN;

    /* The UDP length field is read for nothing here — deliberately. It is
     * another sender claim (SPEC §7.9) and cannot bound anything. Eight bytes,
     * fixed, no options: there is nothing for it to tell us that caplen has not
     * already told us more reliably. */

    cur_advance(c, PP_UDP_HLEN);
    m->layers |= PP_LAYER_L4;
    return PP_OK;
}

static int parse_icmp(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!cur_has(c, PP_ICMP_HLEN)))
        return fail(m, PP_ERR_TRUNC_L4);

    const uint8_t *h = cur_ptr(c);

    /* ICMP has no ports. Type and code go in the port fields — which is what
     * tcpdump and most rule languages do, and it keeps the 5-tuple uniform so
     * the classifier needs no ICMP special case. Only meaningful when ip_proto
     * is ICMP/ICMPv6; documented rather than clever. */
    m->sport   = h[PP_ICMP_OFF_TYPE];
    m->dport   = h[PP_ICMP_OFF_CODE];
    m->l4_hlen = (uint8_t)PP_ICMP_HLEN;

    cur_advance(c, PP_ICMP_HLEN);
    m->layers |= PP_LAYER_L4;
    return PP_OK;
}

static int parse_l4(pp_cursor *c, pp_meta *m)
{
    if (PP_UNLIKELY(!(m->layers & PP_LAYER_L3)))
        return PP_OK;   /* no L3 => no L4 to find. Not an error. */

    /* Not the first fragment => the L4 header lives in fragment #1 and the
     * bytes here are payload. Reading them as TCP would invent ports out of
     * somebody's HTTP body — a real evasion technique. Decline. */
    if (m->frag_off != 0)
        return PP_OK;

    int rc;
    switch (m->ip_proto) {
    case PP_IPPROTO_TCP:    rc = parse_tcp(c, m);  break;
    case PP_IPPROTO_UDP:    rc = parse_udp(c, m);  break;
    case PP_IPPROTO_ICMP:
    case PP_IPPROTO_ICMPV6: rc = parse_icmp(c, m); break;
    default:
        /* SCTP, GRE, ESP, OSPF... Not decoded, not an error. */
        return PP_OK;
    }
    if (rc != PP_OK) return rc;

    m->payload_off = c->off;
    m->payload_len = cur_avail(c);
    if (m->payload_len) m->layers |= PP_LAYER_PAYLOAD;
    return PP_OK;
}

/* ---------------------------------------------------------------------------
 * Entry point — including tunnel re-entry.
 * ------------------------------------------------------------------------- */

/* Does the packet we just parsed look like VXLAN carrying an inner frame? */
static PP_ALWAYS_INLINE int looks_like_vxlan(const pp_meta *m)
{
    return (m->layers & PP_LAYER_L4) &&
            m->ip_proto == PP_IPPROTO_UDP &&
            m->dport    == PP_UDP_PORT_VXLAN;
}

/* Clear the per-encapsulation fields before parsing the inner frame.
 *
 * NOT a memset: vni, tunnel_depth, outer_l3_off, caplen/wirelen and the layer
 * bits we want to keep all have to survive. This is the "reset exactly what the
 * next layer will re-derive, and nothing else" list, and getting it wrong
 * leaks outer values into the inner packet's metadata — e.g. an inner frame
 * with no VLAN inheriting the outer frame's VLAN ID, which then matches a rule
 * it should not. */
static void reset_for_inner(pp_meta *m)
{
    m->vlan_outer = PP_VLAN_NONE;
    m->vlan_inner = PP_VLAN_NONE;
    m->eth_type   = 0;
    m->ip_ver = m->ip_proto = m->ttl = m->tcp_flags = 0;
    m->ip_hlen = m->l4_hlen = 0;
    m->ip_src = m->ip_dst = 0;
    m->sport = m->dport = 0;
    m->frag_off = 0;
    m->payload_off = m->payload_len = 0;
    m->layers &= (uint8_t)~(PP_LAYER_VLAN | PP_LAYER_L3 | PP_LAYER_L4 |
                            PP_LAYER_PAYLOAD);
}

int pp_parse(const pp_rawpkt *pkt, pp_meta *m)
{
    pp_meta_init(m, pkt);

    if (PP_UNLIKELY(!pkt || !pkt->data))
        return fail(m, PP_ERR_TRUNC_L2);

    pp_cursor c;
    c.base = pkt->data;
    /* m->caplen, not pkt->caplen: pp_meta_init already clamped the 32-bit
     * capture length into 16 bits. Re-deriving it here from the raw 32-bit
     * field would reintroduce exactly the silent narrowing that clamp exists to
     * prevent. One source of truth for the bound. */
    c.len  = m->caplen;
    c.off  = 0;

    /* The tunnel loop.
     *
     * A VXLAN packet's payload is a complete Ethernet frame — another packet,
     * from the top. So parsing is naturally recursive, and recursion driven by
     * attacker-controlled data is a stack overflow waiting to happen: nest
     * VXLAN inside VXLAN inside VXLAN and a recursive parser blows the stack
     * from ONE frame.
     *
     * Written as a LOOP rather than as recursion, which makes the memory cost
     * constant and the depth cap trivially auditable — there is no stack to
     * overflow because there are no frames to push. The cap is then about CPU
     * (SPEC §7.8), not about memory, which is a much easier thing to reason
     * about. */
    unsigned depth = 0;
    for (;;) {
        int rc = parse_l2(&c, m);
        if (rc != PP_OK) return rc;

        rc = parse_l3(&c, m);
        if (rc != PP_OK) return rc;

        rc = parse_l4(&c, m);
        if (rc != PP_OK) return rc;

        if (!looks_like_vxlan(m))
            break;

        if (PP_UNLIKELY(depth >= PP_MAX_TUNNEL_DEPTH))
            return fail(m, PP_ERR_TOO_DEEP_TUNNEL);

        if (PP_UNLIKELY(!cur_has(&c, PP_VXLAN_HLEN)))
            return fail(m, PP_ERR_TRUNC_TUNNEL);

        const uint8_t *vx = cur_ptr(&c);

        /* The 'I' flag says the VNI field is valid. Without it this is UDP/4789
         * that is not really VXLAN — or is malformed VXLAN. Either way, stop
         * here and report it as ordinary UDP rather than manufacture a tenant
         * ID out of reserved bytes. */
        if (!(vx[PP_VXLAN_OFF_FLAGS] & PP_VXLAN_FLAG_VNI))
            break;

        /* 24-bit VNI in the top 3 bytes of the second word. */
        m->vni = pp_rd_be32(vx + PP_VXLAN_OFF_VNI) >> 8;

        cur_advance(&c, PP_VXLAN_HLEN);

        /* Keep the underlay's L3 before the inner parse overwrites l3_off. */
        m->outer_l3_off  = m->l3_off;
        m->layers       |= PP_LAYER_TUNNEL;
        m->tunnel_depth  = (uint8_t)(++depth);

        reset_for_inner(m);
        /* ...and around again, now parsing the inner Ethernet frame. */
    }

    return PP_OK;
}
