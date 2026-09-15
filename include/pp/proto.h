/* proto.h — wire-format constants and safe field readers.
 *
 * Everything here describes bytes as they appear on the wire. Nothing here
 * allocates, branches on configuration, or knows about the pipeline.
 */
#ifndef PP_PROTO_H
#define PP_PROTO_H

#include "pp/pp.h"

PP_BEGIN_DECLS

/* ---------------------------------------------------------------------------
 * Reading multi-byte fields out of a packet.
 *
 * This is the single most important idiom in the parser, and the place where
 * the obvious code is wrong (SPEC §7.2). The tempting version is:
 *
 *     const struct ethhdr *eth = (const struct ethhdr *)(pkt + off);
 *     uint16_t type = ntohs(eth->h_proto);
 *
 * It has three defects, and everybody writes it anyway:
 *
 *   1. ALIGNMENT. `pkt + off` is wherever the previous header ended — offset 14
 *      after Ethernet, which is even but not 4-aligned. Casting to a struct
 *      whose members want 2- or 4-byte alignment produces a misaligned pointer.
 *      x86 and arm64 tolerate misaligned loads; other targets fault, and UBSan
 *      flags it on all of them.
 *
 *   2. STRICT ALIASING. Reading `unsigned char` bytes through an unrelated
 *      struct type is undefined behavior in C. The compiler is entitled to
 *      assume a `struct ethhdr *` and a `uint8_t *` never point at the same
 *      object, and at -O2 it will reorder or cache loads on that assumption.
 *      This is the "worked until we upgraded the compiler" class of bug.
 *
 *   3. ENDIANNESS. Requires remembering ntohs() at every single field. Forget
 *      one and you get a value that is wrong only on little-endian machines —
 *      which is every machine you'll test on, so it's wrong everywhere, or
 *      subtly right for the wrong reason.
 *
 * The fix used throughout is byte loads composed by shifting:
 *
 *     static uint16_t rd_be16(const uint8_t *p) { return p[0] << 8 | p[1]; }
 *
 * This kills all three at once and is not a compromise:
 *   - `uint8_t` (a character type) may alias ANY object. No aliasing UB.
 *   - Byte loads have no alignment requirement. No misalignment.
 *   - It spells out big-endian arithmetically, so it is correct on a big-endian
 *     machine and a little-endian one with no ntohs() and no #ifdef. The
 *     host's byte order never enters the picture.
 *   - It costs NOTHING. Both gcc and clang recognize this exact idiom and emit
 *     a single unaligned load plus a byte-reverse (`rev16` on arm64, `movbe` or
 *     `mov`+`rol` on x86). Verified in tools/disasm_check.sh — the point of that
 *     script is that this claim is checked rather than believed.
 * ------------------------------------------------------------------------- */

static PP_ALWAYS_INLINE uint16_t pp_rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static PP_ALWAYS_INLINE uint32_t pp_rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Little-endian twins.
 *
 * Wire protocols are big-endian, so the parser only ever needs the BE readers
 * above. FILE formats are a different matter: a pcap file is written in the
 * byte order of whatever machine captured it, and announces which via its magic
 * number. So a reader needs both, chosen at runtime.
 *
 * This is where the byte-load idiom pays a second dividend. The conventional
 * approach is #ifdefs plus conditional bswap calls, and it is easy to get
 * subtly wrong. Here "little-endian" and "big-endian" are simply two functions
 * that differ in the order of their shifts; picking one at runtime is a branch
 * or a function pointer, not a preprocessor problem, and each is obviously
 * correct by inspection on any host. */
static PP_ALWAYS_INLINE uint16_t pp_rd_le16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1] << 8) | (uint16_t)p[0]);
}

static PP_ALWAYS_INLINE uint32_t pp_rd_le32(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8)  |  (uint32_t)p[0];
}

/* ---------------------------------------------------------------------------
 * Layer 2 — Ethernet II (IEEE 802.3)
 * ------------------------------------------------------------------------- */
#define PP_ETH_HLEN     14u   /* dst[6] + src[6] + ethertype[2] */
#define PP_ETH_ALEN      6u

#define PP_ETHERTYPE_IPV4   0x0800u
#define PP_ETHERTYPE_ARP    0x0806u
#define PP_ETHERTYPE_IPV6   0x86DDu
#define PP_ETHERTYPE_VLAN   0x8100u  /* 802.1Q — one C-tag                     */
#define PP_ETHERTYPE_QINQ   0x88A8u  /* 802.1ad — S-tag (provider bridging)    */
#define PP_ETHERTYPE_QINQ9100 0x9100u/* pre-standard QinQ; still in the wild   */

/* An Ethernet II frame is identified by its type field being >= 1536. Below
 * that, the same two bytes are an 802.3 LENGTH, and what follows is an LLC/SNAP
 * header rather than an ethertype. Conflating the two is a classic parser bug:
 * a 1400-byte 802.3 frame would be read as "ethertype 0x0578" and then walked
 * as though it were IP. Real traffic is essentially all Ethernet II, but
 * "essentially all" is not "all", and the check costs one compare. */
#define PP_ETH_TYPE_MIN 1536u

/* ---------------------------------------------------------------------------
 * 802.1Q VLAN tag
 *
 *   +--------+--------+--------+--------+
 *   |      TPID       |       TCI       |
 *   +--------+--------+--------+--------+
 *    16 bits            PCP(3) DEI(1) VID(12)
 *
 * The tag is 4 bytes and REPLACES nothing: it is inserted before the ethertype,
 * so a tagged frame's real ethertype sits 4 bytes further in. Stacked tags
 * (QinQ) repeat this.
 * ------------------------------------------------------------------------- */
#define PP_VLAN_HLEN     4u
#define PP_VLAN_VID_MASK 0x0FFFu   /* low 12 bits of the TCI */
#define PP_VLAN_PCP_SHIFT 13u
#define PP_VLAN_DEI_MASK 0x1000u

/* ---------------------------------------------------------------------------
 * Layer 4 / next-header protocol numbers (IANA).
 *
 * In IPv6 this single number space is used for BOTH real L4 protocols and
 * extension headers, which is exactly why the chain walk in parse.c has to know
 * which is which. See PP_IP6_EXT below.
 * ------------------------------------------------------------------------- */
#define PP_IPPROTO_HOPOPTS  0u   /* IPv6 hop-by-hop options    (ext hdr)    */
#define PP_IPPROTO_ICMP     1u
#define PP_IPPROTO_TCP      6u
#define PP_IPPROTO_UDP     17u
#define PP_IPPROTO_IPV6    41u   /* IPv6-in-IP encapsulation                */
#define PP_IPPROTO_ROUTING 43u   /* IPv6 routing header       (ext hdr)    */
#define PP_IPPROTO_FRAGMENT 44u  /* IPv6 fragment header      (ext hdr)    */
#define PP_IPPROTO_GRE     47u
#define PP_IPPROTO_ESP     50u   /* encrypted — chain ends here            */
#define PP_IPPROTO_AH      51u   /* auth header  (ext hdr, ODD LENGTH RULE)*/
#define PP_IPPROTO_ICMPV6  58u
#define PP_IPPROTO_NONE    59u   /* IPv6 "no next header"                  */
#define PP_IPPROTO_DSTOPTS 60u   /* IPv6 destination options  (ext hdr)    */
#define PP_IPPROTO_MH     135u   /* IPv6 mobility header      (ext hdr)    */
#define PP_IPPROTO_SCTP   132u

/* ---------------------------------------------------------------------------
 * Layer 3 — IPv4 (RFC 791)
 *
 *    0                   1                   2                   3
 *   +-------+-------+---------------+-------------------------------+
 *   |Version|  IHL  |    DSCP/ECN   |         Total Length          |
 *   +-------+-------+---------------+-----+-------------------------+
 *   |        Identification         |Flags|    Fragment Offset      |
 *   +---------------+---------------+-----+-------------------------+
 *   |      TTL      |   Protocol    |        Header Checksum        |
 *   +---------------+---------------+-------------------------------+
 *   |                       Source Address                          |
 *   +---------------------------------------------------------------+
 *   |                    Destination Address                        |
 *   +---------------------------------------------------------------+
 *   |                  Options (0-40 bytes)         |    Padding    |
 *   +---------------------------------------------------------------+
 * ------------------------------------------------------------------------- */
#define PP_IP4_HLEN_MIN   20u   /* IHL == 5 */
#define PP_IP4_HLEN_MAX   60u   /* IHL == 15 */
#define PP_IP4_IHL_MIN     5u   /* an IHL below this describes a header shorter
                                 * than the fixed part of the header itself —
                                 * i.e. a lie. */
#define PP_IP4_OFF_VER_IHL  0u
#define PP_IP4_OFF_TOTLEN   2u
#define PP_IP4_OFF_FRAG     6u
#define PP_IP4_OFF_TTL      8u
#define PP_IP4_OFF_PROTO    9u
#define PP_IP4_OFF_SRC     12u
#define PP_IP4_OFF_DST     16u

/* The flags/fragment word: 3 bits of flags, 13 bits of offset. */
#define PP_IP4_FLAG_MF     0x2000u  /* More Fragments                       */
#define PP_IP4_FLAG_DF     0x4000u  /* Don't Fragment                       */
#define PP_IP4_FRAG_MASK   0x1FFFu  /* offset, in EIGHT-BYTE units          */

/* ---------------------------------------------------------------------------
 * Layer 3 — IPv6 (RFC 8200)
 *
 *   +-------+---------------+---------------------------------------+
 *   |Version| Traffic Class |             Flow Label                |
 *   +-------+---------------+-------+---------------+---------------+
 *   |        Payload Length         |  Next Header  |   Hop Limit   |
 *   +-------------------------------+---------------+---------------+
 *   |                     Source Address (128 bits)                 |
 *   +---------------------------------------------------------------+
 *   |                  Destination Address (128 bits)               |
 *   +---------------------------------------------------------------+
 *
 * The header is a FIXED 40 bytes — no IHL. Options moved out into a linked list
 * of extension headers, which is where all the difficulty went.
 * ------------------------------------------------------------------------- */
#define PP_IP6_HLEN        40u
#define PP_IP6_OFF_PLEN     4u
#define PP_IP6_OFF_NXT      6u
#define PP_IP6_OFF_HLIM     7u
#define PP_IP6_OFF_SRC      8u
#define PP_IP6_OFF_DST     24u
#define PP_IP6_ADDR_LEN    16u

/* ---------------------------------------------------------------------------
 * IPv6 extension headers — the trap.
 *
 * Every extension header starts the same way:
 *
 *     +---------------+---------------+- - - - - - - - - - - - - -+
 *     |  Next Header  |  Hdr Ext Len  |    type-specific data     |
 *     +---------------+---------------+- - - - - - - - - - - - - -+
 *
 * ...and then the length rule is NOT uniform, which is the bug factory:
 *
 *   Hop-by-Hop(0), Routing(43), DestOpts(60), Mobility(135):
 *        length = (hdr_ext_len + 1) * 8      -- units of 8 bytes, EXCLUDING
 *                                               the first 8. So 0 means 8.
 *   Fragment(44):
 *        length = 8, FIXED. The hdr_ext_len byte is RESERVED and is usually 0 —
 *        applying the general rule gives (0+1)*8 = 8 and accidentally works,
 *        which is worse than failing, because it hides the bug until someone
 *        sends a fragment header with junk in the reserved byte.
 *   Auth Header(51):
 *        length = (hdr_ext_len + 2) * 4      -- units of FOUR bytes, and +2.
 *        AH is the one everyone gets wrong. It is not a typo.
 *   ESP(50):
 *        NOT parseable — everything after it is encrypted. The chain ends.
 *   NONE(59):
 *        explicit "nothing follows".
 *
 * A parser that applies (len+1)*8 uniformly walks AH with the wrong stride and
 * lands mid-header, then reads whatever byte is there as the next header type.
 * It does not crash; it produces confident nonsense.
 * ------------------------------------------------------------------------- */
#define PP_IP6_EXT_HLEN_MIN 8u

/* Is `proto` an IPv6 extension header (as opposed to a real L4 payload)? */
static PP_ALWAYS_INLINE int pp_ip6_is_ext(uint8_t proto)
{
    return proto == PP_IPPROTO_HOPOPTS  || proto == PP_IPPROTO_ROUTING  ||
           proto == PP_IPPROTO_FRAGMENT || proto == PP_IPPROTO_DSTOPTS  ||
           proto == PP_IPPROTO_AH       || proto == PP_IPPROTO_MH;
}

/* ---------------------------------------------------------------------------
 * Layer 4 — TCP (RFC 9293)
 *
 *   +-------------------------------+-------------------------------+
 *   |          Source Port          |       Destination Port        |
 *   +-------------------------------+-------------------------------+
 *   |                        Sequence Number                        |
 *   +---------------------------------------------------------------+
 *   |                     Acknowledgment Number                     |
 *   +-------+-------+---------------+-------------------------------+
 *   | DOff  |  Rsvd |     Flags     |            Window             |
 *   +-------+-------+---------------+-------------------------------+
 *   |           Checksum            |         Urgent Pointer        |
 *   +-------------------------------+-------------------------------+
 *   |                    Options (0-40 bytes)                       |
 *   +---------------------------------------------------------------+
 * ------------------------------------------------------------------------- */
#define PP_TCP_HLEN_MIN   20u
#define PP_TCP_HLEN_MAX   60u
#define PP_TCP_DOFF_MIN    5u   /* below this the header is shorter than itself */
#define PP_TCP_OFF_SPORT   0u
#define PP_TCP_OFF_DPORT   2u
#define PP_TCP_OFF_DOFF   12u   /* high nibble = data offset, in 32-bit words   */
#define PP_TCP_OFF_FLAGS  13u

#define PP_TCP_FIN 0x01u
#define PP_TCP_SYN 0x02u
#define PP_TCP_RST 0x04u
#define PP_TCP_PSH 0x08u
#define PP_TCP_ACK 0x10u
#define PP_TCP_URG 0x20u
#define PP_TCP_ECE 0x40u
#define PP_TCP_CWR 0x80u

/* ---------------------------------------------------------------------------
 * Layer 4 — UDP (RFC 768). Eight bytes, no options, nothing to get wrong.
 * ------------------------------------------------------------------------- */
#define PP_UDP_HLEN      8u
#define PP_UDP_OFF_SPORT 0u
#define PP_UDP_OFF_DPORT 2u
#define PP_UDP_OFF_LEN   4u

/* ---------------------------------------------------------------------------
 * Layer 4 — ICMP / ICMPv6. Four bytes of common header.
 *
 * ICMP has no ports. We record type/code in the port fields, which is what
 * tcpdump and most rule languages do — it keeps the 5-tuple uniform so the
 * classifier does not need an ICMP special case. Documented rather than
 * clever: `sport = type, dport = code` only when ip_proto is ICMP/ICMPv6.
 * ------------------------------------------------------------------------- */
#define PP_ICMP_HLEN     4u
#define PP_ICMP_OFF_TYPE 0u
#define PP_ICMP_OFF_CODE 1u

/* ---------------------------------------------------------------------------
 * VXLAN (RFC 7348) — a tunnel, and therefore a recursion hazard.
 *
 *   UDP dport 4789, then:
 *   +-------+-----------------------+-------------------------------+
 *   | Flags |       Reserved        |                               |
 *   +-------+-----------------------+---------------+---------------+
 *   |                VNI (24 bits)                  |   Reserved    |
 *   +-----------------------------------------------+---------------+
 *   ...followed by a complete INNER ETHERNET FRAME.
 *
 * That last line is the whole problem: the payload of a VXLAN packet is another
 * packet, from the top. So the parser must re-enter itself — and re-entering on
 * attacker-controlled data without a depth cap is how you get a stack overflow
 * from a single frame (SPEC §7.8, PP_MAX_TUNNEL_DEPTH).
 * ------------------------------------------------------------------------- */
#define PP_UDP_PORT_VXLAN 4789u
#define PP_VXLAN_HLEN        8u
#define PP_VXLAN_FLAG_VNI 0x08u  /* the 'I' bit: VNI field is valid */
#define PP_VXLAN_OFF_FLAGS   0u
#define PP_VXLAN_OFF_VNI     4u  /* 3 bytes of VNI, then 1 reserved */

PP_END_DECLS

#endif /* PP_PROTO_H */
