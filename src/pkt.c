/* pkt.c — metadata lifecycle and error naming. */
#include "pp/pkt.h"

#include <string.h>

void pp_meta_init(pp_meta *m, const pp_rawpkt *pkt)
{
    /* One 64-byte store-set over a cache-line-aligned struct. The compiler
     * lowers this to a couple of vector stores; it is not worth hand-rolling. */
    memset(m, 0, sizeof *m);

    /* ...but zero is the WRONG default for the VLAN fields, so fix them up.
     *
     * VLAN ID 0 is a legal, meaningful value: an 802.1Q tag with VID 0 is a
     * "priority-tagged" frame, carrying a PCP class with no VLAN membership.
     * Real switches emit these. So if 0 meant "no VLAN", a priority-tagged
     * frame would be indistinguishable from an untagged one, and a rule
     * matching `vlan 0` would silently match all untagged traffic.
     *
     * The general lesson, which recurs across this parser: a sentinel must be a
     * value the wire format cannot produce. 0 is almost never that value. */
    m->vlan_outer = PP_VLAN_NONE;
    m->vlan_inner = PP_VLAN_NONE;

    if (pkt) {
        /* caplen is the ONLY bound the parser is allowed to trust. Every header
         * read checks against this and never against a length field found
         * inside the packet, because those are attacker-controlled (SPEC §7.9).
         *
         * The clamp matters: pp_rawpkt carries 32-bit lengths (that is what
         * libpcap and the kernel hand us) while pp_meta stores 16-bit ones to
         * fit the cache line. A jumbo or corrupt caplen above 65535 would
         * truncate silently on assignment and produce a bound LARGER than
         * reality is not the risk — a wrapped, far smaller bound is, and either
         * way a silent narrowing is how buffer overruns are born. Clamping
         * makes the narrowing explicit and safe: we under-read at worst. */
        m->caplen  = pkt->caplen  > 0xFFFFu ? 0xFFFFu : (uint16_t)pkt->caplen;
        m->wirelen = pkt->wirelen > 0xFFFFu ? 0xFFFFu : (uint16_t)pkt->wirelen;
    }
}

static const char *const err_names[PP_ERR__COUNT] = {
    [PP_OK]                   = "ok",
    [PP_ERR_TRUNC_L2]         = "truncated L2 header",
    [PP_ERR_TRUNC_VLAN]       = "truncated VLAN tag",
    [PP_ERR_TRUNC_L3]         = "truncated L3 header",
    [PP_ERR_TRUNC_L4]         = "truncated L4 header",
    [PP_ERR_TRUNC_TUNNEL]     = "truncated tunnel header",
    [PP_ERR_BAD_IHL]          = "bad IPv4 IHL",
    [PP_ERR_BAD_IP_VERSION]   = "bad IP version",
    [PP_ERR_BAD_TCP_DOFF]     = "bad TCP data offset",
    [PP_ERR_BAD_LEN]          = "length field contradicts captured bytes",
    [PP_ERR_TOO_MANY_VLANS]   = "VLAN stack too deep",
    [PP_ERR_TOO_MANY_EXTHDRS] = "IPv6 extension header chain too long",
    [PP_ERR_TOO_DEEP_TUNNEL]  = "tunnel nesting too deep",
    [PP_ERR_UNSUPPORTED_L3]   = "unsupported L3 protocol",
};

const char *pp_err_str(int err)
{
    if (err < 0 || err >= PP_ERR__COUNT) return "invalid error code";
    const char *s = err_names[err];
    return s ? s : "unnamed error";
}
