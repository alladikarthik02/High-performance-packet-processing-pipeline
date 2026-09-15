// test_l3 — IPv4, IPv6, extension header chains, fragments, and liars.
//
// The theme: every length in an IP header is a CLAIM MADE BY THE SENDER. This
// suite is mostly about what happens when those claims are false.
#include "test.h"
#include "pktbuild.h"
#include "pp/parse.h"

using namespace pktbuild;

static constexpr uint32_t SRC = 0xC0A80101;  // 192.168.1.1
static constexpr uint32_t DST = 0x08080808;  // 8.8.8.8

// ---------------------------------------------------------------------------
// IPv4 — well-formed
// ---------------------------------------------------------------------------

static void suite_ipv4_basic() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST).fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK(m.layers & PP_LAYER_L3);
    CHECK_EQ(m.ip_ver, uint8_t(4));
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(m.ip_hlen, uint8_t(20));
    CHECK_EQ(m.ttl, uint8_t(64));
    CHECK_EQ(m.ip_src, SRC);
    CHECK_EQ(m.ip_dst, DST);
    CHECK_EQ(m.l3_off, uint16_t(14));
    CHECK_EQ(m.l4_off, uint16_t(34));   // 14 + 20
}

static void suite_ipv4_with_options() {
    // IHL=8 => a 32-byte header (20 fixed + 12 of options). L4 must start 12
    // bytes later than the no-options case. A parser that hardcodes 20 reads
    // the TCP header out of the middle of the options.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, SRC, DST, /*ihl=*/8).fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK_EQ(m.ip_hlen, uint8_t(32));
    CHECK_EQ(m.l4_off, uint16_t(14 + 32));
    CHECK_EQ(m.ip_src, SRC);            // src/dst are still at fixed offsets
}

static void suite_ipv4_max_ihl() {
    // IHL=15 => 60 bytes, the maximum a 4-bit field can express.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST, /*ihl=*/15).fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.ip_hlen, uint8_t(60));
    CHECK_EQ(m.l4_off, uint16_t(74));
}

static void suite_ipv4_over_vlan() {
    // Layers compose: the VLAN tag shifts L3, which shifts L4.
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(42, PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST).fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.vlan_outer, uint16_t(42));
    CHECK_EQ(m.l3_off, uint16_t(18));
    CHECK_EQ(m.l4_off, uint16_t(38));
    CHECK_EQ(m.ip_src, SRC);
}

// ---------------------------------------------------------------------------
// IPv4 — lies and damage
// ---------------------------------------------------------------------------

static void suite_ipv4_ihl_too_small() {
    // IHL < 5 claims a header shorter than the fixed header itself. Believing
    // it would advance the cursor less than 20 bytes and make every subsequent
    // offset wrong — src/dst read out of the middle of the header.
    for (uint8_t ihl = 0; ihl < 5; ++ihl) {
        Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST, ihl).fill(20);
        auto v = p.view();
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK_EQ(rc, int(PP_ERR_BAD_IHL));
        CHECK(m.layers & PP_LAYER_L2);      // L2 was fine
        CHECK(!(m.layers & PP_LAYER_L3));   // L3 was not decoded
    }
}

static void suite_ipv4_ihl_beyond_capture() {
    // IHL=15 (60 bytes) but only ~24 bytes of IP captured. The header is legal;
    // we simply do not have it. Distinct from BAD_IHL: different cause,
    // different error, same rule — never advance past caplen.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST, /*ihl=*/15).fill(20);
    auto v = p.view(/*caplen=*/14 + 24);
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_TRUNC_L3));
}

static void suite_ipv4_truncated_everywhere() {
    // Sweep every truncation point through the IP header.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST).fill(20);
    for (uint32_t n = 14; n < 14 + 20; ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK_EQ(rc, int(PP_ERR_TRUNC_L3));
        CHECK(m.l4_off <= m.caplen);   // never points past what we hold
    }
}

static void suite_ipv4_totlen_lies() {
    // Total Length is a sender claim (SPEC §7.9). A totlen smaller than the
    // header it describes is unambiguously malformed.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, /*ihl=*/5, /*totlen=*/10)
            .fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_BAD_LEN));
}

static void suite_ipv4_totlen_absurdly_large_is_harmless() {
    // totlen=60000 in a 54-byte capture. This is NOT an error — it's what a
    // snaplen-truncated capture looks like every day. The parser must ignore
    // the field entirely for bounds purposes and keep working from caplen.
    // A parser that trusted totlen here would read 60000 bytes off the end.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, /*ihl=*/5, /*totlen=*/60000)
            .fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_NE(rc, int(PP_ERR_BAD_LEN));   // not malformed — just truncated capture
    CHECK(m.layers & PP_LAYER_L3);
    CHECK_EQ(m.ip_src, SRC);             // and it parsed correctly anyway
}

static void suite_ipv4_version_mismatch() {
    // Ethertype says IPv4; the version nibble says 6. Two fields disagree —
    // believe neither. This is what a parser-differential probe looks like.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 5, 0xFFFF, 0, 64, /*version=*/6)
            .fill(20);
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_BAD_IP_VERSION));
}

// ---------------------------------------------------------------------------
// IPv4 fragmentation
// ---------------------------------------------------------------------------

static void suite_ipv4_first_fragment_has_l4() {
    // MF set, offset 0 => the first fragment. It DOES carry the L4 header.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 5, 0xFFFF, /*fragword=*/PP_IP4_FLAG_MF)
            .fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(m.frag_off, uint16_t(0));
    CHECK(m.layers & PP_LAYER_L3);
    CHECK_NE(rc, int(PP_ERR_BAD_LEN));
}

static void suite_ipv4_later_fragment_has_no_l4() {
    // offset != 0 => a later fragment. The bytes at l4_off are PAYLOAD, not a
    // TCP header. Reading them as ports invents port numbers out of somebody's
    // HTTP body — a real evasion technique, not a hypothetical.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 5, 0xFFFF, /*fragword=*/185)  // offset 185*8
            .fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(m.frag_off, uint16_t(185));
    // Not an error: the packet is FINE. It simply has no L4 header, because the
    // L4 header was in fragment #1. That distinction is the parse contract —
    // the return value answers "is it malformed", layers answers "how deep".
    CHECK_EQ(rc, int(PP_OK));
    CHECK(m.layers & PP_LAYER_L3);          // L3 is valid and classifiable...
    CHECK(!(m.layers & PP_LAYER_L4));       // ...and there is no L4 to find
    CHECK_EQ(m.sport, uint16_t(0));         // and we did NOT invent ports
    CHECK_EQ(m.dport, uint16_t(0));
}

static void suite_ipv4_df_is_not_a_fragment() {
    // The classic mask bug. DF (0x4000) lives in the flags bits; without the
    // 0x1FFF mask, frag_off reads as 8192 and EVERY DF packet — which is most
    // of the internet — looks like a mid-stream fragment and loses its L4.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 5, 0xFFFF, /*fragword=*/PP_IP4_FLAG_DF)
            .tcp(1234, 80);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(m.frag_off, uint16_t(0));      // NOT 8192
    CHECK_EQ(rc, int(PP_OK));
    CHECK(m.layers & PP_LAYER_L4);          // L4 really is reachable...
    CHECK_EQ(m.dport, uint16_t(80));        // ...and correctly parsed
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

static void suite_ipv6_basic() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_TCP, 20).fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK(m.layers & PP_LAYER_L3);
    CHECK_EQ(m.ip_ver, uint8_t(6));
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(m.ip_hlen, uint8_t(40));       // fixed — no IHL to lie about
    CHECK_EQ(m.l3_off, uint16_t(14));
    CHECK_EQ(m.l4_off, uint16_t(54));       // 14 + 40
    CHECK_EQ(m.ttl, uint8_t(64));           // hop limit
}

static void suite_ipv6_truncated() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_TCP, 20).fill(20);
    for (uint32_t n = 14; n < 14 + 40; ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_TRUNC_L3));
    }
}

static void suite_ipv6_single_ext_header() {
    // Hop-by-hop options, hdr_ext_len=0 => 8 bytes total. ip_proto must be the
    // FINAL protocol (TCP), not the first next-header value (0 = hop-by-hop).
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_HOPOPTS, 28)
            .ip6_ext(PP_IPPROTO_TCP, 0)
            .fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));   // walked THROUGH the chain
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 8));
}

static void suite_ipv6_ext_len_rule() {
    // hdr_ext_len is in 8-byte units EXCLUDING the first 8: len=2 => 24 bytes.
    // Off-by-one here lands the cursor mid-header and reads a data byte as the
    // next-header type.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_DSTOPTS, 44)
            .ip6_ext(PP_IPPROTO_UDP, /*hdr_ext_len=*/2)   // (2+1)*8 = 24
            .fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_UDP));
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 24));
}

static void suite_ipv6_chain_of_several() {
    // Hop-by-hop -> Routing -> DestOpts -> TCP. Real traffic rarely does this;
    // the parser still must.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_HOPOPTS, 0)
            .ip6_ext(PP_IPPROTO_ROUTING, 0)   // 8
            .ip6_ext(PP_IPPROTO_DSTOPTS, 1)   // 16
            .ip6_ext(PP_IPPROTO_TCP, 0)       // 8
            .fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 8 + 16 + 8));
}

static void suite_ipv6_ah_has_its_own_length_rule() {
    // THE one everyone gets wrong. AH is (len+2)*4, NOT (len+1)*8.
    // With hdr_ext_len=1: correct = (1+2)*4 = 12. The general rule would give
    // (1+1)*8 = 16 — four bytes too far, landing inside the TCP header and
    // reading a byte of it as the next protocol. It would not crash; it would
    // produce confident nonsense.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_AH, 0)
            .ip6_ah(PP_IPPROTO_TCP, /*hdr_ext_len=*/1)    // (1+2)*4 = 12 bytes
            .fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 12));   // 12, not 16
}

static void suite_ipv6_fragment_header_is_fixed_8() {
    // The Fragment header is FIXED at 8 bytes; its second byte is RESERVED, not
    // a length. Put junk in that byte: a parser applying the general
    // (len+1)*8 rule would stride (200+1)*8 = 1608 bytes into oblivion.
    // Ours must ignore it entirely and advance exactly 8.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_FRAGMENT, 0)
            .ip6_frag(PP_IPPROTO_TCP, /*frag_off=*/0, /*more=*/true,
                      /*reserved_byte=*/200)      // <-- the trap
            .fill(20);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);

    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 8));    // exactly 8, junk ignored
}

static void suite_ipv6_later_fragment_has_no_l4() {
    // Same rule as IPv4, carried in an extension header instead.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_FRAGMENT, 0)
            .ip6_frag(PP_IPPROTO_TCP, /*frag_off=*/100)
            .fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(m.frag_off, uint16_t(100));
    CHECK_EQ(rc, int(PP_OK));               // valid packet, just no L4 in it
    CHECK(!(m.layers & PP_LAYER_L4));
    CHECK_EQ(m.sport, uint16_t(0));
}

static void suite_ipv6_esp_ends_the_chain() {
    // Everything after ESP is encrypted. Reporting "no L4" is correct;
    // inventing ports from ciphertext would not be.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_ESP, 20).fill(20);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_OK));                       // not malformed...
    CHECK(m.layers & PP_LAYER_L3);                  // ...L3 was perfectly good
    CHECK(!(m.layers & PP_LAYER_L4));               // ...and L4 is ciphertext
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_ESP));  // ip_proto says WHY
}

// ---------------------------------------------------------------------------
// IPv6 — the DoS
// ---------------------------------------------------------------------------

static void suite_ipv6_exthdr_bomb_is_bounded() {
    // SPEC §7.8, and a historically exploited bug class. RFC 8200 sets no limit
    // on chain length and every hop is attacker-controlled. `while (is_ext())`
    // walks all 200 of these while the NIC delivers more — a remote DoS that
    // never crashes, it just stops keeping up.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_DSTOPTS, 0);
    for (int i = 0; i < 200; ++i) p.ip6_ext(PP_IPPROTO_DSTOPTS, 0);
    p.ip6_ext(PP_IPPROTO_TCP, 0).fill(20);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(rc, int(PP_ERR_TOO_MANY_EXTHDRS));
    CHECK(m.layers & PP_LAYER_L3);
}

static void suite_ipv6_exactly_max_exthdrs_is_ok() {
    // The cap is 8 and exactly 8 must PASS. A bound that's too tight silently
    // drops legitimate traffic — also a bug, and a more embarrassing one.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_DSTOPTS, 0);
    for (int i = 0; i < PP_MAX_IP6_EXTHDRS - 1; ++i) p.ip6_ext(PP_IPPROTO_DSTOPTS, 0);
    p.ip6_ext(PP_IPPROTO_TCP, 0).fill(20);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_NE(rc, int(PP_ERR_TOO_MANY_EXTHDRS));
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_TCP));
}

static void suite_ipv6_truncated_ext_chain() {
    // Chain says "more headers follow" and the capture ends. Must not read past.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_DSTOPTS, 0)
            .ip6_ext(PP_IPPROTO_DSTOPTS, 4)     // claims 40 bytes
            .fill(4);                           // ...but only 4 are here
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_TRUNC_L3));
}

static void suite_every_prefix_ipv6_chain() {
    // The systematic one. Every prefix of a well-formed IPv6+ext+TCP packet.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6)
            .ipv6(PP_IPPROTO_HOPOPTS, 0)
            .ip6_ext(PP_IPPROTO_ROUTING, 1)
            .ip6_ext(PP_IPPROTO_TCP, 0)
            .fill(30, 0xEE);

    for (uint32_t n = 0; n <= p.size(); ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK(rc >= 0 && rc < PP_ERR__COUNT);
        CHECK(m.l3_off <= m.caplen);
        CHECK(m.l4_off <= m.caplen);
        CHECK(m.caplen <= n);
    }
}

static void suite_every_prefix_ipv4() {
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(5, PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 7).fill(30, 0xEE);

    for (uint32_t n = 0; n <= p.size(); ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK(rc >= 0 && rc < PP_ERR__COUNT);
        CHECK(m.l3_off <= m.caplen);
        CHECK(m.l4_off <= m.caplen);
    }
}

int main() {
    suite_ipv4_basic();
    suite_ipv4_with_options();
    suite_ipv4_max_ihl();
    suite_ipv4_over_vlan();
    suite_ipv4_ihl_too_small();
    suite_ipv4_ihl_beyond_capture();
    suite_ipv4_truncated_everywhere();
    suite_ipv4_totlen_lies();
    suite_ipv4_totlen_absurdly_large_is_harmless();
    suite_ipv4_version_mismatch();
    suite_ipv4_first_fragment_has_l4();
    suite_ipv4_later_fragment_has_no_l4();
    suite_ipv4_df_is_not_a_fragment();
    suite_ipv6_basic();
    suite_ipv6_truncated();
    suite_ipv6_single_ext_header();
    suite_ipv6_ext_len_rule();
    suite_ipv6_chain_of_several();
    suite_ipv6_ah_has_its_own_length_rule();
    suite_ipv6_fragment_header_is_fixed_8();
    suite_ipv6_later_fragment_has_no_l4();
    suite_ipv6_esp_ends_the_chain();
    suite_ipv6_exthdr_bomb_is_bounded();
    suite_ipv6_exactly_max_exthdrs_is_ok();
    suite_ipv6_truncated_ext_chain();
    suite_every_prefix_ipv6_chain();
    suite_every_prefix_ipv4();
    TEST_SUMMARY("test_l3");
}
