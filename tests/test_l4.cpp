// test_l4 — TCP, UDP, ICMP, and VXLAN tunnel re-entry.
#include "test.h"
#include "pktbuild.h"
#include "pp/parse.h"

using namespace pktbuild;

static constexpr uint32_t SRC = 0xC0A80101;   // 192.168.1.1
static constexpr uint32_t DST = 0x08080808;   // 8.8.8.8
static constexpr uint32_t USRC = 0x0A000001;  // 10.0.0.1  (underlay)
static constexpr uint32_t UDST = 0x0A000002;  // 10.0.0.2

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

static void suite_tcp_basic() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(12345, 80, PP_TCP_SYN).fill(10, 0xDD);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(rc, int(PP_OK));
    CHECK(m.layers & PP_LAYER_L4);
    CHECK_EQ(m.sport, uint16_t(12345));
    CHECK_EQ(m.dport, uint16_t(80));
    CHECK_EQ(m.tcp_flags, uint8_t(PP_TCP_SYN));
    CHECK_EQ(m.l4_hlen, uint8_t(20));
    CHECK_EQ(m.l4_off, uint16_t(34));            // 14 + 20
    CHECK_EQ(m.payload_off, uint16_t(54));       // 14 + 20 + 20
    CHECK_EQ(m.payload_len, uint16_t(10));
    CHECK(m.layers & PP_LAYER_PAYLOAD);
}

static void suite_tcp_with_options() {
    // doff=8 => 32-byte header. Payload starts 12 bytes later than the doff=5
    // case. A parser hardcoding 20 reads options as payload.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2, PP_TCP_ACK, /*doff=*/8).fill(10, 0xDD);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.l4_hlen, uint8_t(32));
    CHECK_EQ(m.payload_off, uint16_t(14 + 20 + 32));
    CHECK_EQ(m.payload_len, uint16_t(10));
}

static void suite_tcp_all_flags() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2, uint8_t(PP_TCP_FIN | PP_TCP_SYN | PP_TCP_RST | PP_TCP_PSH |
                               PP_TCP_ACK | PP_TCP_URG | PP_TCP_ECE | PP_TCP_CWR));
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.tcp_flags, uint8_t(0xFF));
}

static void suite_tcp_doff_too_small() {
    // doff < 5 claims a header shorter than the fixed TCP header itself.
    for (uint8_t doff = 0; doff < 5; ++doff) {
        Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
                .tcp(1, 2, PP_TCP_ACK, doff).fill(10);
        auto v = p.view();
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK_EQ(rc, int(PP_ERR_BAD_TCP_DOFF));
        // Ports were at fixed offsets and are still usable — a corrupt data
        // offset does not erase what we legitimately read before it.
        CHECK_EQ(m.sport, uint16_t(1));
        CHECK_EQ(m.dport, uint16_t(2));
    }
}

static void suite_tcp_doff_beyond_capture() {
    // doff=15 => 60-byte header, but we only captured ~24 bytes of TCP.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2, PP_TCP_ACK, /*doff=*/15);
    auto v = p.view(/*caplen=*/14 + 20 + 24);
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_TRUNC_L4));
}

static void suite_tcp_truncated_sweep() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST).tcp(1, 2);
    for (uint32_t n = 34; n < 34 + 20; ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_TRUNC_L4));
        CHECK(m.layers & PP_LAYER_L3);          // L3 still decoded
        CHECK(!(m.layers & PP_LAYER_L4));
    }
}

static void suite_tcp_no_payload() {
    // A bare ACK: header only, zero payload. payload_len 0 and no PAYLOAD bit —
    // "empty payload" and "payload present" must not be conflated.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST).tcp(1, 2);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.payload_len, uint16_t(0));
    CHECK(!(m.layers & PP_LAYER_PAYLOAD));
    CHECK(m.layers & PP_LAYER_L4);
}

// ---------------------------------------------------------------------------
// UDP / ICMP
// ---------------------------------------------------------------------------

static void suite_udp_basic() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, SRC, DST)
            .udp(53, 5353).fill(16, 0xEE);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_OK));
    CHECK_EQ(m.sport, uint16_t(53));
    CHECK_EQ(m.dport, uint16_t(5353));
    CHECK_EQ(m.l4_hlen, uint8_t(8));
    CHECK_EQ(m.payload_off, uint16_t(14 + 20 + 8));
    CHECK_EQ(m.payload_len, uint16_t(16));
}

static void suite_udp_length_field_is_ignored() {
    // The UDP length field claims 9999 in a small capture. It must not bound
    // anything — caplen already told us the truth (SPEC §7.9).
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, SRC, DST)
            .udp(1, 2, /*len=*/9999).fill(16);
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_OK));
    CHECK_EQ(m.payload_len, uint16_t(16));   // from caplen, not from the field
}

static void suite_udp_truncated() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, SRC, DST).udp(1, 2);
    for (uint32_t n = 34; n < 34 + 8; ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_TRUNC_L4));
    }
}

static void suite_icmp_type_code_in_ports() {
    // ICMP has no ports; type/code ride in the port fields so the 5-tuple stays
    // uniform and the classifier needs no special case.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_ICMP, SRC, DST)
            .icmp(/*type=*/8, /*code=*/0).fill(32);   // echo request
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_OK));
    CHECK(m.layers & PP_LAYER_L4);
    CHECK_EQ(m.sport, uint16_t(8));
    CHECK_EQ(m.dport, uint16_t(0));
}

static void suite_icmpv6_over_ipv6() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_ICMPV6, 8)
            .icmp(/*type=*/128, /*code=*/0).fill(16);
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_OK));
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_ICMPV6));
    CHECK_EQ(m.sport, uint16_t(128));
}

static void suite_tcp_over_ipv6_ext_chain() {
    // The full stack: IPv6 + extension header + TCP. Offsets must compose.
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_HOPOPTS, 0)
            .ip6_ext(PP_IPPROTO_TCP, 0)
            .tcp(443, 51000, PP_TCP_ACK).fill(8);
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_OK));
    CHECK_EQ(m.ip_ver, uint8_t(6));
    CHECK_EQ(m.sport, uint16_t(443));
    CHECK_EQ(m.l4_off, uint16_t(14 + 40 + 8));
}

static void suite_unknown_l4_is_not_an_error() {
    // SCTP: we don't decode it. L3 is still perfectly good and classifiable.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_SCTP, SRC, DST).fill(20);
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_OK));
    CHECK(m.layers & PP_LAYER_L3);
    CHECK(!(m.layers & PP_LAYER_L4));
    CHECK_EQ(m.ip_proto, uint8_t(PP_IPPROTO_SCTP));
}

static void suite_fragment_still_has_no_l4() {
    // Now that L4 exists, the fragment rule from T3 is genuinely enforceable:
    // a later fragment's bytes at l4_off LOOK like a TCP header. We must not
    // read them.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST, 5, 0xFFFF, /*fragword=*/100)
            .tcp(31337, 31338).fill(10);     // plausible-looking bytes!
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(rc, int(PP_OK));
    CHECK(m.layers & PP_LAYER_L3);
    CHECK(!(m.layers & PP_LAYER_L4));
    CHECK_EQ(m.sport, uint16_t(0));      // NOT 31337 — we refused to invent them
    CHECK_EQ(m.dport, uint16_t(0));
}

// ---------------------------------------------------------------------------
// VXLAN
// ---------------------------------------------------------------------------

static void suite_vxlan_decap() {
    // Underlay: 10.0.0.1 -> 10.0.0.2, UDP/4789, VNI 5000
    // Overlay:  192.168.1.1 -> 8.8.8.8, TCP 1234 -> 443
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(45678, PP_UDP_PORT_VXLAN)
            .vxlan(5000)
            // ---- inner frame starts here ----
            .eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1234, 443, PP_TCP_SYN)
            .fill(12, 0xAB);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(rc, int(PP_OK));
    CHECK(m.layers & PP_LAYER_TUNNEL);
    CHECK_EQ(m.vni, uint32_t(5000));
    CHECK_EQ(m.tunnel_depth, uint8_t(1));

    // The metadata describes the INNER (tenant) packet — that is what a rule
    // wants to match on.
    CHECK_EQ(m.ip_src, SRC);
    CHECK_EQ(m.ip_dst, DST);
    CHECK_EQ(m.sport, uint16_t(1234));
    CHECK_EQ(m.dport, uint16_t(443));
    CHECK_EQ(m.tcp_flags, uint8_t(PP_TCP_SYN));

    // ...while the underlay's L3 is retained rather than lost.
    CHECK_EQ(m.outer_l3_off, uint16_t(14));
    // inner L3 = 14 eth + 20 ip + 8 udp + 8 vxlan + 14 inner-eth = 64
    CHECK_EQ(m.l3_off, uint16_t(64));
    CHECK_EQ(m.payload_len, uint16_t(12));
}

static void suite_vxlan_inner_vlan_does_not_leak() {
    // The reset_for_inner() bug this guards: if the outer frame had a VLAN and
    // the inner does not, a sloppy reset leaves the outer VLAN in the metadata
    // and the inner packet matches a `vlan 77` rule it has nothing to do with.
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(77, PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN)
            .vxlan(99)
            .eth(PP_ETHERTYPE_IPV4)              // inner: NO vlan
            .ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2).fill(4);
    auto v = p.view();

    pp_meta m; pp_parse(&v, &m);

    CHECK_EQ(m.vni, uint32_t(99));
    CHECK_EQ(m.vlan_outer, uint16_t(PP_VLAN_NONE));   // outer VLAN must NOT leak
    CHECK(!(m.layers & PP_LAYER_VLAN));
    CHECK_EQ(m.ip_src, SRC);
}

static void suite_vxlan_without_vni_flag_is_plain_udp() {
    // UDP/4789 with the 'I' bit clear is not valid VXLAN. Reporting it as plain
    // UDP is honest; manufacturing a tenant ID out of reserved bytes is not.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4)
            .ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN)
            .vxlan(1234, /*flags=*/0x00)          // 'I' bit CLEAR
            .fill(20);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_OK));
    CHECK(!(m.layers & PP_LAYER_TUNNEL));
    CHECK_EQ(m.vni, uint32_t(0));
    CHECK_EQ(m.dport, uint16_t(PP_UDP_PORT_VXLAN));   // still plain UDP
    CHECK_EQ(m.ip_src, USRC);                         // ...to the underlay
}

static void suite_vxlan_truncated_header() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN).fill(4);      // only 4 of 8 VXLAN bytes
    auto v = p.view();
    pp_meta m;
    CHECK_EQ(pp_parse(&v, &m), int(PP_ERR_TRUNC_TUNNEL));
}

static void suite_vxlan_nesting_bomb_is_bounded() {
    // THE recursion DoS (SPEC §7.8). VXLAN inside VXLAN. A recursive parser
    // pushes a stack frame per layer and a deep enough nest blows the stack
    // from ONE frame. pktpipe parses in a LOOP, so there is no stack to
    // overflow — and the depth cap is then purely about CPU.
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN).vxlan(1)
            .eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN).vxlan(2)      // second level: over the cap
            .eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2).fill(4);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_TOO_DEEP_TUNNEL));
    CHECK_EQ(m.tunnel_depth, uint8_t(PP_MAX_TUNNEL_DEPTH));
}

static void suite_vxlan_every_prefix() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, USRC, UDST)
            .udp(1, PP_UDP_PORT_VXLAN).vxlan(7)
            .eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, SRC, DST)
            .tcp(1, 2).fill(8, 0xEE);

    for (uint32_t n = 0; n <= p.size(); ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK(rc >= 0 && rc < PP_ERR__COUNT);
        CHECK(m.l3_off <= m.caplen);
        CHECK(m.l4_off <= m.caplen);
        CHECK(m.payload_off <= m.caplen);
        CHECK(uint32_t(m.payload_off) + m.payload_len <= m.caplen);
    }
}

int main() {
    suite_tcp_basic();
    suite_tcp_with_options();
    suite_tcp_all_flags();
    suite_tcp_doff_too_small();
    suite_tcp_doff_beyond_capture();
    suite_tcp_truncated_sweep();
    suite_tcp_no_payload();
    suite_udp_basic();
    suite_udp_length_field_is_ignored();
    suite_udp_truncated();
    suite_icmp_type_code_in_ports();
    suite_icmpv6_over_ipv6();
    suite_tcp_over_ipv6_ext_chain();
    suite_unknown_l4_is_not_an_error();
    suite_fragment_still_has_no_l4();
    suite_vxlan_decap();
    suite_vxlan_inner_vlan_does_not_leak();
    suite_vxlan_without_vni_flag_is_plain_udp();
    suite_vxlan_truncated_header();
    suite_vxlan_nesting_bomb_is_bounded();
    suite_vxlan_every_prefix();
    TEST_SUMMARY("test_l4");
}
