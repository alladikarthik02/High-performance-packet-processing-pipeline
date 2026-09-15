// test_classify — rules meeting packets.
//
// Most of these are about the ways a classifier can match something it should
// not. A parser bug crashes; a classifier bug silently permits traffic you
// believed you had blocked, which is why the "must NOT match" cases outnumber
// the positive ones here.
#include "test.h"
#include "pktbuild.h"
#include "pp/classify.h"
#include "pp/parse.h"
#include "pp/arena.h"

#include <string>

using namespace pktbuild;

namespace {

struct Fixture {
    pp_arena a{};
    pp_ruleset rs{};
    pp_classifier cl{};
    char err[256]{};

    Fixture(const char* rules) {
        pp_arena_init(&a, 1 << 20);
        if (pp_rules_compile_str(rules, "t.rules", &a, &rs, err, sizeof err) != 0) {
            std::fprintf(stderr, "  RULE COMPILE FAILED: %s\n", err);
            std::abort();
        }
        pp_classifier_init(&cl, &rs, &a);
    }
    ~Fixture() { pp_arena_destroy(&a); }

    // Parse a packet and classify it in one step, the way the pipeline will.
    uint8_t verdict(const Pkt& p, uint32_t* rule = nullptr) {
        auto v = p.view();
        pp_meta m;
        pp_parse(&v, &m);
        return pp_classify(&cl, &m, rule);
    }
};

uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|d;
}

Pkt tcp_pkt(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport) {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4);
    size_t ip0 = p.size();
    p.ipv4(PP_IPPROTO_TCP, src, dst).tcp(sport, dport).fill(8).fix_ipv4_totlen(ip0);
    return p;
}

} // namespace

static void suite_basic_match() {
    Fixture f("default drop\n"
              "accept tcp 192.168.1.0/24 any -> 10.0.0.0/8 443\n");

    uint32_t rule = 999;
    CHECK_EQ(f.verdict(tcp_pkt(ip4(192,168,1,50), ip4(10,1,2,3), 1234, 443), &rule),
             uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(rule, uint32_t(1));                       // and it names the line

    // Wrong dst port -> falls through to the default.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(192,168,1,50), ip4(10,1,2,3), 1234, 80), &rule),
             uint8_t(PP_ACTION_DROP));
    CHECK_EQ(rule, uint32_t(0));                       // 0 == "the default applied"

    // Source outside the /24.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(192,168,2,50), ip4(10,1,2,3), 1234, 443)),
             uint8_t(PP_ACTION_DROP));
    // Destination outside the /8.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(192,168,1,50), ip4(11,1,2,3), 1234, 443)),
             uint8_t(PP_ACTION_DROP));
}

static void suite_first_match_wins() {
    // Order is policy. Rule 1 must win even though rule 2 also matches — this
    // is the semantics every operator expects from iptables.
    Fixture f("default accept\n"
              "drop   tcp any any -> any 22\n"
              "accept tcp any any -> any any\n");
    uint32_t rule = 0;
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,2,3,4), ip4(5,6,7,8), 1000, 22), &rule),
             uint8_t(PP_ACTION_DROP));
    CHECK_EQ(rule, uint32_t(1));

    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,2,3,4), ip4(5,6,7,8), 1000, 80), &rule),
             uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(rule, uint32_t(2));
}

static void suite_count_is_not_terminal() {
    // A count rule must tally AND let evaluation continue — otherwise a
    // monitoring rule silently becomes a policy rule, which would be a
    // spectacular way to break someone's firewall by adding telemetry.
    Fixture f("default accept\n"
              "count tcp any any -> any 443\n"     // rule 1: counts, continues
              "drop  tcp any any -> any 443\n");   // rule 2: actually decides
    uint32_t rule = 0;
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,2,3,4), ip4(5,6,7,8), 1000, 443), &rule),
             uint8_t(PP_ACTION_DROP));
    CHECK_EQ(rule, uint32_t(2));            // the DROP decided...
    CHECK_EQ(f.cl.hits[0], uint64_t(1));    // ...and the count still counted
    CHECK_EQ(f.cl.hits[1], uint64_t(1));
}

static void suite_hit_counters() {
    Fixture f("default drop\n"
              "accept tcp any any -> any 80\n"
              "accept tcp any any -> any 443\n");
    for (int i = 0; i < 5; ++i) f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 80));
    for (int i = 0; i < 3; ++i) f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 443));
    for (int i = 0; i < 2; ++i) f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 22));
    CHECK_EQ(f.cl.hits[0], uint64_t(5));
    CHECK_EQ(f.cl.hits[1], uint64_t(3));
    CHECK_EQ(f.cl.n_default, uint64_t(2));
}

static void suite_proto_selectivity() {
    Fixture f("default drop\naccept udp any any -> any 53\n");
    // Right port, wrong protocol: must not match.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(8,8,8,8), 1000, 53)),
             uint8_t(PP_ACTION_DROP));

    Pkt u; u.eth(PP_ETHERTYPE_IPV4);
    size_t ip0 = u.size();
    u.ipv4(PP_IPPROTO_UDP, ip4(1,1,1,1), ip4(8,8,8,8)).udp(1000, 53).fill(8)
     .fix_ipv4_totlen(ip0);
    CHECK_EQ(f.verdict(u), uint8_t(PP_ACTION_ACCEPT));
}

static void suite_port_ranges_are_inclusive() {
    Fixture f("default drop\naccept tcp any any -> any 100-200\n");
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1,  99)), uint8_t(PP_ACTION_DROP));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 100)), uint8_t(PP_ACTION_ACCEPT)); // inclusive lo
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 150)), uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 200)), uint8_t(PP_ACTION_ACCEPT)); // inclusive hi
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 201)), uint8_t(PP_ACTION_DROP));
}

static void suite_prefix_boundaries() {
    Fixture f("default drop\naccept tcp 10.0.0.0/8 any -> any any\n");
    CHECK_EQ(f.verdict(tcp_pkt(ip4(10,0,0,0),     ip4(1,1,1,1), 1, 1)), uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(10,255,255,255), ip4(1,1,1,1), 1, 1)), uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(9,255,255,255), ip4(1,1,1,1), 1, 1)), uint8_t(PP_ACTION_DROP));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(11,0,0,0),     ip4(1,1,1,1), 1, 1)), uint8_t(PP_ACTION_DROP));
}

static void suite_slash_zero_matches_everything() {
    Fixture f("default drop\naccept tcp 0.0.0.0/0 any -> 0.0.0.0/0 any\n");
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,2,3,4), ip4(250,250,250,250), 1, 1)),
             uint8_t(PP_ACTION_ACCEPT));
}

// ---------------------------------------------------------------------------
// The dangerous cases: matching something we should not
// ---------------------------------------------------------------------------

static void suite_port_rule_must_not_match_fragment() {
    // THE security case. A later fragment has no L4 header, so the parser
    // refuses to invent ports and leaves them 0 (T3/T4). A rule naming port 22
    // must NOT fire on it — dropping traffic on the basis of a port number
    // nobody ever read would be a decision made out of thin air.
    Fixture f("default accept\ndrop tcp any any -> any 22\n");

    Pkt frag; frag.eth(PP_ETHERTYPE_IPV4);
    size_t ip0 = frag.size();
    frag.ipv4(PP_IPPROTO_TCP, ip4(1,1,1,1), ip4(2,2,2,2), 5, 0xFFFF, /*fragword=*/100)
        .tcp(31337, 22)      // payload bytes that LOOK like a port-22 header
        .fix_ipv4_totlen(ip0);

    uint32_t rule = 999;
    CHECK_EQ(f.verdict(frag, &rule), uint8_t(PP_ACTION_ACCEPT));  // default, not the drop
    CHECK_EQ(rule, uint32_t(0));
    CHECK_EQ(f.cl.hits[0], uint64_t(0));   // the drop rule never fired
}

static void suite_any_ports_does_match_portless_packets() {
    // The complement of the above: "any" ports must mean ANY, including
    // "there are none". An ARP frame or an ESP packet is still matchable by a
    // rule that does not care about ports.
    Fixture f("default drop\naccept any any any -> any any\n");
    Pkt arp; arp.eth(PP_ETHERTYPE_ARP).fill(46);
    CHECK_EQ(f.verdict(arp), uint8_t(PP_ACTION_ACCEPT));
}

static void suite_ipv4_rule_must_not_match_ipv6() {
    // pp_meta.ip_src is 0 for IPv6 (we deliberately don't copy 128-bit
    // addresses into the cache line). Without the ip_ver guard in
    // rule_matches(), a `0.0.0.0/8` rule would match every IPv6 packet.
    Fixture f("default drop\naccept tcp 0.0.0.0/8 any -> any any\n");

    Pkt v6; v6.eth(PP_ETHERTYPE_IPV6);
    size_t ip0 = v6.size();
    v6.ipv6(PP_IPPROTO_TCP, 0).tcp(1234, 443).fill(8).fix_ipv6_plen(ip0);

    CHECK_EQ(f.verdict(v6), uint8_t(PP_ACTION_DROP));   // NOT accepted
    CHECK_EQ(f.cl.hits[0], uint64_t(0));
}

static void suite_ip6_qualifier() {
    Fixture f("default drop\naccept tcp any any -> any 443 ip6\n");

    Pkt v6; v6.eth(PP_ETHERTYPE_IPV6);
    size_t i0 = v6.size();
    v6.ipv6(PP_IPPROTO_TCP, 0).tcp(1, 443).fill(4).fix_ipv6_plen(i0);
    CHECK_EQ(f.verdict(v6), uint8_t(PP_ACTION_ACCEPT));

    // Same ports over IPv4 must not match an ip6-qualified rule.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 443)),
             uint8_t(PP_ACTION_DROP));
}

static void suite_vlan_matching() {
    Fixture f("default drop\n"
              "accept tcp any any -> any any vlan 100\n");

    Pkt tagged; tagged.eth(PP_ETHERTYPE_VLAN).vlan_tag(100, PP_ETHERTYPE_IPV4);
    size_t i0 = tagged.size();
    tagged.ipv4(PP_IPPROTO_TCP, ip4(1,1,1,1), ip4(2,2,2,2)).tcp(1,2).fill(4)
          .fix_ipv4_totlen(i0);
    CHECK_EQ(f.verdict(tagged), uint8_t(PP_ACTION_ACCEPT));

    // Different VLAN.
    Pkt other; other.eth(PP_ETHERTYPE_VLAN).vlan_tag(200, PP_ETHERTYPE_IPV4);
    size_t i1 = other.size();
    other.ipv4(PP_IPPROTO_TCP, ip4(1,1,1,1), ip4(2,2,2,2)).tcp(1,2).fill(4)
         .fix_ipv4_totlen(i1);
    CHECK_EQ(f.verdict(other), uint8_t(PP_ACTION_DROP));

    // Untagged must not match a vlan-qualified rule.
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 2)),
             uint8_t(PP_ACTION_DROP));
}

static void suite_vlan_zero_vs_no_vlan() {
    // The sentinel story, third appearance, now with real consequences: a rule
    // matching `vlan 0` must fire on a priority-tagged frame and NOT on an
    // untagged one.
    Fixture f("default drop\naccept tcp any any -> any any vlan 0\n");

    Pkt prio; prio.eth(PP_ETHERTYPE_VLAN).vlan_tag(0, PP_ETHERTYPE_IPV4, /*pcp=*/5);
    size_t i0 = prio.size();
    prio.ipv4(PP_IPPROTO_TCP, ip4(1,1,1,1), ip4(2,2,2,2)).tcp(1,2).fill(4)
        .fix_ipv4_totlen(i0);
    CHECK_EQ(f.verdict(prio), uint8_t(PP_ACTION_ACCEPT));    // VLAN 0 IS a VLAN

    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 2)),
             uint8_t(PP_ACTION_DROP));                       // untagged is not
}

static void suite_vni_matches_the_tenant_not_the_underlay() {
    // A VXLAN packet: metadata describes the INNER flow (T4). So a rule matches
    // the tenant's addresses, and `vni` selects which tenant.
    Fixture f("default drop\n"
              "accept tcp 172.16.0.0/16 any -> any 8080 vni 5000\n");

    Pkt vx; vx.eth(PP_ETHERTYPE_IPV4);
    size_t o0 = vx.size();
    vx.ipv4(PP_IPPROTO_UDP, ip4(10,0,0,1), ip4(10,0,0,2));
    size_t u0 = vx.size();
    vx.udp(4000, PP_UDP_PORT_VXLAN).vxlan(5000).eth(PP_ETHERTYPE_IPV4);
    size_t i0 = vx.size();
    vx.ipv4(PP_IPPROTO_TCP, ip4(172,16,0,5), ip4(172,16,1,1)).tcp(1234, 8080).fill(4)
      .fix_ipv4_totlen(i0).fix_udp_len(u0).fix_ipv4_totlen(o0);

    CHECK_EQ(f.verdict(vx), uint8_t(PP_ACTION_ACCEPT));

    // Same packet, wrong tenant.
    Fixture g("default drop\n"
              "accept tcp 172.16.0.0/16 any -> any 8080 vni 9999\n");
    CHECK_EQ(g.verdict(vx), uint8_t(PP_ACTION_DROP));
}

static void suite_malformed_packets_are_classifiable() {
    // A truncated TCP header means no L4, but L3 was decoded and is perfectly
    // good — so an IP-only rule must still match it. This is exactly why
    // pp_parse keeps what it decoded on error (T3's contract) rather than
    // discarding the packet.
    Fixture f("default accept\ndrop any 192.168.1.0/24 any -> any any\n");

    Pkt p; p.eth(PP_ETHERTYPE_IPV4);
    size_t i0 = p.size();
    p.ipv4(PP_IPPROTO_TCP, ip4(192,168,1,7), ip4(2,2,2,2)).fix_ipv4_totlen(i0);
    p.fill(4, 0x00);       // a stub of a TCP header: truncated

    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_TRUNC_L4));       // malformed...
    CHECK(m.layers & PP_LAYER_L3);            // ...but L3 survived

    uint32_t rule = 0;
    CHECK_EQ(pp_classify(&f.cl, &m, &rule), uint8_t(PP_ACTION_DROP));  // still matched
    CHECK_EQ(rule, uint32_t(1));
}

static void suite_empty_ruleset_uses_default() {
    Fixture f("default drop\n");
    CHECK_EQ(f.rs.n, uint32_t(0));
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 80)),
             uint8_t(PP_ACTION_DROP));
    CHECK_EQ(f.cl.n_default, uint64_t(1));
}

static void suite_many_rules_scan_in_order() {
    // 64 rules, matching the last one: exercises the full scan and proves order
    // is preserved at depth, not just for the two-rule case.
    std::string rules = "default drop\n";
    for (int i = 0; i < 63; ++i)
        rules += "accept tcp any any -> any " + std::to_string(1000 + i) + "\n";
    rules += "accept tcp any any -> any 9999\n";   // rule 64

    Fixture f(rules.c_str());
    CHECK_EQ(f.rs.n, uint32_t(64));

    uint32_t rule = 0;
    CHECK_EQ(f.verdict(tcp_pkt(ip4(1,1,1,1), ip4(2,2,2,2), 1, 9999), &rule),
             uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(rule, uint32_t(64));
    CHECK_EQ(f.cl.hits[63], uint64_t(1));
    CHECK_EQ(f.cl.hits[0], uint64_t(0));
}

int main() {
    suite_basic_match();
    suite_first_match_wins();
    suite_count_is_not_terminal();
    suite_hit_counters();
    suite_proto_selectivity();
    suite_port_ranges_are_inclusive();
    suite_prefix_boundaries();
    suite_slash_zero_matches_everything();
    suite_port_rule_must_not_match_fragment();
    suite_any_ports_does_match_portless_packets();
    suite_ipv4_rule_must_not_match_ipv6();
    suite_ip6_qualifier();
    suite_vlan_matching();
    suite_vlan_zero_vs_no_vlan();
    suite_vni_matches_the_tenant_not_the_underlay();
    suite_malformed_packets_are_classifiable();
    suite_empty_ruleset_uses_default();
    suite_many_rules_scan_in_order();
    TEST_SUMMARY("test_classify");
}
