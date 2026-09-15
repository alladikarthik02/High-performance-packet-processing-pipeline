// test_rules — the C++17 control plane, and the boundary it must not leak past.
#include "test.h"
#include "pp/ruleset.h"
#include "pp/arena.h"
#include "pp/proto.h"   // PP_IPPROTO_* — ruleset.h deliberately does not pull this in

#include <string>

namespace {

struct Fixture {
    pp_arena a{};
    pp_ruleset rs{};
    char err[256]{};

    Fixture() { pp_arena_init(&a, 1 << 20); }
    ~Fixture() { pp_arena_destroy(&a); }

    int compile(const char* text) {
        err[0] = 0;
        return pp_rules_compile_str(text, "test.rules", &a, &rs, err, sizeof err);
    }
    std::string error() const { return err; }
};

} // namespace

static void suite_layout() {
    // 32 bytes: two rules per cache line. The linear classifier walks this
    // array per packet, so its size is a performance decision, not a detail.
    CHECK_EQ(sizeof(pp_rule), size_t(32));
}

static void suite_basic_rule() {
    Fixture f;
    CHECK_EQ(f.compile("accept tcp 192.168.1.0/24 any -> 10.0.0.0/8 80"), 0);
    CHECK_EQ(f.rs.n, uint32_t(1));

    const pp_rule& r = f.rs.rules[0];
    CHECK_EQ(pp_rule_action(&r), uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(r.proto, uint8_t(PP_IPPROTO_TCP));
    CHECK_EQ(r.src_addr, uint32_t(0xC0A80100));   // 192.168.1.0
    CHECK_EQ(r.src_mask, uint32_t(0xFFFFFF00));   // /24
    CHECK_EQ(r.dst_addr, uint32_t(0x0A000000));   // 10.0.0.0
    CHECK_EQ(r.dst_mask, uint32_t(0xFF000000));   // /8
    CHECK_EQ(r.sport_lo, uint16_t(0));
    CHECK_EQ(r.sport_hi, uint16_t(65535));        // "any"
    CHECK_EQ(r.dport_lo, uint16_t(80));
    CHECK_EQ(r.dport_hi, uint16_t(80));
    CHECK_EQ(pp_rule_id(0), uint32_t(1));
    CHECK_EQ(r.vlan, uint16_t(PP_ANY_VLAN));
    CHECK_EQ(r.vni, uint32_t(PP_ANY_VNI));
}

static void suite_addresses_are_premasked() {
    // The compile step's payoff (ruleset.h): `addr` already has `mask` applied,
    // so the hot path does one AND instead of two. Verify the invariant holds
    // rather than trusting the comment.
    Fixture f;
    CHECK_EQ(f.compile(
        "accept tcp 10.0.0.0/8 any -> 172.16.0.0/12 any\n"
        "accept udp 192.168.0.0/16 any -> any any\n"
        "drop   tcp 8.8.8.8 any -> any any\n"), 0);
    for (uint32_t i = 0; i < f.rs.n; ++i) {
        const pp_rule& r = f.rs.rules[i];
        CHECK_EQ(r.src_addr & ~r.src_mask, uint32_t(0));   // no host bits survive
        CHECK_EQ(r.dst_addr & ~r.dst_mask, uint32_t(0));
        CHECK_EQ(r.src_addr, r.src_addr & r.src_mask);     // idempotent: already masked
    }
}

static void suite_prefix_boundaries() {
    Fixture f;
    // /0 must produce mask 0. The natural expression, 0xFFFFFFFF << 32, is
    // UNDEFINED BEHAVIOR in C — shift by the full width. It has to be
    // special-cased, and this is the test that would catch forgetting to.
    CHECK_EQ(f.compile("accept any 0.0.0.0/0 any -> any any"), 0);
    CHECK_EQ(f.rs.rules[0].src_mask, uint32_t(0));
    CHECK_EQ(f.rs.rules[0].src_addr, uint32_t(0));

    Fixture g;
    CHECK_EQ(g.compile("accept any 10.1.2.3/32 any -> any any"), 0);
    CHECK_EQ(g.rs.rules[0].src_mask, uint32_t(0xFFFFFFFF));
    CHECK_EQ(g.rs.rules[0].src_addr, uint32_t(0x0A010203));

    Fixture h;
    CHECK_EQ(h.compile("accept any 10.1.2.3 any -> any any"), 0);   // bare == /32
    CHECK_EQ(h.rs.rules[0].src_mask, uint32_t(0xFFFFFFFF));
}

static void suite_host_bits_rejected() {
    // 192.168.1.5/24 almost certainly means the author thinks it matches only
    // .5 — when it would match the entire /24. That is a silent, dangerous
    // widening of an access rule, so refuse it and say what they probably meant.
    Fixture f;
    CHECK_EQ(f.compile("drop tcp 192.168.1.5/24 any -> any any"), -1);
    CHECK(f.error().find("host bits") != std::string::npos);
    CHECK(f.error().find("192.168.1.0/24") != std::string::npos);  // the suggestion
    CHECK(f.error().find("test.rules:1") != std::string::npos);    // and WHERE
}

static void suite_port_ranges() {
    Fixture f;
    CHECK_EQ(f.compile("accept tcp any 1024-65535 -> any 80-443"), 0);
    CHECK_EQ(f.rs.rules[0].sport_lo, uint16_t(1024));
    CHECK_EQ(f.rs.rules[0].sport_hi, uint16_t(65535));
    CHECK_EQ(f.rs.rules[0].dport_lo, uint16_t(80));
    CHECK_EQ(f.rs.rules[0].dport_hi, uint16_t(443));
}

static void suite_inverted_port_range_rejected() {
    // An inverted range matches NOTHING. Accepting it silently gives you a
    // 'drop' rule you believe protects you and which never fires.
    Fixture f;
    CHECK_EQ(f.compile("drop tcp any any -> any 443-80"), -1);
    CHECK(f.error().find("inverted") != std::string::npos);
    CHECK(f.error().find("match nothing") != std::string::npos);
}

static void suite_qualifiers() {
    Fixture f;
    CHECK_EQ(f.compile(
        "accept tcp any any -> any 22 vlan 100\n"
        "drop   udp any any -> any any vni 5000\n"
        "count  any any any -> any any ip4\n"
        "log    any any any -> any any ip6\n"), 0);
    CHECK_EQ(f.rs.n, uint32_t(4));
    CHECK_EQ(f.rs.rules[0].vlan, uint16_t(100));
    CHECK_EQ(f.rs.rules[1].vni, uint32_t(5000));
    CHECK_EQ(pp_rule_ipver(&f.rs.rules[2]), uint8_t(4));
    CHECK_EQ(pp_rule_ipver(&f.rs.rules[3]), uint8_t(6));
    CHECK_EQ(pp_rule_action(&f.rs.rules[3]), uint8_t(PP_ACTION_LOG));
    // The packing must be lossless: both nibbles survive independently.
    CHECK_EQ(pp_rule_action(&f.rs.rules[2]), uint8_t(PP_ACTION_COUNT));
    CHECK_EQ(pp_rule_ipver(&f.rs.rules[0]), uint8_t(PP_ANY_IPVER));
}

static void suite_vlan_zero_is_valid_here_too() {
    // The T1/T2 sentinel story, once more: VLAN 0 is a legal, meaningful ID
    // (priority-tagged). A rule matching `vlan 0` must be distinguishable from
    // a rule with no VLAN qualifier at all.
    Fixture f;
    CHECK_EQ(f.compile(
        "accept tcp any any -> any any vlan 0\n"
        "accept tcp any any -> any any\n"), 0);
    CHECK_EQ(f.rs.rules[0].vlan, uint16_t(0));               // matches VLAN 0...
    CHECK_EQ(f.rs.rules[1].vlan, uint16_t(PP_ANY_VLAN));     // ...vs "don't care"
    CHECK_NE(f.rs.rules[0].vlan, f.rs.rules[1].vlan);
}

static void suite_default_action() {
    Fixture f;
    CHECK_EQ(f.compile("default drop\naccept tcp any any -> any 443"), 0);
    CHECK_EQ(f.rs.default_action, uint8_t(PP_ACTION_DROP));
    CHECK_EQ(f.rs.n, uint32_t(1));

    Fixture g;
    CHECK_EQ(g.compile("accept tcp any any -> any 443"), 0);
    CHECK_EQ(g.rs.default_action, uint8_t(PP_ACTION_ACCEPT));   // accept by default
}

static void suite_comments_and_blanks() {
    Fixture f;
    CHECK_EQ(f.compile(
        "# a leading comment\n"
        "\n"
        "accept tcp any any -> any 80   # trailing comment\n"
        "   \n"
        "# accept tcp any any -> any 22   <- commented out, must NOT compile\n"
        "drop udp any any -> any 53\n"), 0);
    CHECK_EQ(f.rs.n, uint32_t(2));                          // not 3
    CHECK_EQ(f.rs.rules[0].dport_lo, uint16_t(80));
    CHECK_EQ(f.rs.rules[1].proto, uint8_t(PP_IPPROTO_UDP));
}

static void suite_ids_are_positional() {
    // Rule identity is the array index, not a stored field: pp_rule_id(i) is
    // i+1 and tracks file order, so "rule 3 matched 40,000 packets" points at a
    // line the author can find. Not storing it saves 4 bytes AND removes the
    // possibility of the stored id disagreeing with the position.
    Fixture f;
    CHECK_EQ(f.compile(
        "accept tcp any any -> any 80\n"
        "drop   tcp any any -> any 22\n"
        "count  udp any any -> any 53\n"), 0);
    CHECK_EQ(pp_rule_id(0), uint32_t(1));
    CHECK_EQ(pp_rule_id(2), uint32_t(3));
    // ...and order really is file order:
    CHECK_EQ(pp_rule_action(&f.rs.rules[0]), uint8_t(PP_ACTION_ACCEPT));
    CHECK_EQ(pp_rule_action(&f.rs.rules[1]), uint8_t(PP_ACTION_DROP));
    CHECK_EQ(pp_rule_action(&f.rs.rules[2]), uint8_t(PP_ACTION_COUNT));
}

// ---------------------------------------------------------------------------
// Errors. A config language is a UI: its error messages are the product.
// ---------------------------------------------------------------------------

static void suite_error_messages_name_the_line() {
    Fixture f;
    CHECK_EQ(f.compile(
        "accept tcp any any -> any 80\n"
        "accept tcp any any -> any 443\n"
        "bogus  tcp any any -> any 22\n"), -1);
    CHECK(f.error().find("test.rules:3") != std::string::npos);   // the right line
    CHECK(f.error().find("bogus") != std::string::npos);          // the bad token
    CHECK(f.error().find("accept|drop|count|log") != std::string::npos);  // the fix
}

static void suite_various_syntax_errors() {
    struct Case { const char* text; const char* expect; };
    const Case cases[] = {
        {"accept tcp any any any any",          "->"},
        {"accept",                              "expected"},
        {"accept tcp any any -> any",           "expected"},
        {"accept blah any any -> any any",      "unknown protocol"},
        {"accept tcp 999.1.1.1/24 any -> any any", "> 255"},
        {"accept tcp 1.2.3/24 any -> any any",  "4 octets"},
        {"accept tcp 1.2.3.4/33 any -> any any","out of range"},
        {"accept tcp any 99999 -> any any",     "out of range"},
        {"accept tcp any any -> any any vlan 4096", "out of range"},
        {"accept tcp any any -> any any vni 99999999", "out of range"},
        {"accept tcp any any -> any any frobnicate", "unknown qualifier"},
        {"accept tcp any any -> any any vlan",  "needs an ID"},
        {"default",                             "exactly one action"},
    };
    for (const auto& c : cases) {
        Fixture f;
        CHECK_EQ(f.compile(c.text), -1);
        if (f.error().find(c.expect) == std::string::npos)
            std::fprintf(stderr, "  [note] %-42s -> %s\n", c.text, f.error().c_str());
        CHECK(f.error().find(c.expect) != std::string::npos);
    }
}

static void suite_contradictory_rule_rejected() {
    // ip6 + an IPv4 CIDR can never match anything. Better to fail the build
    // than to ship a rule that quietly does nothing.
    Fixture f;
    CHECK_EQ(f.compile("drop tcp 10.0.0.0/8 any -> any any ip6"), -1);
    CHECK(f.error().find("ip6") != std::string::npos);
}

static void suite_octal_and_hex_addresses_rejected() {
    // inet_pton() accepts "010.1.1.1" (octal!), "0x0a000001", and "10" as
    // shorthand. That's historically a rich source of ACL bypasses: the tool
    // writing the rule and the tool reading the packet disagree about what the
    // string means. We take four decimal octets and nothing else.
    Fixture f;
    CHECK_EQ(f.compile("drop tcp 0x0a000001 any -> any any"), -1);

    Fixture g;
    CHECK_EQ(g.compile("drop tcp 10 any -> any any"), -1);
    CHECK(g.error().find("4 octets") != std::string::npos);
}

static void suite_empty_ruleset_is_valid() {
    Fixture f;
    CHECK_EQ(f.compile("# nothing but a comment\n"), 0);
    CHECK_EQ(f.rs.n, uint32_t(0));
    CHECK_EQ(f.compile(""), 0);
    CHECK_EQ(f.rs.n, uint32_t(0));
}

static void suite_rules_live_in_the_arena() {
    // The lifetime story (ruleset.h): the rule array must come from the arena,
    // NOT from the C++ heap, so the data plane never holds memory owned by the
    // C++ runtime and the ruleset outlives every object that built it.
    Fixture f;
    size_t before = f.a.used;
    CHECK_EQ(f.compile(
        "accept tcp any any -> any 80\n"
        "drop tcp any any -> any 22\n"), 0);
    CHECK(f.a.used > before);                       // it really came from here
    CHECK(f.a.used - before >= 2 * sizeof(pp_rule));

    // ...and within the arena's mapping, not somewhere else.
    auto p = reinterpret_cast<const uint8_t*>(f.rs.rules);
    CHECK(p >= f.a.base && p < f.a.base + f.a.cap);
    // ...and cache-line aligned, because the classifier walks it.
    CHECK_EQ(reinterpret_cast<uintptr_t>(f.rs.rules) % PP_CACHELINE, uintptr_t(0));
}

static void suite_arena_exhaustion_is_reported() {
    // A tiny arena and many rules. Must fail cleanly with a message, not
    // overrun or return a half-built ruleset.
    pp_arena a{};
    pp_arena_init(&a, 4096);
    pp_arena_alloc(&a, 4000, 1);        // leave almost nothing

    std::string text;
    for (int i = 0; i < 100; ++i) text += "accept tcp any any -> any 80\n";

    pp_ruleset rs{}; char err[256]{};
    CHECK_EQ(pp_rules_compile_str(text.c_str(), "big.rules", &a, &rs, err, sizeof err), -1);
    CHECK(std::string(err).find("arena") != std::string::npos);
    pp_arena_destroy(&a);
}

static void suite_action_strings() {
    for (int i = 0; i < PP_ACTION__COUNT; ++i)
        CHECK(std::string(pp_action_str(i)) != "invalid");
    CHECK_EQ(std::string(pp_action_str(999)), std::string("invalid"));
}

int main() {
    suite_layout();
    suite_basic_rule();
    suite_addresses_are_premasked();
    suite_prefix_boundaries();
    suite_host_bits_rejected();
    suite_port_ranges();
    suite_inverted_port_range_rejected();
    suite_qualifiers();
    suite_vlan_zero_is_valid_here_too();
    suite_default_action();
    suite_comments_and_blanks();
    suite_ids_are_positional();
    suite_error_messages_name_the_line();
    suite_various_syntax_errors();
    suite_contradictory_rule_rejected();
    suite_octal_and_hex_addresses_rejected();
    suite_empty_ruleset_is_valid();
    suite_rules_live_in_the_arena();
    suite_arena_exhaustion_is_reported();
    suite_action_strings();
    TEST_SUMMARY("test_rules");
}
