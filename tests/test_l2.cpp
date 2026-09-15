// test_l2 — Ethernet, VLAN, QinQ, and the malformed frames that break parsers.
//
// Roughly half of these are hostile inputs. That ratio is deliberate: on a real
// link, malformed and truncated frames are ordinary traffic, and a parser is
// only as good as its behaviour on the packets nobody meant to send.
#include "test.h"
#include "pktbuild.h"
#include "pp/parse.h"

using namespace pktbuild;

// ---------------------------------------------------------------------------
// Well-formed frames
// ---------------------------------------------------------------------------

static void suite_plain_ethernet() {
    // ARP on purpose, so this stays a test of L2 alone. ARP is also the
    // cleanest illustration of the parse contract: a perfectly good packet
    // (PP_OK) that has no L3 at all (layers == L2). "Not decoded" and
    // "malformed" are different answers to different questions.
    Pkt p; p.eth(PP_ETHERTYPE_ARP).fill(46);   // 14 + 46 = 60, min frame size
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);

    CHECK_EQ(rc, int(PP_ERR_UNSUPPORTED_L3));   // we decline to decode ARP...
    CHECK(m.layers & PP_LAYER_L2);              // ...but L2 parsed fine
    CHECK(!(m.layers & PP_LAYER_L3));
    CHECK_EQ(m.eth_type, uint16_t(PP_ETHERTYPE_ARP));
    CHECK_EQ(m.l2_off, uint16_t(0));
    CHECK_EQ(m.l3_off, uint16_t(14));           // straight after the Ethernet header
    CHECK_EQ(m.vlan_outer, uint16_t(PP_VLAN_NONE));
    CHECK(!(m.layers & PP_LAYER_VLAN));
}

static void suite_ipv6_ethertype() {
    Pkt p; p.eth(PP_ETHERTYPE_IPV6).fill(46);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.eth_type, uint16_t(PP_ETHERTYPE_IPV6));
    CHECK_EQ(m.l3_off, uint16_t(14));
}

static void suite_single_vlan() {
    // eth(type=0x8100) then tag{vid=100, next=0x0800}
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(100, PP_ETHERTYPE_IPV4).fill(42);
    auto v = p.view();

    pp_meta m; pp_parse(&v, &m);

    CHECK(m.layers & PP_LAYER_VLAN);
    CHECK_EQ(m.vlan_outer, uint16_t(100));
    CHECK_EQ(m.vlan_inner, uint16_t(PP_VLAN_NONE));
    // eth_type must be the ethertype AFTER tag stripping, not the TPID. If this
    // reported 0x8100 the classifier would never see a VLAN'd packet as IP.
    CHECK_EQ(m.eth_type, uint16_t(PP_ETHERTYPE_IPV4));
    // 14 (eth) + 4 (tag) — the tag pushes L3 out by exactly 4 bytes.
    CHECK_EQ(m.l3_off, uint16_t(18));
}

static void suite_qinq_802_1ad() {
    // Provider bridging: outer S-tag 0x88A8, inner C-tag 0x8100.
    Pkt p; p.eth(PP_ETHERTYPE_QINQ)
            .vlan_tag(10, PP_ETHERTYPE_VLAN)     // S-tag, next is a C-tag
            .vlan_tag(20, PP_ETHERTYPE_IPV4)     // C-tag, next is IPv4
            .fill(38);
    auto v = p.view();

    pp_meta m; pp_parse(&v, &m);

    CHECK(m.layers & PP_LAYER_VLAN);
    CHECK_EQ(m.vlan_outer, uint16_t(10));
    CHECK_EQ(m.vlan_inner, uint16_t(20));
    CHECK_EQ(m.eth_type, uint16_t(PP_ETHERTYPE_IPV4));
    CHECK_EQ(m.l3_off, uint16_t(22));            // 14 + 4 + 4
}

static void suite_qinq_legacy_9100() {
    // 0x9100 predates 802.1ad and is still emitted by older gear. Recognising
    // only 0x8100 would silently classify this as "not IP" — no crash, no log,
    // it just stops matching rules. That failure mode is why this test exists.
    Pkt p; p.eth(PP_ETHERTYPE_QINQ9100)
            .vlan_tag(30, PP_ETHERTYPE_IPV4)
            .fill(42);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.vlan_outer, uint16_t(30));
    CHECK_EQ(m.eth_type, uint16_t(PP_ETHERTYPE_IPV4));
}

static void suite_vlan_id_zero_is_legal() {
    // The sentinel bug from T1, now end-to-end. VID 0 is a priority-tagged
    // frame: a real thing that real switches emit. It must be reported as
    // VLAN 0 PRESENT, not as "no VLAN".
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(0, PP_ETHERTYPE_IPV4, /*pcp=*/5).fill(42);
    auto v = p.view();

    pp_meta m; pp_parse(&v, &m);

    CHECK(m.layers & PP_LAYER_VLAN);        // the tag WAS there
    CHECK_EQ(m.vlan_outer, uint16_t(0));    // ...and its ID really is 0
    CHECK_NE(m.vlan_outer, uint16_t(PP_VLAN_NONE));
    CHECK_EQ(m.l3_off, uint16_t(18));       // and it still consumed 4 bytes
}

static void suite_vlan_id_masking() {
    // The VID is the low 12 bits of the TCI; PCP and DEI occupy the top 4. A
    // parser that forgets the mask returns pcp<<13 | vid and is wrong for every
    // frame with a non-zero priority — which is exactly the traffic that
    // matters (voice, control planes).
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(4094, PP_ETHERTYPE_IPV4, /*pcp=*/7).fill(42);
    auto v = p.view();
    pp_meta m; pp_parse(&v, &m);
    CHECK_EQ(m.vlan_outer, uint16_t(4094));   // NOT 0xFFFE
}

// ---------------------------------------------------------------------------
// Malformed / hostile frames
// ---------------------------------------------------------------------------

static void suite_truncated_ethernet() {
    // Every length from 0..13 is a truncated Ethernet header. All must be
    // reported, none may over-read. Sweeping the whole range rather than
    // spot-checking one value is the difference between testing the bound and
    // testing a number near it.
    for (uint32_t n = 0; n < PP_ETH_HLEN; ++n) {
        Pkt p; p.fill(n, 0xAA);
        auto v = p.view();
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK_EQ(rc, int(PP_ERR_TRUNC_L2));
        CHECK_EQ(m.err, uint8_t(PP_ERR_TRUNC_L2));
        CHECK(!(m.layers & PP_LAYER_L2));   // we did NOT decode a header we lack
    }
}

static void suite_truncated_vlan_tag() {
    // Ethernet header says "a VLAN tag follows" and then the capture ends
    // mid-tag. The 4-byte tag needs 4 bytes; 0..3 available must all fail
    // cleanly rather than read whatever is past the buffer.
    for (uint32_t extra = 0; extra < PP_VLAN_HLEN; ++extra) {
        Pkt p; p.eth(PP_ETHERTYPE_VLAN).fill(extra, 0xBB);
        auto v = p.view();
        pp_meta m;
        int rc = pp_parse(&v, &m);
        CHECK_EQ(rc, int(PP_ERR_TRUNC_VLAN));
        CHECK(m.layers & PP_LAYER_L2);      // L2 was fine; the TAG was not
    }
}

static void suite_vlan_bomb_is_bounded() {
    // THE DoS TEST (SPEC §7.8). A frame carrying a long run of 0x8100 tags.
    // `while (is_vlan(type))` would walk every one of them; with the NIC
    // delivering more, that is a remote denial of service — the parser never
    // crashes, it just never keeps up.
    //
    // 100 stacked tags. Real traffic has at most 2.
    Pkt p; p.eth(PP_ETHERTYPE_VLAN);
    for (int i = 0; i < 100; ++i) p.vlan_tag(uint16_t(i + 1), PP_ETHERTYPE_VLAN);
    p.vlan_tag(999, PP_ETHERTYPE_IPV4).fill(20);
    auto v = p.view();

    pp_meta m;
    int rc = pp_parse(&v, &m);

    // Bounded: refused at the cap, not walked to the end.
    CHECK_EQ(rc, int(PP_ERR_TOO_MANY_VLANS));
    CHECK_EQ(m.err, uint8_t(PP_ERR_TOO_MANY_VLANS));
    // The two tags we DID accept are still recorded — a bounded parser keeps
    // what it learned rather than throwing the packet away entirely.
    CHECK_EQ(m.vlan_outer, uint16_t(1));
    CHECK_EQ(m.vlan_inner, uint16_t(2));
}

static void suite_exactly_max_vlans_is_ok() {
    // The cap is 2 and 2 must PASS. Off-by-one in the other direction would
    // reject every legitimate QinQ frame on the network — a bound that is too
    // tight is also a bug, and a much more embarrassing one.
    Pkt p; p.eth(PP_ETHERTYPE_QINQ)
            .vlan_tag(1, PP_ETHERTYPE_VLAN)
            .vlan_tag(2, PP_ETHERTYPE_IPV4)
            .fill(38);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_NE(rc, int(PP_ERR_TOO_MANY_VLANS));
    CHECK_EQ(m.vlan_outer, uint16_t(1));
    CHECK_EQ(m.vlan_inner, uint16_t(2));
}

static void suite_802_3_length_not_ethertype() {
    // A field < 1536 is an 802.3 LENGTH, and LLC/SNAP follows — not an
    // ethertype. Treating 0x0578 (1400) as an ethertype and walking it as IP
    // produces garbage offsets from perfectly valid bytes. We decline instead.
    Pkt p; p.eth(1400).fill(46);
    auto v = p.view();
    pp_meta m;
    int rc = pp_parse(&v, &m);
    CHECK_EQ(rc, int(PP_ERR_UNSUPPORTED_L3));
    CHECK(m.layers & PP_LAYER_L2);
    CHECK_EQ(m.eth_type, uint16_t(1400));
}

static void suite_ethertype_boundary_1536() {
    // The exact boundary. 1535 is a length; 1536 (0x0600) is an ethertype.
    Pkt lo; lo.eth(1535).fill(46);
    auto vlo = lo.view();
    pp_meta mlo; CHECK_EQ(pp_parse(&vlo, &mlo), int(PP_ERR_UNSUPPORTED_L3));

    Pkt hi; hi.eth(1536).fill(46);
    auto vhi = hi.view();
    pp_meta mhi; pp_parse(&vhi, &mhi);
    CHECK_EQ(mhi.eth_type, uint16_t(1536));
    CHECK_EQ(mhi.l3_off, uint16_t(14));   // accepted as an ethertype, L3 located
}

static void suite_caplen_shorter_than_wirelen() {
    // A snaplen-truncated capture: 64 bytes on the wire, 20 captured. The
    // parser must bound every read by CAPLEN and never by wirelen (SPEC §7.9),
    // because wirelen describes bytes we do not have.
    Pkt p; p.eth(PP_ETHERTYPE_VLAN).vlan_tag(7, PP_ETHERTYPE_IPV4).fill(200);
    auto v = p.view(/*caplen=*/18, /*wirelen=*/218);

    pp_meta m;
    pp_parse(&v, &m);

    CHECK_EQ(m.caplen, uint16_t(18));
    CHECK_EQ(m.wirelen, uint16_t(218));
    CHECK(m.caplen < m.wirelen);
    // 18 bytes is exactly enough for eth + one tag, so the VLAN parse succeeds.
    CHECK_EQ(m.vlan_outer, uint16_t(7));
    CHECK_EQ(m.l3_off, uint16_t(18));
}

static void suite_null_and_empty() {
    // Degenerate inputs must return, not crash.
    pp_meta m;

    pp_rawpkt none{};
    none.data = nullptr; none.caplen = 100; none.wirelen = 100;
    CHECK_EQ(pp_parse(&none, &m), int(PP_ERR_TRUNC_L2));   // caplen lies; data is null

    Pkt e;
    auto ev = e.view();
    ev.caplen = 0;
    CHECK_EQ(pp_parse(&ev, &m), int(PP_ERR_TRUNC_L2));
}

static void suite_every_prefix_of_a_valid_frame() {
    // Systematic truncation: take one well-formed QinQ frame and feed every
    // prefix of it. Not one may crash, over-read, or report success it did not
    // earn. This is a hand-rolled stand-in for the fuzzer in T14, and it is the
    // single highest-value test in the file — truncation is where parsers die.
    Pkt p; p.eth(PP_ETHERTYPE_QINQ)
            .vlan_tag(11, PP_ETHERTYPE_VLAN)
            .vlan_tag(22, PP_ETHERTYPE_IPV4)
            .fill(40, 0xCC);

    for (uint32_t n = 0; n <= p.size(); ++n) {
        auto v = p.view(n, uint32_t(p.size()));
        pp_meta m;
        int rc = pp_parse(&v, &m);

        // Whatever the verdict, the invariants hold for every single prefix:
        CHECK(rc >= 0 && rc < PP_ERR__COUNT);          // a known error code
        CHECK(m.l3_off <= m.caplen);                   // never points past what we have
        CHECK(m.caplen <= n);                          // never claims bytes we lack
        if (rc == PP_OK || rc == PP_ERR_UNSUPPORTED_L3)
            CHECK(m.layers & PP_LAYER_L2);             // success implies L2 decoded
    }
}

int main() {
    suite_plain_ethernet();
    suite_ipv6_ethertype();
    suite_single_vlan();
    suite_qinq_802_1ad();
    suite_qinq_legacy_9100();
    suite_vlan_id_zero_is_legal();
    suite_vlan_id_masking();
    suite_truncated_ethernet();
    suite_truncated_vlan_tag();
    suite_vlan_bomb_is_bounded();
    suite_exactly_max_vlans_is_ok();
    suite_802_3_length_not_ethertype();
    suite_ethertype_boundary_1536();
    suite_caplen_shorter_than_wirelen();
    suite_null_and_empty();
    suite_every_prefix_of_a_valid_frame();
    TEST_SUMMARY("test_l2");
}
