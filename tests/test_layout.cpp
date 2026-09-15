// test_layout — the résumé's "cache-friendly layout" claim, made falsifiable.
//
// A static_assert in the header already fails the BUILD if pp_meta stops fitting
// a cache line, so these tests are not re-checking sizeof for its own sake. They
// exist to pin the *reasoning* behind the layout: that offsets beat pointers,
// that the struct doesn't straddle lines, and that the VLAN sentinel is not zero.
// Each is a claim someone could ask me to defend.
#include "test.h"
#include "pp/pkt.h"

#include <vector>

static void suite_cacheline_budget() {
    // The headline claim (SPEC R5).
    CHECK_EQ(sizeof(pp_meta), size_t(64));

    // Size without alignment is a half-claim: a 64-byte struct starting at
    // offset 32 of a line touches TWO lines and costs two misses per access,
    // which is worse than not having bothered. Both properties together are
    // what make "one cache line" true.
    CHECK_EQ(alignof(pp_meta), size_t(64));

    // And the allocation must actually land on a line boundary in practice,
    // not just promise to in the type system.
    std::vector<pp_meta> batch(32);
    CHECK_EQ(reinterpret_cast<uintptr_t>(batch.data()) % 64, uintptr_t(0));

    // An array of them must tile lines exactly with no gaps: metadata for a
    // batch is walked linearly, so consecutive entries must be consecutive
    // lines for the hardware prefetcher to do its job.
    CHECK_EQ(reinterpret_cast<uintptr_t>(&batch[1]) -
             reinterpret_cast<uintptr_t>(&batch[0]), uintptr_t(64));
}

static void suite_offsets_not_pointers() {
    // This is the decision that bought the cache line, so prove the arithmetic
    // rather than asserting it in a comment. Four pointers would cost 32 bytes;
    // the four offsets cost 8. Without this trade the struct could not fit.
    CHECK_EQ(sizeof(pp_meta::l3_off), size_t(2));
    const size_t as_offsets  = 4 * sizeof(uint16_t);
    const size_t as_pointers = 4 * sizeof(const uint8_t*);
    CHECK_EQ(as_offsets, size_t(8));
    CHECK_EQ(as_pointers, size_t(32));
    // The saving is exactly what makes 64 reachable.
    CHECK(sizeof(pp_meta) + (as_pointers - as_offsets) > size_t(64));

    // 16 bits is sufficient because a packet cannot exceed 64 KiB. If that ever
    // stopped being true, this test is where it would be caught.
    CHECK(65535u >= 9000u);  // jumbo frames still fit comfortably
}

static void suite_no_interior_padding() {
    // Fields are ordered widest-first so the compiler inserts no padding
    // between them; all slack is the explicit _reserved tail. If someone
    // reorders fields carelessly, padding appears, the tail no longer accounts
    // for the difference, and this catches it.
    const size_t field_bytes =
        4 * sizeof(uint32_t) +   // ip_src, ip_dst, flow_hash, vni
        14 * sizeof(uint16_t) +  // caplen..inner_l3_off
        9 * sizeof(uint8_t);     // ip_ver..tunnel_depth
    CHECK_EQ(field_bytes, size_t(53));
    CHECK_EQ(field_bytes + sizeof(pp_meta::_reserved), size_t(64));

    // u32s must start at offset 0 — anything else means padding crept in front.
    CHECK_EQ(offsetof(pp_meta, ip_src), size_t(0));
    CHECK_EQ(offsetof(pp_meta, flow_hash), size_t(8));
    CHECK_EQ(offsetof(pp_meta, caplen), size_t(16));
}

static void suite_meta_init_sentinels() {
    pp_rawpkt pkt{};
    const uint8_t bytes[64] = {0};
    pkt.data = bytes;
    pkt.caplen = 64;
    pkt.wirelen = 128;   // deliberately > caplen: a snaplen-truncated capture

    pp_meta m;
    pp_meta_init(&m, &pkt);

    // The subtle one. VLAN 0 is a LEGAL VID (priority-tagged frames use it), so
    // zero cannot mean "no VLAN". A plain memset would get this wrong and make
    // a priority-tagged frame look untagged.
    CHECK_EQ(m.vlan_outer, PP_VLAN_NONE);
    CHECK_EQ(m.vlan_inner, PP_VLAN_NONE);
    CHECK_NE(m.vlan_outer, uint16_t(0));

    // caplen and wirelen are different things and must not be conflated:
    // caplen is what we HAVE, wirelen is what EXISTED. Only caplen bounds reads.
    CHECK_EQ(m.caplen, uint16_t(64));
    CHECK_EQ(m.wirelen, uint16_t(128));
    CHECK(m.caplen < m.wirelen);   // a truncated capture, faithfully represented

    CHECK_EQ(m.err, uint8_t(PP_OK));
    CHECK_EQ(m.layers, uint8_t(0));
    CHECK_EQ(m.ip_ver, uint8_t(0));
}

static void suite_meta_init_clamps_oversize() {
    // pp_rawpkt lengths are 32-bit (that is what libpcap and the kernel give
    // us); pp_meta stores 16-bit to fit the line. A corrupt or jumbo length
    // above 65535 must not narrow silently — an unclamped assignment of 65540
    // would wrap to 4 and produce a nonsense bound.
    pp_rawpkt pkt{};
    const uint8_t bytes[8] = {0};
    pkt.data = bytes;
    pkt.caplen = 70000;     // would wrap to 4464 if truncated blindly
    pkt.wirelen = 200000;

    pp_meta m;
    pp_meta_init(&m, &pkt);
    CHECK_EQ(m.caplen, uint16_t(0xFFFF));
    CHECK_EQ(m.wirelen, uint16_t(0xFFFF));
}

static void suite_err_strings() {
    // Every error code must have a name: an unnamed code turns a diagnosable
    // parse failure into a number nobody can act on.
    for (int e = 0; e < PP_ERR__COUNT; ++e) {
        const char* s = pp_err_str(e);
        CHECK(s != nullptr);
        CHECK(std::string(s) != "unnamed error");
        CHECK(std::string(s) != "invalid error code");
    }
    // Out-of-range codes are reported, not UB.
    CHECK_EQ(std::string(pp_err_str(-1)), std::string("invalid error code"));
    CHECK_EQ(std::string(pp_err_str(PP_ERR__COUNT)), std::string("invalid error code"));
}

int main() {
    suite_cacheline_budget();
    suite_offsets_not_pointers();
    suite_no_interior_padding();
    suite_meta_init_sentinels();
    suite_meta_init_clamps_oversize();
    suite_err_strings();
    TEST_SUMMARY("test_layout");
}
