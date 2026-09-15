// pktbuild.h — construct packets byte-exactly for tests.
//
// Deliberately low-level. A builder with a `.vlan(100)` method that silently
// fixes up the preceding ethertype would be more convenient and would also hide
// the exact thing these tests exist to check. Here you write the wire bytes you
// mean, in the order they appear on the wire, and the test reads like a packet
// diagram. When a parser test fails, the question is always "what were the
// actual bytes?" — so the bytes are right there in the test.
#pragma once
#include <cstdint>
#include <vector>
#include <initializer_list>
#include "pp/pkt.h"
#include "pp/proto.h"

namespace pktbuild {

class Pkt {
public:
    Pkt& u8(uint8_t v) { b_.push_back(v); return *this; }

    // Big-endian by construction, matching the wire and pp_rd_be16's reading.
    Pkt& be16(uint16_t v) {
        b_.push_back(uint8_t(v >> 8)); b_.push_back(uint8_t(v)); return *this;
    }
    Pkt& be32(uint32_t v) {
        b_.push_back(uint8_t(v >> 24)); b_.push_back(uint8_t(v >> 16));
        b_.push_back(uint8_t(v >> 8));  b_.push_back(uint8_t(v));  return *this;
    }
    Pkt& raw(std::initializer_list<uint8_t> xs) {
        for (uint8_t x : xs) b_.push_back(x);
        return *this;
    }
    Pkt& fill(size_t n, uint8_t v = 0) {
        for (size_t i = 0; i < n; ++i) b_.push_back(v);
        return *this;
    }

    Pkt& mac(uint8_t last) { return raw({0x02, 0x00, 0x00, 0x00, 0x00, last}); }

    // A full Ethernet II header: dst[6] src[6] type[2].
    // `ethertype` is whatever literally goes in the field — 0x8100 when a VLAN
    // tag follows, 0x0800 when IPv4 follows. The caller says what it means.
    Pkt& eth(uint16_t ethertype, uint8_t dst = 0x01, uint8_t src = 0x02) {
        mac(dst); mac(src); return be16(ethertype);
    }

    // One 802.1Q tag body: TCI[2] then the NEXT ethertype[2].
    // Note the TPID is NOT here — it was the preceding ethertype field. That
    // asymmetry is the thing tests need to pin down, so the builder mirrors it
    // rather than smoothing it over.
    Pkt& vlan_tag(uint16_t vid, uint16_t next_ethertype, uint8_t pcp = 0) {
        uint16_t tci = uint16_t((uint16_t(pcp) << PP_VLAN_PCP_SHIFT) |
                                (vid & PP_VLAN_VID_MASK));
        be16(tci); return be16(next_ethertype);
    }

    // ---- L3: IPv4 ----------------------------------------------------------
    // Every field is settable, including the ones a correct sender would never
    // get wrong — because the tests that matter are the ones where a field
    // LIES. `ihl` and `totlen` are independently controllable for exactly that
    // reason: the parser must survive `ihl=0`, `ihl=15`, and a `totlen` that
    // contradicts the captured bytes.
    Pkt& ipv4(uint8_t proto, uint32_t src, uint32_t dst,
              uint8_t ihl = 5, uint16_t totlen = 0xFFFF,
              uint16_t fragword = 0, uint8_t ttl = 64, uint8_t version = 4) {
        size_t start = b_.size();
        u8(uint8_t((version << 4) | (ihl & 0x0F)));
        u8(0);                                   // DSCP/ECN
        be16(totlen == 0xFFFF ? 0 : totlen);     // patched below if defaulted
        be16(0x1234);                            // identification
        be16(fragword);                          // flags(3) | frag offset(13)
        u8(ttl);
        u8(proto);
        be16(0);                                 // checksum: not validated (see test note)
        be32(src);
        be32(dst);
        // Options, if IHL claims more than the 20-byte fixed header. Filled
        // with 0x01 (NOP option) so they are at least plausible.
        if (ihl > 5) fill(size_t(ihl - 5) * 4, 0x01);
        if (totlen == 0xFFFF) {
            // Default: make totlen honest about the fixed+options header.
            uint16_t hl = uint16_t((ihl >= 5 ? ihl : 5) * 4);
            b_[start + 2] = uint8_t(hl >> 8);
            b_[start + 3] = uint8_t(hl);
        }
        return *this;
    }

    // ---- Length back-patching ---------------------------------------------
    //
    // A header's length field describes bytes that do not exist yet when the
    // header is written, so it can only be filled in afterwards. That is not an
    // artifact of this builder — it is why real senders compute checksums and
    // lengths in a second pass too.
    //
    // These exist because tcpdump caught a bug: the generated corpus had
    // totlen = header length, so every packet looked truncated to any reader
    // that TRUSTS the field. pktpipe's parser does not (SPEC §7.9), so its own
    // tests passed happily — an independent reader is what found it. Worth
    // remembering: a test suite that only checks your code against your code
    // agrees with itself by construction.
    Pkt& fix_ipv4_totlen(size_t ip_start) {
        uint16_t tl = uint16_t(b_.size() - ip_start);
        b_[ip_start + 2] = uint8_t(tl >> 8);
        b_[ip_start + 3] = uint8_t(tl);
        return *this;
    }

    // IPv6 "payload length" excludes the 40-byte base header — unlike IPv4's
    // total length, which includes its own header. A real difference between
    // the two protocols and an easy one to get backwards.
    Pkt& fix_ipv6_plen(size_t ip6_start) {
        uint16_t pl = uint16_t(b_.size() - ip6_start - PP_IP6_HLEN);
        b_[ip6_start + 4] = uint8_t(pl >> 8);
        b_[ip6_start + 5] = uint8_t(pl);
        return *this;
    }

    // UDP length INCLUDES the 8-byte UDP header.
    Pkt& fix_udp_len(size_t udp_start) {
        uint16_t ul = uint16_t(b_.size() - udp_start);
        b_[udp_start + 4] = uint8_t(ul >> 8);
        b_[udp_start + 5] = uint8_t(ul);
        return *this;
    }

    // ---- L3: IPv6 ----------------------------------------------------------
    Pkt& ipv6(uint8_t next_hdr, uint16_t payload_len = 0,
              uint8_t hop_limit = 64, uint8_t version = 6) {
        u8(uint8_t((version << 4) | 0));   // version | traffic class hi
        u8(0); be16(0);                    // traffic class lo | flow label
        be16(payload_len);
        u8(next_hdr);
        u8(hop_limit);
        for (int i = 0; i < 4; ++i) be32(i == 3 ? 0x00000001u : 0x20010db8u); // src
        for (int i = 0; i < 4; ++i) be32(i == 3 ? 0x00000002u : 0x20010db8u); // dst
        return *this;
    }

    // A generic IPv6 extension header using the (len+1)*8 rule.
    // `hdr_ext_len` is in 8-byte units EXCLUDING the first 8, so 0 => 8 bytes.
    Pkt& ip6_ext(uint8_t next_hdr, uint8_t hdr_ext_len = 0) {
        u8(next_hdr);
        u8(hdr_ext_len);
        fill(size_t(hdr_ext_len + 1) * 8 - 2, 0x00);   // type-specific data
        return *this;
    }

    // IPv6 fragment header: FIXED 8 bytes. The second byte is RESERVED, not a
    // length — settable here precisely so a test can put junk in it and prove
    // the parser doesn't mistake it for a length.
    Pkt& ip6_frag(uint8_t next_hdr, uint16_t frag_off, bool more = false,
                  uint8_t reserved_byte = 0) {
        u8(next_hdr);
        u8(reserved_byte);
        be16(uint16_t((frag_off << 3) | (more ? 1 : 0)));
        be32(0xAABBCCDD);          // identification
        return *this;
    }

    // Authentication Header: length = (hdr_ext_len + 2) * 4. The odd one out.
    Pkt& ip6_ah(uint8_t next_hdr, uint8_t hdr_ext_len = 1) {
        u8(next_hdr);
        u8(hdr_ext_len);
        fill(size_t(hdr_ext_len + 2) * 4 - 2, 0x00);
        return *this;
    }

    // ---- L4 ---------------------------------------------------------------
    // `doff` is settable independently of reality for the same reason `ihl`
    // was: the tests that matter are the ones where the field lies.
    Pkt& tcp(uint16_t sport, uint16_t dport, uint8_t flags = PP_TCP_ACK,
             uint8_t doff = 5) {
        be16(sport); be16(dport);
        be32(0x1000);            // seq
        be32(0x2000);            // ack
        u8(uint8_t(doff << 4));  // data offset | reserved
        u8(flags);
        be16(65535);             // window
        be16(0);                 // checksum
        be16(0);                 // urgent
        if (doff > 5) fill(size_t(doff - 5) * 4, 0x01);   // options (NOPs)
        return *this;
    }

    Pkt& udp(uint16_t sport, uint16_t dport, uint16_t len = 8) {
        be16(sport); be16(dport); be16(len); be16(0);
        return *this;
    }

    Pkt& icmp(uint8_t type, uint8_t code) {
        u8(type); u8(code); be16(0);
        return *this;
    }

    // ---- Tunnel -----------------------------------------------------------
    // VXLAN header. `flags` defaults to the 'I' bit set (VNI valid); pass 0 to
    // build the "UDP/4789 that isn't really VXLAN" case.
    Pkt& vxlan(uint32_t vni, uint8_t flags = PP_VXLAN_FLAG_VNI) {
        u8(flags); u8(0); u8(0); u8(0);        // flags + reserved
        u8(uint8_t(vni >> 16)); u8(uint8_t(vni >> 8)); u8(uint8_t(vni));
        u8(0);                                  // reserved
        return *this;
    }

    size_t size() const { return b_.size(); }
    const uint8_t* data() const { return b_.data(); }

    // Sentinel for "argument not supplied".
    //
    // This was `= 0` with a `caplen ? caplen : size()` default, and it was a
    // BUG — caplen 0 is a perfectly legal capture ("we got nothing"), so the
    // helper silently rewrote view(0) into "the whole packet" and the
    // every-prefix test's n=0 case checked the wrong thing entirely.
    //
    // It is exactly the mistake PP_VLAN_NONE exists to avoid: 0 is a value the
    // domain can produce, so 0 cannot mean "absent". Same rule, and knowing the
    // rule evidently does not confer immunity to it. UINT32_MAX cannot be a
    // real capture length, so it can carry the meaning.
    static constexpr uint32_t UNSET = UINT32_MAX;

    // A capture of this packet. By default caplen == "we got all of it".
    // Pass a smaller caplen to simulate a snaplen-truncated capture, and a
    // larger wirelen to simulate a packet longer on the wire than we captured.
    pp_rawpkt view(uint32_t caplen = UNSET, uint32_t wirelen = UNSET) const {
        pp_rawpkt p{};
        p.data    = b_.data();
        p.caplen  = (caplen  == UNSET) ? uint32_t(b_.size()) : caplen;
        p.wirelen = (wirelen == UNSET) ? p.caplen            : wirelen;
        p.ts_ns   = 0;
        return p;
    }

private:
    std::vector<uint8_t> b_;
};

} // namespace pktbuild
