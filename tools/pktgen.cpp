// pktgen — synthesize .pcap corpora.
//
// Why generate rather than ship a captured file:
//   - A real capture cannot be checked into git honestly (privacy, size), and
//     cannot be *explained* — you cannot point at packet 4,912 and say why it
//     is there.
//   - A generated corpus has KNOWN GROUND TRUTH. The benchmark knows exactly
//     how many TCP packets it contains, so "the classifier matched 40,000" can
//     be checked rather than trusted.
//   - It is reproducible bit-for-bit, which is what makes a throughput delta
//     attributable to a code change (SPEC §3.2).
//
// This is C++ and lives in tools/, not the data plane: it runs offline, at
// build time, and may allocate as freely as it likes.
#include "pktbuild.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <random>

using namespace pktbuild;

// ---------------------------------------------------------------------------
// pcap writer
// ---------------------------------------------------------------------------
namespace {

class PcapWriter {
public:
    explicit PcapWriter(const char* path) : f_(std::fopen(path, "wb")) {
        if (!f_) { std::perror(path); std::exit(1); }
        // Global header, little-endian, microsecond timestamps, Ethernet.
        put32(0xa1b2c3d4);  // magic
        put16(2); put16(4); // version 2.4
        put32(0);           // thiszone
        put32(0);           // sigfigs
        put32(65535);       // snaplen
        put32(1);           // linktype = Ethernet
    }
    ~PcapWriter() { if (f_) std::fclose(f_); }

    void packet(const Pkt& p, uint32_t caplen = 0) {
        uint32_t orig = uint32_t(p.size());
        uint32_t incl = caplen ? caplen : orig;
        put32(ts_sec_); put32(ts_usec_);
        put32(incl); put32(orig);
        std::fwrite(p.data(), 1, incl, f_);
        // Monotonic fake clock: 1 us apart. Real timestamps would make the file
        // non-reproducible, and nothing downstream depends on their realism.
        ts_usec_ += 1;
        if (ts_usec_ >= 1000000) { ts_usec_ = 0; ts_sec_++; }
        n_++;
    }

    size_t count() const { return n_; }

private:
    void put16(uint16_t v) { uint8_t b[2] = {uint8_t(v), uint8_t(v>>8)}; std::fwrite(b,1,2,f_); }
    void put32(uint32_t v) {
        uint8_t b[4] = {uint8_t(v), uint8_t(v>>8), uint8_t(v>>16), uint8_t(v>>24)};
        std::fwrite(b,1,4,f_);
    }
    std::FILE* f_ = nullptr;
    uint32_t ts_sec_ = 1700000000, ts_usec_ = 0;
    size_t n_ = 0;
};

uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t(a)<<24) | (uint32_t(b)<<16) | (uint32_t(c)<<8) | d;
}

// ---------------------------------------------------------------------------
// Corpora
// ---------------------------------------------------------------------------

// A mix that looks like a plausible edge link. Deterministic: seeded RNG, so
// the same file is produced byte-for-byte on every machine and every run.
void gen_mixed(const char* path, size_t n) {
    PcapWriter w(path);
    std::mt19937 rng(42);   // fixed seed — reproducibility is the whole point

    for (size_t i = 0; i < n; ++i) {
        uint32_t r = rng() % 100;
        Pkt p;
        if (r < 60) {
            // 60% TCP — the bulk of real traffic
            p.eth(PP_ETHERTYPE_IPV4);
            size_t ip0 = p.size();
            p.ipv4(PP_IPPROTO_TCP, ip4(192,168,1, uint8_t(1 + rng()%254)),
                                   ip4(10,0, uint8_t(rng()%256), uint8_t(1+rng()%254)))
             .tcp(uint16_t(1024 + rng()%64000), (rng()%2) ? 80 : 443,
                  uint8_t((rng()%2) ? PP_TCP_ACK : (PP_TCP_ACK|PP_TCP_PSH)))
             .fill(rng() % 512, 0x41)
             .fix_ipv4_totlen(ip0);
        } else if (r < 80) {
            // 20% UDP
            p.eth(PP_ETHERTYPE_IPV4);
            size_t ip0 = p.size();
            size_t udp0;
            p.ipv4(PP_IPPROTO_UDP, ip4(192,168,1, uint8_t(1+rng()%254)),
                                   ip4(8,8,8,8));
            udp0 = p.size();
            p.udp(uint16_t(1024 + rng()%64000), 53)
             .fill(32 + rng()%128, 0x42)
             .fix_udp_len(udp0)
             .fix_ipv4_totlen(ip0);
        } else if (r < 88) {
            // 8% IPv6/TCP
            p.eth(PP_ETHERTYPE_IPV6);
            size_t ip0 = p.size();
            p.ipv6(PP_IPPROTO_TCP, 0)
             .tcp(uint16_t(1024 + rng()%64000), 443, PP_TCP_ACK)
             .fill(rng()%256, 0x43)
             .fix_ipv6_plen(ip0);
        } else if (r < 93) {
            // 5% VLAN-tagged TCP
            p.eth(PP_ETHERTYPE_VLAN).vlan_tag(uint16_t(100 + rng()%10), PP_ETHERTYPE_IPV4);
            size_t ip0 = p.size();
            p.ipv4(PP_IPPROTO_TCP, ip4(192,168,2, uint8_t(1+rng()%254)), ip4(10,1,1,1))
             .tcp(uint16_t(1024 + rng()%64000), 22, PP_TCP_ACK)
             .fill(rng()%128, 0x44)
             .fix_ipv4_totlen(ip0);
        } else if (r < 96) {
            // 3% ICMP
            p.eth(PP_ETHERTYPE_IPV4);
            size_t ip0 = p.size();
            p.ipv4(PP_IPPROTO_ICMP, ip4(192,168,1,1), ip4(8,8,4,4))
             .icmp(8, 0).fill(56, 0x45)
             .fix_ipv4_totlen(ip0);
        } else if (r < 99) {
            // 3% VXLAN-encapsulated TCP — the tunnel path gets exercised by the
            // benchmark, not just by unit tests
            p.eth(PP_ETHERTYPE_IPV4);
            size_t oip0 = p.size();
            p.ipv4(PP_IPPROTO_UDP, ip4(10,0,0,1), ip4(10,0,0,2));
            size_t oudp0 = p.size();
            p.udp(uint16_t(30000+rng()%1000), PP_UDP_PORT_VXLAN)
             .vxlan(5000 + rng()%16)
             .eth(PP_ETHERTYPE_IPV4);
            size_t iip0 = p.size();
            p.ipv4(PP_IPPROTO_TCP, ip4(172,16,0, uint8_t(1+rng()%254)), ip4(172,16,1,1))
             .tcp(uint16_t(1024+rng()%64000), 8080, PP_TCP_ACK)
             .fill(rng()%256, 0x46)
             .fix_ipv4_totlen(iip0)      // inner IP covers inner TCP + payload
             .fix_udp_len(oudp0)         // outer UDP covers VXLAN + whole inner frame
             .fix_ipv4_totlen(oip0);     // outer IP covers all of it
        } else {
            // 1% ARP — not IP at all. Present so the "we decline to decode
            // this, and that is not an error" path is exercised at volume.
            p.eth(PP_ETHERTYPE_ARP).fill(46, 0x47);
        }
        w.packet(p);
    }
    std::printf("  %-28s %8zu packets\n", path, w.count());
}

// Uniform, minimal TCP packets. The benchmark's control: one code path, no
// branch-prediction noise from a protocol mix, so a change in ns/packet is
// attributable to the parser rather than to which packets happened to come up.
void gen_uniform_tcp(const char* path, size_t n) {
    PcapWriter w(path);
    for (size_t i = 0; i < n; ++i) {
        Pkt p; p.eth(PP_ETHERTYPE_IPV4);
        size_t ip0 = p.size();
        p.ipv4(PP_IPPROTO_TCP, ip4(192,168,1,1), ip4(10,0,0,1))
         .tcp(12345, 80, PP_TCP_ACK)
         .fill(6, 0x41)            // -> 60-byte minimum Ethernet frame
         .fix_ipv4_totlen(ip0);
        w.packet(p);
    }
    std::printf("  %-28s %8zu packets\n", path, w.count());
}

// Every hostile shape the parser is supposed to survive, in one file. Feed this
// to the pipeline and it must not crash, hang, or over-read (T14).
void gen_hostile(const char* path) {
    PcapWriter w(path);

    { Pkt p; p.eth(PP_ETHERTYPE_IPV4); w.packet(p); }                    // L2 only
    { Pkt p; p.fill(3, 0xAA); w.packet(p); }                             // runt
    { Pkt p; p.eth(PP_ETHERTYPE_VLAN); w.packet(p); }                    // VLAN tag missing
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, 0); w.packet(p); }  // IHL=0
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, 15); w.packet(p); } // IHL=15, truncated
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, 5, 9)
              .tcp(1,2); w.packet(p); }                                  // totlen < hlen
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, 5, 60000)
              .tcp(1,2); w.packet(p); }                                  // totlen absurd
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2)
              .tcp(1, 2, PP_TCP_ACK, 0); w.packet(p); }                  // TCP doff=0
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2)
              .tcp(1, 2, PP_TCP_ACK, 15); w.packet(p); }                 // doff beyond capture

    // VLAN stack bomb
    { Pkt p; p.eth(PP_ETHERTYPE_VLAN);
      for (int i = 0; i < 60; ++i) p.vlan_tag(uint16_t(i+1), PP_ETHERTYPE_VLAN);
      p.vlan_tag(999, PP_ETHERTYPE_IPV4).fill(20); w.packet(p); }

    // IPv6 extension header bomb
    { Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_DSTOPTS, 0);
      for (int i = 0; i < 60; ++i) p.ip6_ext(PP_IPPROTO_DSTOPTS, 0);
      p.ip6_ext(PP_IPPROTO_TCP, 0).tcp(1,2); w.packet(p); }

    // IPv6 fragment header with junk in the RESERVED byte
    { Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_FRAGMENT, 0)
              .ip6_frag(PP_IPPROTO_TCP, 0, true, 200).tcp(1,2); w.packet(p); }

    // AH, whose length rule is (len+2)*4 and not (len+1)*8
    { Pkt p; p.eth(PP_ETHERTYPE_IPV6).ipv6(PP_IPPROTO_AH, 0)
              .ip6_ah(PP_IPPROTO_TCP, 1).tcp(1,2); w.packet(p); }

    // VXLAN nesting bomb
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, 1, 2)
              .udp(1, PP_UDP_PORT_VXLAN).vxlan(1)
              .eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_UDP, 1, 2)
              .udp(1, PP_UDP_PORT_VXLAN).vxlan(2)
              .eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2).tcp(1,2);
      w.packet(p); }

    // Later fragment whose payload is crafted to LOOK like a TCP header —
    // the evasion case. A parser that reads it reports ports 31337/31338.
    { Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2, 5, 0xFFFF, 100)
              .tcp(31337, 31338); w.packet(p); }

    // 802.3 length field, not an ethertype
    { Pkt p; p.eth(1400).fill(46); w.packet(p); }

    // A valid packet truncated at EVERY offset — the systematic killer.
    { Pkt full; full.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 1, 2).tcp(1,2).fill(20);
      for (uint32_t k = 1; k <= full.size(); ++k) w.packet(full, k); }

    std::printf("  %-28s %8zu packets\n", path, w.count());
}

} // namespace

int main(int argc, char** argv) {
    const char* dir = (argc > 1) ? argv[1] : "pcaps";
    size_t n = (argc > 2) ? size_t(std::atol(argv[2])) : 50000;

    std::printf("Generating corpora into %s/ (deterministic, seed=42)\n", dir);
    std::string d(dir);
    gen_uniform_tcp((d + "/uniform_tcp.pcap").c_str(), n);
    gen_mixed((d + "/mixed.pcap").c_str(), n);
    gen_hostile((d + "/hostile.pcap").c_str());
    return 0;
}
