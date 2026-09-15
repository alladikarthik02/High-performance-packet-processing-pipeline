// test_pcap — the deterministic replay backend.
//
// This backend is the measurement baseline for the whole project, so its
// correctness matters more than its cleverness: if it silently drops packets or
// mis-reads lengths, every benchmark number downstream is wrong and nothing
// tells you.
#include "test.h"
#include "pktbuild.h"
#include "pp/source.h"
#include "pp/parse.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

using namespace pktbuild;

// ---------------------------------------------------------------------------
// A minimal pcap writer, so tests can build files byte-exactly — including
// malformed ones, which is the point.
// ---------------------------------------------------------------------------
namespace {

struct TmpPcap {
    std::string path;
    std::vector<uint8_t> buf;

    explicit TmpPcap(const char* tag) {
        char t[64];
        std::snprintf(t, sizeof t, "/tmp/pptest_%s_%d.pcap", tag, int(getpid()));
        path = t;
    }
    ~TmpPcap() { ::unlink(path.c_str()); }

    void u16(uint16_t v) { buf.push_back(uint8_t(v)); buf.push_back(uint8_t(v>>8)); }
    void u32(uint32_t v) {
        buf.push_back(uint8_t(v));       buf.push_back(uint8_t(v>>8));
        buf.push_back(uint8_t(v>>16));   buf.push_back(uint8_t(v>>24));
    }
    void u32be(uint32_t v) {
        buf.push_back(uint8_t(v>>24));   buf.push_back(uint8_t(v>>16));
        buf.push_back(uint8_t(v>>8));    buf.push_back(uint8_t(v));
    }

    // Little-endian global header (the common case).
    void ghdr(uint32_t magic = 0xa1b2c3d4, uint32_t linktype = 1) {
        u32(magic); u16(2); u16(4); u32(0); u32(0); u32(65535); u32(linktype);
    }
    // Big-endian global header: a capture written on a big-endian machine.
    void ghdr_be(uint32_t magic = 0xa1b2c3d4, uint32_t linktype = 1) {
        u32be(magic);
        buf.push_back(0); buf.push_back(2);   // major, BE
        buf.push_back(0); buf.push_back(4);   // minor, BE
        u32be(0); u32be(0); u32be(65535); u32be(linktype);
    }

    void rec(const Pkt& p, uint32_t incl = 0xFFFFFFFF, uint32_t orig = 0xFFFFFFFF) {
        uint32_t i = (incl == 0xFFFFFFFF) ? uint32_t(p.size()) : incl;
        uint32_t o = (orig == 0xFFFFFFFF) ? uint32_t(p.size()) : orig;
        u32(1700000000); u32(0); u32(i); u32(o);
        for (size_t k = 0; k < i && k < p.size(); ++k) buf.push_back(p.data()[k]);
    }
    void rec_be(const Pkt& p) {
        u32be(1700000000); u32be(0); u32be(uint32_t(p.size())); u32be(uint32_t(p.size()));
        for (size_t k = 0; k < p.size(); ++k) buf.push_back(p.data()[k]);
    }
    // Write raw bytes, for building deliberately broken records.
    void raw(std::initializer_list<uint8_t> xs) { for (uint8_t x : xs) buf.push_back(x); }

    const char* write() {
        std::FILE* f = std::fopen(path.c_str(), "wb");
        if (f) { std::fwrite(buf.data(), 1, buf.size(), f); std::fclose(f); }
        return path.c_str();
    }
};

Pkt sample_tcp(uint16_t sport) {
    Pkt p; p.eth(PP_ETHERTYPE_IPV4).ipv4(PP_IPPROTO_TCP, 0xC0A80101, 0x08080808)
            .tcp(sport, 80, PP_TCP_ACK).fill(6);
    return p;
}

} // namespace

// ---------------------------------------------------------------------------

static void suite_read_back_what_we_wrote() {
    TmpPcap t("basic");
    t.ghdr();
    for (uint16_t i = 0; i < 10; ++i) t.rec(sample_tcp(uint16_t(1000 + i)));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);

    pp_rawpkt batch[32];
    int n = pp_source_next(&s, batch, 32);
    CHECK_EQ(n, 10);

    // Every packet must round-trip through the file AND the parser.
    for (int i = 0; i < n; ++i) {
        pp_meta m;
        CHECK_EQ(pp_parse(&batch[i], &m), int(PP_OK));
        CHECK_EQ(m.sport, uint16_t(1000 + i));
        CHECK_EQ(m.dport, uint16_t(80));
    }

    CHECK_EQ(pp_source_next(&s, batch, 32), 0);   // clean EOF

    pp_capture_stats st;
    pp_source_stats(&s, &st);
    CHECK_EQ(st.packets, uint64_t(10));
    CHECK_EQ(st.truncated, uint64_t(0));

    pp_source_close(&s);
}

static void suite_batching_boundaries() {
    // 10 packets pulled 3 at a time: 3,3,3,1,0. Off-by-one in the batch loop
    // shows up here as a lost or duplicated packet.
    TmpPcap t("batch");
    t.ghdr();
    for (int i = 0; i < 10; ++i) t.rec(sample_tcp(uint16_t(2000 + i)));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);

    pp_rawpkt batch[3];
    int total = 0, n;
    std::vector<uint16_t> ports;
    while ((n = pp_source_next(&s, batch, 3)) > 0) {
        CHECK(n <= 3);
        for (int i = 0; i < n; ++i) {
            pp_meta m; pp_parse(&batch[i], &m);
            ports.push_back(m.sport);
        }
        total += n;
    }
    CHECK_EQ(total, 10);
    CHECK_EQ(ports.size(), size_t(10));
    // ...and in order, with none dropped or repeated.
    for (int i = 0; i < 10; ++i) CHECK_EQ(ports[size_t(i)], uint16_t(2000 + i));

    pp_source_close(&s);
}

static void suite_zero_copy_points_into_the_mapping() {
    // The backend's headline property: pp_rawpkt.data points straight into the
    // mmap'd file, not into a copy. Two packets from one batch must therefore
    // be at increasing addresses within one contiguous region — which is only
    // true if nothing was copied.
    TmpPcap t("zerocopy");
    t.ghdr();
    for (int i = 0; i < 4; ++i) t.rec(sample_tcp(uint16_t(3000 + i)));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[4];
    CHECK_EQ(pp_source_next(&s, b, 4), 4);

    for (int i = 1; i < 4; ++i) {
        CHECK(b[i].data > b[i-1].data);
        // Consecutive records are exactly (16-byte record header + caplen) apart.
        ptrdiff_t gap = b[i].data - b[i-1].data;
        CHECK_EQ(gap, ptrdiff_t(16 + b[i-1].caplen));
    }
    pp_source_close(&s);
}

static void suite_caplen_vs_wirelen() {
    // A snaplen-truncated capture: the file says "60 on the wire, 20 captured".
    // Conflating the two is how a parser reads 40 bytes it does not have.
    TmpPcap t("snap");
    t.ghdr();
    Pkt p = sample_tcp(4000);
    t.rec(p, /*incl=*/20, /*orig=*/uint32_t(p.size()));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[1];
    CHECK_EQ(pp_source_next(&s, b, 1), 1);
    CHECK_EQ(b[0].caplen, uint32_t(20));
    CHECK_EQ(b[0].wirelen, uint32_t(p.size()));
    CHECK(b[0].caplen < b[0].wirelen);

    pp_capture_stats st; pp_source_stats(&s, &st);
    CHECK_EQ(st.truncated, uint64_t(1));

    // ...and the parser must survive it, bounded by caplen.
    pp_meta m;
    int rc = pp_parse(&b[0], &m);
    CHECK_EQ(rc, int(PP_ERR_TRUNC_L3));   // 20 bytes: eth + 6 of IP
    CHECK_EQ(m.caplen, uint16_t(20));

    pp_source_close(&s);
}

static void suite_big_endian_file() {
    // A capture written on a big-endian machine, read on this little-endian
    // one. Completely normal, and the reason the reader picks its field-read
    // function at runtime instead of at compile time.
    TmpPcap t("bigendian");
    t.ghdr_be();
    for (int i = 0; i < 3; ++i) t.rec_be(sample_tcp(uint16_t(5000 + i)));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[4];
    CHECK_EQ(pp_source_next(&s, b, 4), 3);
    for (int i = 0; i < 3; ++i) {
        pp_meta m;
        CHECK_EQ(pp_parse(&b[i], &m), int(PP_OK));
        CHECK_EQ(m.sport, uint16_t(5000 + i));   // decoded despite the byte order
    }
    pp_source_close(&s);
}

static void suite_nanosecond_magic() {
    TmpPcap t("nano");
    t.ghdr(0xa1b23c4d);       // ns-resolution magic
    t.rec(sample_tcp(6000));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[1];
    CHECK_EQ(pp_source_next(&s, b, 1), 1);
    // ts_sub was written as 0, so the only observable is that it opened at all
    // and that the seconds survived — the point is the magic was RECOGNISED
    // rather than rejected.
    CHECK_EQ(b[0].ts_ns / 1000000000ull, uint64_t(1700000000));
    pp_source_close(&s);
}

// ---------------------------------------------------------------------------
// Broken files. A pcap on disk is untrusted input exactly like a packet is.
// ---------------------------------------------------------------------------

static void suite_rejects_non_pcap() {
    TmpPcap t("notpcap");
    t.raw({'h','e','l','l','o',' ','w','o','r','l','d','!'});
    t.buf.resize(64, 0);
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), -1);
    CHECK(std::string(pp_pcapfile_error()).find("not a pcap") != std::string::npos);
}

static void suite_rejects_too_short() {
    TmpPcap t("short");
    t.raw({0xd4, 0xc3, 0xb2});      // 3 bytes: not even a global header
    t.write();
    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), -1);
}

static void suite_rejects_cooked_mode() {
    // `tcpdump -i any` writes linktype 113 (LINUX_SLL), which has a 16-byte
    // pseudo-header where Ethernet would be. Parsing it as Ethernet does not
    // fail — it produces plausible garbage, which is the worst outcome. Refuse
    // it at the door, with a message that names the actual mistake.
    TmpPcap t("cooked");
    t.ghdr(0xa1b2c3d4, /*linktype=*/113);
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), -1);
    std::string e = pp_pcapfile_error();
    CHECK(e.find("not Ethernet") != std::string::npos);
    CHECK(e.find("cooked") != std::string::npos);   // tells the user WHY
}

static void suite_truncated_final_record() {
    // What every ^C'd tcpdump produces: a record header claiming N bytes with
    // fewer than N actually present. Must stop cleanly, NOT hand out a
    // pp_rawpkt pointing past the end of the mapping.
    TmpPcap t("cut");
    t.ghdr();
    t.rec(sample_tcp(7000));                 // one good packet
    Pkt p = sample_tcp(7001);
    t.u32(1700000000); t.u32(0);
    t.u32(uint32_t(p.size()));               // claims the full length...
    t.u32(uint32_t(p.size()));
    for (size_t k = 0; k < 10; ++k) t.buf.push_back(p.data()[k]);  // ...but only 10 bytes
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[8];
    int n = pp_source_next(&s, b, 8);
    CHECK_EQ(n, 1);                          // the good one, and only the good one
    pp_capture_stats st; pp_source_stats(&s, &st);
    CHECK_EQ(st.errors, uint64_t(1));        // and the bad one was COUNTED
    pp_source_close(&s);
}

static void suite_absurd_caplen_is_refused() {
    // A record claiming a 4 GiB packet. Trusting it means a pointer 4 GiB past
    // the mapping.
    TmpPcap t("absurd");
    t.ghdr();
    t.u32(1700000000); t.u32(0);
    t.u32(0xFFFFFFF0u);      // incl_len: absurd
    t.u32(0xFFFFFFF0u);
    t.buf.resize(t.buf.size() + 40, 0xCC);
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[4];
    CHECK_EQ(pp_source_next(&s, b, 4), 0);   // refused, no packet handed out
    pp_capture_stats st; pp_source_stats(&s, &st);
    CHECK_EQ(st.errors, uint64_t(1));
    pp_source_close(&s);
}

static void suite_empty_file_is_valid() {
    // A header and no packets is a perfectly legal pcap. tcpdump writes one
    // when nothing matched the filter.
    TmpPcap t("empty");
    t.ghdr();
    t.write();
    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);
    pp_rawpkt b[4];
    CHECK_EQ(pp_source_next(&s, b, 4), 0);
    pp_source_close(&s);
}

static void suite_rewind_is_exact() {
    // Benchmarks replay the same corpus repeatedly; re-opening per iteration
    // would measure the filesystem instead of the code. So rewind must give
    // byte-identical results, or run-to-run comparisons are meaningless.
    TmpPcap t("rewind");
    t.ghdr();
    for (int i = 0; i < 5; ++i) t.rec(sample_tcp(uint16_t(8000 + i)));
    t.write();

    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, t.path.c_str()), 0);

    pp_rawpkt b[8];
    int n1 = pp_source_next(&s, b, 8);
    const uint8_t* first_ptr = b[0].data;
    CHECK_EQ(n1, 5);

    pp_source_pcapfile_rewind(&s);
    int n2 = pp_source_next(&s, b, 8);
    CHECK_EQ(n2, 5);
    CHECK(b[0].data == first_ptr);     // same bytes, same address, same everything

    pp_capture_stats st; pp_source_stats(&s, &st);
    CHECK_EQ(st.packets, uint64_t(5));  // stats reset too, not accumulated

    pp_source_close(&s);
}

static void suite_missing_file() {
    pp_source s{};
    CHECK_EQ(pp_source_pcapfile_open(&s, "/nonexistent/nope.pcap"), -1);
}

int main() {
    suite_read_back_what_we_wrote();
    suite_batching_boundaries();
    suite_zero_copy_points_into_the_mapping();
    suite_caplen_vs_wirelen();
    suite_big_endian_file();
    suite_nanosecond_magic();
    suite_rejects_non_pcap();
    suite_rejects_too_short();
    suite_rejects_cooked_mode();
    suite_truncated_final_record();
    suite_absurd_caplen_is_refused();
    suite_empty_file_is_valid();
    suite_rewind_is_exact();
    suite_missing_file();
    TEST_SUMMARY("test_pcap");
}
