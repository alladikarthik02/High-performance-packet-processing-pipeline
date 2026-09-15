// bench — measure the pipeline, and settle the questions the spec deferred.
//
// WHAT THIS EXISTS TO ANSWER:
//   1. "Why batch 32?"          -> sweep it and show the curve (SPEC §4)
//   2. "Why prefetch distance 4?" -> same
//   3. "Is a linear classifier really OK?" -> sweep rule count, find where it
//      stops being OK, and report the crossover rather than assert one
//      (SPEC §7.5)
//
// METHODOLOGY, because a benchmark nobody can criticise is a benchmark nobody
// should believe:
//   - Fixed corpus, replayed from a mmap'd file: identical bytes every run, so
//     a delta is attributable to the code and not to the traffic.
//   - The file is read once into the page cache before timing starts. Otherwise
//     the first run measures the filesystem.
//   - Every configuration is run REPS times and the MEDIAN is reported. Not the
//     mean (one scheduler hiccup skews it) and not the minimum (that is the
//     luckiest run, not a typical one). The min and max are printed too, so the
//     spread is visible and the reader can judge the noise for themselves.
//   - ns/packet from CLOCK_MONOTONIC, NOT cycles/packet: the PMU is not
//     available under virtualization (SPEC §7.6, measured not assumed).
#include "pp/pipeline.h"
#include "pp/parse.h"
#include "pp/classify.h"
#include "pp/arena.h"
#include "pp/source.h"
#include "pp/ruleset.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr int REPS = 7;   // odd, so the median is an actual observation

struct Result {
    double ns_median, ns_min, ns_max;
    double mpps;
    uint64_t packets;
};

// One timed configuration.
Result run(const char* pcap, const pp_ruleset& rs, pp_arena& a,
           int batch, int prefetch, int repeat) {
    std::vector<double> samples;
    uint64_t packets = 0;

    for (int r = 0; r < REPS; ++r) {
        pp_source src{};
        if (pp_source_pcapfile_open(&src, pcap) != 0) {
            std::fprintf(stderr, "bench: %s\n", pp_pcapfile_error());
            std::exit(1);
        }

        // A fresh arena scope per run for the batch arrays, so a long sweep
        // cannot exhaust the arena. The rules keep their original allocation.
        pp_arena run_arena{};
        pp_arena_init(&run_arena, 8 << 20);

        pp_classifier cl{};
        pp_classifier_init(&cl, &rs, &run_arena);

        pp_pipeline p{};
        pp_pipeline_init(&p, &src, &cl, &run_arena, batch, prefetch);

        uint64_t t0 = pp_now_ns();
        for (int k = 0; k < repeat; ++k) {
            if (k) pp_source_pcapfile_rewind(&src);
            while (pp_pipeline_step(&p) > 0) {}
        }
        uint64_t dt = pp_now_ns() - t0;

        packets = p.st.packets;
        if (packets) samples.push_back(double(dt) / double(packets));

        pp_source_close(&src);
        pp_arena_destroy(&run_arena);
    }
    (void)a;

    std::sort(samples.begin(), samples.end());
    Result res{};
    res.ns_median = samples[samples.size() / 2];
    res.ns_min    = samples.front();
    res.ns_max    = samples.back();
    res.mpps      = 1000.0 / res.ns_median;
    res.packets   = packets;
    return res;
}

std::string make_rules(int n) {
    // n rules that all FAIL to match, followed by nothing — so every packet
    // walks the entire list. That is the worst case, and the worst case is what
    // a scan's cost should be quoted at. Quoting the best case (rule 1 matches
    // everything) would measure nothing but the first iteration.
    std::string s = "default accept\n";
    for (int i = 0; i < n; ++i)
        s += "drop tcp 203.0.113.0/24 any -> any " + std::to_string(10000 + i) + "\n";
    return s;
}

void header(const char* title) {
    std::printf("\n%s\n", title);
    for (size_t i = 0; i < std::strlen(title); ++i) std::putchar('=');
    std::putchar('\n');
}

} // namespace

int main(int argc, char** argv) {
    const char* pcap = (argc > 1) ? argv[1] : "pcaps/uniform_tcp.pcap";
    int repeat = (argc > 2) ? std::atoi(argv[2]) : 20;

    std::printf("%s\n", pp_build_info());
    std::printf("corpus: %s, replayed %dx per run, %d runs per config, median reported\n",
                pcap, repeat, REPS);

    // Warm the page cache: the first read of the file would otherwise measure
    // the filesystem rather than the pipeline.
    {
        pp_source s{};
        if (pp_source_pcapfile_open(&s, pcap) != 0) {
            std::fprintf(stderr, "bench: cannot open %s: %s\n", pcap, pp_pcapfile_error());
            return 1;
        }
        pp_rawpkt b[64];
        while (pp_source_next(&s, b, 64) > 0) {}
        pp_source_close(&s);
    }

    pp_arena arena{};
    pp_arena_init(&arena, 64 << 20);

    char err[256];

    // ---------------------------------------------------------------------
    header("1. Batch size sweep  (why 32? — SPEC §4)");
    {
        pp_ruleset rs{};
        std::string r = make_rules(8);
        pp_rules_compile_str(r.c_str(), "b", &arena, &rs, err, sizeof err);

        std::printf("  %6s  %10s  %8s  %14s  %s\n",
                    "batch", "ns/pkt", "Mpps", "[min..max]", "vs batch=1");
        double base = 0;
        for (int b : {1, 2, 4, 8, 16, 32, 64, 128, 256}) {
            Result x = run(pcap, rs, arena, b, PP_PREFETCH_DEFAULT, repeat);
            if (b == 1) base = x.ns_median;
            std::printf("  %6d  %10.1f  %8.3f  [%5.1f..%5.1f]  %+.1f%%\n",
                        b, x.ns_median, x.mpps, x.ns_min, x.ns_max,
                        100.0 * (x.ns_median - base) / base);
        }
    }

    // ---------------------------------------------------------------------
    header("2. Prefetch distance sweep  (0 = off)");
    {
        pp_ruleset rs{};
        std::string r = make_rules(8);
        pp_rules_compile_str(r.c_str(), "p", &arena, &rs, err, sizeof err);

        std::printf("  %8s  %10s  %8s  %14s  %s\n",
                    "distance", "ns/pkt", "Mpps", "[min..max]", "vs off");
        double base = 0;
        for (int d : {0, 1, 2, 4, 8, 16, 32}) {
            Result x = run(pcap, rs, arena, PP_BATCH_DEFAULT, d, repeat);
            if (d == 0) base = x.ns_median;
            std::printf("  %8d  %10.1f  %8.3f  [%5.1f..%5.1f]  %+.1f%%\n",
                        d, x.ns_median, x.mpps, x.ns_min, x.ns_max,
                        100.0 * (x.ns_median - base) / base);
        }
    }

    // ---------------------------------------------------------------------
    header("3. Rule count sweep  (does the linear scan hold up? — SPEC §7.5)");
    {
        std::printf("  Every rule is constructed to FAIL, so each packet walks the\n"
                    "  whole list: this is the worst case, which is the only honest\n"
                    "  thing to quote a linear scan's cost at.\n\n");
        std::printf("  %6s  %8s  %10s  %8s  %12s\n",
                    "rules", "bytes", "ns/pkt", "Mpps", "ns/rule");
        double base = 0;
        for (int n : {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512}) {
            pp_arena ra{}; pp_arena_init(&ra, 16 << 20);
            pp_ruleset rs{};
            std::string r = make_rules(n);
            if (pp_rules_compile_str(r.c_str(), "r", &ra, &rs, err, sizeof err) != 0) {
                std::fprintf(stderr, "  rule compile failed: %s\n", err);
                pp_arena_destroy(&ra);
                continue;
            }
            Result x = run(pcap, rs, ra, PP_BATCH_DEFAULT, PP_PREFETCH_DEFAULT, repeat);
            if (n == 0) base = x.ns_median;
            std::printf("  %6d  %8zu  %10.1f  %8.3f  %12.2f\n",
                        n, n * sizeof(pp_rule), x.ns_median, x.mpps,
                        n ? (x.ns_median - base) / n : 0.0);
            pp_arena_destroy(&ra);
        }
        std::printf("\n  The ns/rule column is the number that matters: as long as the\n"
                    "  ruleset fits in cache it should stay roughly flat. Where it\n"
                    "  starts climbing is where the array outgrew the cache — and that\n"
                    "  is the point at which an index would start to pay for itself.\n");
    }

    pp_arena_destroy(&arena);
    std::printf("\n");
    return 0;
}
