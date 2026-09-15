/* main.c — the pktpipe CLI.
 *
 *   pktpipe --pcap FILE   --rules FILE [--batch N] [--prefetch N] [--repeat N]
 *   pktpipe --iface NAME  --rules FILE [--mode mmap|recvfrom] [--count N]
 *
 * The same pipeline either way: the source is behind a vtable, so parse and
 * classify neither know nor care whether the bytes came from a file mapping or
 * from a kernel ring (SPEC §3.2).
 */
#define _DEFAULT_SOURCE

#include "pp/pipeline.h"
#include "pp/parse.h"
#include "pp/classify.h"
#include "pp/arena.h"
#include "pp/source.h"
#include "pp/ruleset.h"

#ifdef __linux__
#  include "pp/afpacket.h"
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(void)
{
    fprintf(stderr,
"pktpipe — a high-performance packet processing pipeline\n"
"\n"
"  pktpipe --pcap FILE --rules FILE [options]      replay a capture\n"
#ifdef __linux__
"  pktpipe --iface NAME --rules FILE [options]     capture live (needs CAP_NET_RAW)\n"
#endif
"\n"
"Options:\n"
"  --rules FILE        rule file (required)\n"
"  --batch N           packets per burst (default %d)\n"
"  --prefetch N        software prefetch distance, 0 = off (default %d)\n"
"  --repeat N          replay the pcap N times (benchmarking)\n"
#ifdef __linux__
"  --mode M            mmap | recvfrom   (default mmap)\n"
"  --count N           stop after N packets\n"
"  --no-promisc        do not enable promiscuous mode\n"
#endif
"  --quiet             stats only\n"
"\n", PP_BATCH_DEFAULT, PP_PREFETCH_DEFAULT);
}

static void report(const pp_pipeline *p, const pp_ruleset *rs,
                   const pp_classifier *cl, const pp_capture_stats *cap,
                   const char *src_name)
{
    const pp_pipeline_stats *st = &p->st;

    printf("\n=== pktpipe ===\n");
    printf("  %s\n", pp_build_info());
    printf("  source          : %s\n", src_name);
    printf("  batch / prefetch: %d / %d\n", p->batch_size, p->prefetch_dist);

    printf("\n--- throughput ---\n");
    double secs = (double)st->ns_total / 1e9;
    printf("  packets         : %llu\n", (unsigned long long)st->packets);
    printf("  bytes           : %llu\n", (unsigned long long)st->bytes);
    printf("  batches         : %llu (avg %.1f pkt/batch)\n",
           (unsigned long long)st->batches,
           st->batches ? (double)st->packets / (double)st->batches : 0.0);

    if (secs > 0 && st->packets) {
        printf("  elapsed         : %.3f s\n", secs);

        /* "Rate" means two different things depending on the source, and saying
         * so is the whole point of this branch.
         *
         * REPLAY: the source never blocks, so elapsed IS working time and
         *   packets/elapsed is genuinely our processing throughput.
         *
         * LIVE: elapsed is dominated by waiting for the sender. packets/elapsed
         *   measures how fast the TRAFFIC arrived — a real number, but a fact
         *   about the network, not about this code. Reporting it as our
         *   throughput was a bug: on a link idle for 0.95 s it printed
         *   "0.021 Mpps / 48,720 ns per packet", which reads as a catastrophic
         *   result and is actually a measurement error.
         *
         * So the label changes with the meaning, and per-packet cost comes from
         * ns_busy — which excludes the blocking source call entirely. */
        if (st->ns_busy) {
            double busy = (double)st->ns_busy / 1e9;
            printf("  offered rate    : %.3f Mpps   (how fast traffic ARRIVED — the sender's pace,\n"
                   "                                  not ours; elapsed includes idle poll())\n",
                   (double)st->packets / secs / 1e6);
            printf("  busy time       : %.3f s  (%.1f%% of elapsed; the rest was waiting)\n",
                   busy, 100.0 * busy / secs);
            printf("  PROCESSING rate : %.3f Mpps   <- what this code can actually do\n",
                   (double)st->packets / busy / 1e6);
            printf("  per packet      : %.1f ns  (parse+classify only)\n",
                   (double)st->ns_busy / (double)st->packets);
        } else {
            printf("  rate            : %.3f Mpps\n", (double)st->packets / secs / 1e6);
            printf("  throughput      : %.2f Gbps (wire)\n",
                   (double)st->bytes * 8.0 / secs / 1e9);
            /* ns/packet, NOT cycles/packet: the PMU is not available under
             * virtualization, so a cycle count could not be honestly produced
             * here (SPEC §7.6). This number is real and is what we optimize.
             *
             * NOTE: on a COLD replay this is dominated by page faults on the
             * mmap'd file, not by the code — see --repeat and docs/CHALLENGES.md. */
            printf("  per packet      : %.1f ns\n", (double)st->ns_total / (double)st->packets);
        }
    }

    printf("\n--- capture ---\n");
    printf("  delivered       : %llu\n", (unsigned long long)cap->packets);
    printf("  snaplen-cut     : %llu\n", (unsigned long long)cap->truncated);
    printf("  source errors   : %llu\n", (unsigned long long)cap->errors);
    /* Drops are printed unconditionally, including when zero. A capture tool
     * that only mentions drops when it noticed some is a capture tool you
     * cannot trust the numbers from. */
    printf("  KERNEL DROPS    : %llu", (unsigned long long)cap->kernel_drops);
    if (cap->kernel_drops && (cap->packets + cap->kernel_drops))
        printf("   (%.2f%% of offered traffic never reached us)",
               100.0 * (double)cap->kernel_drops /
               (double)(cap->packets + cap->kernel_drops));
    printf("\n");

    printf("\n--- parse ---\n");
    printf("  %-34s %llu\n", "ok", (unsigned long long)st->parse_err[PP_OK]);
    for (int e = 1; e < PP_ERR__COUNT; e++)
        if (st->parse_err[e])
            printf("  %-34s %llu\n", pp_err_str(e), (unsigned long long)st->parse_err[e]);

    printf("\n--- verdicts ---\n");
    for (int i = 0; i < PP_ACTION__COUNT; i++)
        if (st->action[i])
            printf("  %-34s %llu\n", pp_action_str(i), (unsigned long long)st->action[i]);

    if (rs->n) {
        printf("\n--- rule hits ---\n");
        for (uint32_t i = 0; i < rs->n; i++)
            printf("  rule %-3u %-26s %llu\n", pp_rule_id(i),
                   pp_action_str(pp_rule_action(&rs->rules[i])),
                   (unsigned long long)cl->hits[i]);
    }
    printf("  %-34s %llu\n", "(default)", (unsigned long long)cl->n_default);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL, *rules_path = NULL, *iface = NULL;
    int batch = PP_BATCH_DEFAULT, prefetch = PP_PREFETCH_DEFAULT;
    int repeat = 1, quiet = 0, promisc = 1;
    long count_limit = 0;
#ifdef __linux__
    pp_afp_mode mode = PP_AFP_MMAP;
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(), exit(2), ""))
        if      (!strcmp(a, "--pcap"))     pcap_path  = NEXT();
        else if (!strcmp(a, "--rules"))    rules_path = NEXT();
        else if (!strcmp(a, "--iface"))    iface      = NEXT();
        else if (!strcmp(a, "--batch"))    batch      = atoi(NEXT());
        else if (!strcmp(a, "--prefetch")) prefetch   = atoi(NEXT());
        else if (!strcmp(a, "--repeat"))   repeat     = atoi(NEXT());
        else if (!strcmp(a, "--count"))    count_limit= atol(NEXT());
        else if (!strcmp(a, "--quiet"))    quiet      = 1;
        else if (!strcmp(a, "--no-promisc")) promisc  = 0;
#ifdef __linux__
        else if (!strcmp(a, "--mode")) {
            const char *m = NEXT();
            if      (!strcmp(m, "mmap"))     mode = PP_AFP_MMAP;
            else if (!strcmp(m, "recvfrom")) mode = PP_AFP_RECVFROM;
            else { fprintf(stderr, "unknown mode '%s'\n", m); return 2; }
        }
#endif
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else { fprintf(stderr, "unknown option '%s'\n\n", a); usage(); return 2; }
        #undef NEXT
    }

    if (!rules_path || (!pcap_path && !iface)) { usage(); return 2; }

    /* ONE arena for everything: rules, hit counters, batch arrays. Sized once,
     * up front. After this point the process does not allocate (R6/T9). */
    pp_arena arena;
    if (pp_arena_init(&arena, 32u << 20) != 0) {
        perror("arena");
        return 1;
    }

    pp_ruleset rs;
    char err[256];
    if (pp_rules_compile_file(rules_path, &arena, &rs, err, sizeof err) != 0) {
        fprintf(stderr, "rule error: %s\n", err);
        return 1;
    }
    if (!quiet)
        fprintf(stderr, "loaded %u rules from %s (default %s)\n",
                rs.n, rules_path, pp_action_str(rs.default_action));

    pp_classifier cl;
    if (pp_classifier_init(&cl, &rs, &arena) != 0) {
        fprintf(stderr, "classifier: arena exhausted\n");
        return 1;
    }

    pp_source src;
    char src_name[128];

    if (pcap_path) {
        if (pp_source_pcapfile_open(&src, pcap_path) != 0) {
            fprintf(stderr, "pcap: %s\n", pp_pcapfile_error());
            return 1;
        }
        snprintf(src_name, sizeof src_name, "pcapfile:%s%s", pcap_path,
                 repeat > 1 ? " (repeated)" : "");
    } else {
#ifdef __linux__
        pp_afp_cfg cfg;
        pp_afp_cfg_default(&cfg);
        cfg.mode    = mode;
        cfg.promisc = promisc;
        if (pp_source_afpacket_open(&src, iface, &cfg) != 0) {
            fprintf(stderr, "afpacket: %s\n", pp_afp_error());
            return 1;
        }
        snprintf(src_name, sizeof src_name, "afpacket:%s mode=%s ring=%uMiB(%ux%uMiB)",
                 iface, mode == PP_AFP_MMAP ? "mmap" : "recvfrom",
                 (cfg.block_size * cfg.block_nr) >> 20, cfg.block_nr,
                 cfg.block_size >> 20);
        if (!quiet) fprintf(stderr, "capturing on %s...\n", src_name);
#else
        fprintf(stderr, "live capture requires Linux (AF_PACKET)\n");
        return 1;
#endif
    }

    pp_pipeline pipe;
    if (pp_pipeline_init(&pipe, &src, &cl, &arena, batch, prefetch) != 0) {
        fprintf(stderr, "pipeline: arena exhausted\n");
        return 1;
    }

    /* Live capture only. On a live link the process is blocked in poll() most
     * of the time, so two clock_gettime() calls per batch are free — and
     * ns_busy is the ONLY honest way to report per-packet cost there. On a
     * replay the source never blocks, elapsed already IS working time, and the
     * ~1.6 ns/packet of timing overhead would corrupt the number it measures. */
    pipe.measure_busy = iface ? 1 : 0;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint64_t t0 = pp_now_ns();
    for (int r = 0; r < repeat && !g_stop; r++) {
        if (r > 0 && pcap_path) pp_source_pcapfile_rewind(&src);
        for (;;) {
            int n = pp_pipeline_step(&pipe);
            if (n < 0) { fprintf(stderr, "source error\n"); break; }
            if (n == 0) {
                if (pcap_path) break;               /* EOF */
                if (g_stop) break;
                continue;                           /* live: just a quiet moment */
            }
            if (g_stop) break;
            if (count_limit && (long)pipe.st.packets >= count_limit) { g_stop = 1; break; }
        }
    }
    pipe.st.ns_total = pp_now_ns() - t0;

#ifdef __linux__
    if (iface) pp_source_afpacket_update_drops(&src);
#endif

    pp_capture_stats cap;
    pp_source_stats(&src, &cap);
    report(&pipe, &rs, &cl, &cap, src_name);

    pp_source_close(&src);
    pp_arena_destroy(&arena);
    return 0;
}
