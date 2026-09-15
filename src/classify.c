/* classify.c — the linear-scan classifier.
 *
 * THIS IS THE BASELINE, AND THAT IS ON PURPOSE (SPEC §7.5).
 *
 * The reflex is to reach straight for the clever structure: a hash table for
 * exact 5-tuples, DIR-24-8 for prefixes. But DIR-24-8 costs a flat 16 MiB table
 * — larger than this machine's entire 4 MiB L2 — so every lookup risks a DRAM
 * miss at ~200-300 cycles. Meanwhile eight 32-byte rules occupy four cache
 * lines and live in L1 permanently, and a linear scan over them is a handful of
 * ALU ops with a perfectly predicted branch.
 *
 * For small rulesets the "naive" scan wins, and it is not close. The crossover
 * is an empirical question, so T12 measures it rather than guessing. Building
 * the baseline first is what makes that measurement possible at all — you
 * cannot report a speedup against a thing you never built.
 *
 * The honest interview answer is "it depends on rule count, and here is the
 * graph", which is worth more than either "I used linear" or "I used DIR-24-8".
 */
#include "pp/classify.h"
#include "pp/arena.h"
#include "pp/proto.h"

#include <string.h>

int pp_classifier_init(pp_classifier *c, const pp_ruleset *rs, struct pp_arena *a)
{
    memset(c, 0, sizeof *c);
    c->rs = rs;

    if (rs->n == 0) return 0;   /* an empty ruleset is legal: everything defaults */

    /* Counters come from the arena, and they are cache-line aligned so the
     * counter array never shares a line with whatever was allocated before it.
     * Same false-sharing reasoning as the header. */
    c->hits = (uint64_t *)pp_arena_alloc(a, (size_t)rs->n * sizeof(uint64_t),
                                         PP_CACHELINE);
    if (!c->hits) return -1;
    memset(c->hits, 0, (size_t)rs->n * sizeof(uint64_t));
    return 0;
}

/* Does one rule match one packet?
 *
 * TEST ORDER IS A PERFORMANCE DECISION. Every test is an early-out, so the
 * cheapest and most selective go first: the sooner a non-matching rule is
 * rejected, the less work the scan does. `proto` is one byte, is specified by
 * almost every real rule, and eliminates most candidates immediately — so it
 * leads. Ports come last because they need the L4 layer check first.
 *
 * All of it is branches on data already in registers or in the same cache line,
 * which is exactly why this "naive" function is hard to beat at small N. */
static PP_ALWAYS_INLINE int rule_matches(const pp_rule *r, const pp_meta *m)
{
    /* --- protocol: cheapest, most selective --- */
    if (r->proto != PP_ANY_PROTO && r->proto != m->ip_proto)
        return 0;

    /* --- IP version --- */
    uint8_t want_ver = pp_rule_ipver(r);
    if (want_ver != PP_ANY_IPVER && want_ver != m->ip_ver)
        return 0;

    /* --- addresses ---
     *
     * The rule's addr was PRE-MASKED at compile time (ruleset.h), so this is
     * one AND and one compare rather than two ANDs and a compare. Half the work
     * on the hottest instruction in the program.
     *
     * The ip_ver guard matters: for an IPv6 packet, m->ip_src is 0 because we
     * deliberately do not copy 128-bit addresses into the cache line (pkt.h).
     * Without this check, a rule matching `0.0.0.0/8` would match every IPv6
     * packet — a silent, wrong, and security-relevant match. Address rules are
     * IPv4-only, so say so explicitly rather than let a zero mean something. */
    if (r->src_mask != 0) {
        if (m->ip_ver != 4) return 0;
        if ((m->ip_src & r->src_mask) != r->src_addr) return 0;
    }
    if (r->dst_mask != 0) {
        if (m->ip_ver != 4) return 0;
        if ((m->ip_dst & r->dst_mask) != r->dst_addr) return 0;
    }

    /* --- VLAN / VNI --- */
    if (r->vlan != PP_ANY_VLAN && r->vlan != m->vlan_outer)
        return 0;
    if (r->vni != PP_ANY_VNI && r->vni != m->vni)
        return 0;

    /* --- ports ---
     *
     * The subtle one. When there is no L4 header — a later fragment, ESP, ARP,
     * SCTP — sport and dport are 0, because the parser refuses to invent them
     * (T3/T4). A rule saying `any` ports is 0..65535 and would therefore MATCH
     * that 0, which is right: "any" really does mean any, including "none".
     *
     * But a rule naming specific ports must NOT match a packet that has no
     * ports at all. Without this check, `drop tcp any any -> any 22` would fire
     * on a later fragment whose ports we never read — dropping traffic on the
     * basis of a port number we made up. So: if the rule cares about ports, the
     * packet must actually have some. */
    int wants_ports = (r->sport_lo != 0 || r->sport_hi != 65535 ||
                       r->dport_lo != 0 || r->dport_hi != 65535);
    if (wants_ports) {
        if (!(m->layers & PP_LAYER_L4)) return 0;
        if (m->sport < r->sport_lo || m->sport > r->sport_hi) return 0;
        if (m->dport < r->dport_lo || m->dport > r->dport_hi) return 0;
    }

    return 1;
}

uint8_t pp_classify(pp_classifier *c, const pp_meta *m, uint32_t *matched_rule)
{
    const pp_ruleset *rs = c->rs;

    for (uint32_t i = 0; i < rs->n; i++) {
        const pp_rule *r = &rs->rules[i];
        if (!rule_matches(r, m))
            continue;

        c->hits[i]++;

        uint8_t action = pp_rule_action(r);
        if (action == PP_ACTION_COUNT)
            continue;   /* non-terminal: counted, keep evaluating */

        if (matched_rule) *matched_rule = pp_rule_id(i);
        return action;
    }

    c->n_default++;
    if (matched_rule) *matched_rule = 0;   /* 0 == "the default applied" */
    return rs->default_action;
}
