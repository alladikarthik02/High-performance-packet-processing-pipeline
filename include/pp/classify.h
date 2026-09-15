/* classify.h — apply the compiled ruleset to parsed metadata.
 *
 * EVALUATION SEMANTICS (chosen to match iptables/snort, because a rule language
 * that surprises its author is a security bug):
 *
 *   - Rules are evaluated in file order, top to bottom.
 *   - accept / drop / log are TERMINAL: the first one that matches wins and
 *     evaluation stops.
 *   - count is NON-terminal: it increments the rule's counter and evaluation
 *     CONTINUES. That is what makes a monitoring rule useful — you want to
 *     count something and still let the policy below decide.
 *   - If no terminal rule matches, the ruleset's `default` applies.
 *
 * First-match-wins is not the only option — a "most specific wins" longest-match
 * policy is defensible too — but it is the one every operator already has in
 * their head from iptables, and matching that intuition is worth more than
 * elegance.
 */
#ifndef PP_CLASSIFY_H
#define PP_CLASSIFY_H

#include "pp/pkt.h"
#include "pp/ruleset.h"

PP_BEGIN_DECLS

struct pp_arena;

typedef struct pp_classifier {
    const pp_ruleset *rs;

    /* Per-rule hit counters, indexed exactly like rs->rules.
     *
     * Arena-allocated, not malloc'd, because this is written on the hot path
     * and must not involve the allocator (R6).
     *
     * A separate array rather than a counter inside pp_rule, deliberately: the
     * rules are READ-ONLY hot data shared by every core, and putting a mutable
     * counter in the same cache line would turn every match into a write to a
     * line other cores are reading. That is false sharing, and it is how a
     * "lock-free" design still manages to serialize on the memory bus. Keeping
     * the counters in their own array means the ruleset stays clean read-only
     * data and shards for free (SPEC §7.10). */
    uint64_t *hits;

    uint64_t n_default;   /* packets that matched no terminal rule */
} pp_classifier;

/* Returns 0 on success, -1 if the arena cannot fit the counters. */
int pp_classifier_init(pp_classifier *c, const pp_ruleset *rs, struct pp_arena *a);

/* Classify one parsed packet.
 *
 * Returns the pp_action. `matched_rule`, if non-NULL, receives the 1-based id
 * of the terminal rule that fired, or 0 if the default applied — so a report
 * can say "rule 7" and point at a line of the rules file. */
uint8_t pp_classify(pp_classifier *c, const pp_meta *m, uint32_t *matched_rule);

PP_END_DECLS

#endif /* PP_CLASSIFY_H */
