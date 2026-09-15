/* ruleset.h — the compiled, immutable ruleset, and the C/C++ boundary.
 *
 * THIS HEADER IS THE ARCHITECTURE (SPEC §3.1, R1).
 *
 * Everything below the compile function is plain-old-data readable from C11
 * with no C++ runtime involved. Everything that PRODUCES it is C++17 —
 * std::string, std::vector, exceptions, RAII, all of it — and none of that
 * escapes into the data plane.
 *
 * The direction of the dependency is the point:
 *
 *      rules file (text)
 *          |
 *          v   [C++17 control plane: lexer -> parser -> sema -> compile]
 *          |   runs ONCE at startup. May allocate. May throw. Slow is fine.
 *          v
 *      pp_ruleset (flat POD)
 *          |
 *          v   [C11 data plane: classify]
 *              runs per packet, forever. Reads only. Never allocates.
 *
 * The data plane cannot see std::string; it sees a flat array of 32-byte PODs.
 * That is what makes "no per-packet allocation" auditable by reading the code
 * rather than by hoping — there is nothing here that COULD allocate.
 */
#ifndef PP_RULESET_H
#define PP_RULESET_H

#include "pp/pp.h"

PP_BEGIN_DECLS

/* What to do with a packet that matches. */
enum pp_action {
    PP_ACTION_ACCEPT = 0,
    PP_ACTION_DROP,
    PP_ACTION_COUNT,   /* count it and keep evaluating — a monitoring rule */
    PP_ACTION_LOG,
    PP_ACTION__COUNT
};

const char *pp_action_str(int action);

/* Wildcards. Each is a value the corresponding field cannot legitimately take,
 * for the same reason PP_VLAN_NONE is 0xFFFF and not 0: a sentinel that
 * collides with real data turns a rule into a silent mismatch (see T1/T2). */
#define PP_ANY_PROTO   0xFFu
#define PP_ANY_VLAN    0xFFFFu
#define PP_ANY_VNI     0xFFFFFFFFu
#define PP_ANY_IPVER   0u

/* ---------------------------------------------------------------------------
 * pp_rule — one compiled rule. 32 bytes: two per cache line.
 *
 * Deliberately sized. The linear classifier (T7) walks this array for every
 * packet, so the array IS the hot data. At 32 bytes, eight rules occupy four
 * cache lines and a small ruleset stays entirely in L1 — which is exactly why
 * the "obvious" clever data structure may lose to a linear scan (SPEC §7.5).
 *
 * ADDRESSES ARE PRE-MASKED at compile time: `addr` already has `mask` applied.
 * That turns the per-packet test from
 *      (pkt & mask) == (rule.addr & mask)      -- two ANDs and a compare
 * into
 *      (pkt & mask) == rule.addr               -- one AND and a compare
 * Half the work, on the hottest instruction in the program, bought once at
 * startup. This is the whole reason a compile step exists rather than matching
 * against the parsed text.
 * ------------------------------------------------------------------------- */
/* Field order is load-bearing. The first draft declared these in the order they
 * came to mind and came out at 40 bytes — `uint16_t vlan` ahead of
 * `uint32_t vni` forces two bytes of padding so vni can land 4-aligned, and the
 * whole struct then rounds up. The static_assert below caught it. Widest-first,
 * and every byte earns its place. */
typedef struct pp_rule {
    uint32_t src_addr;   /* IPv4, network byte order, ALREADY masked  */  /*  0 */
    uint32_t src_mask;   /* 0 = match any                             */  /*  4 */
    uint32_t dst_addr;                                                    /*  8 */
    uint32_t dst_mask;                                                    /* 12 */
    uint32_t vni;        /* PP_ANY_VNI = don't care                   */  /* 16 */

    uint16_t sport_lo, sport_hi;   /* inclusive; 0..65535 = any       */  /* 20 */
    uint16_t dport_lo, dport_hi;                                          /* 24 */
    uint16_t vlan;       /* PP_ANY_VLAN = don't care                  */  /* 28 */

    uint8_t  proto;      /* PP_ANY_PROTO = don't care                 */  /* 30 */

    /* action (low nibble) | ip_ver (high nibble).
     *
     * Packed because the honest budget did not stretch to two bytes. Both fit
     * easily: action is 0-3, ip_ver is 0, 4 or 6. Use the accessors below
     * rather than touching this directly. This is what "designed to a size"
     * actually looks like — the alternative was 36 bytes and a struct that no
     * longer tiles a cache line. */
    uint8_t  action_ipver;                                                /* 31 */
} pp_rule;

/* NOTE: there is no `id` field. It would always be (index + 1), and a field
 * that can be derived is a field that can one day disagree with the thing it
 * was derived from. pp_rule_id() computes it; the array index IS the identity. */
static PP_ALWAYS_INLINE uint8_t pp_rule_action(const pp_rule *r)
{ return (uint8_t)(r->action_ipver & 0x0Fu); }

static PP_ALWAYS_INLINE uint8_t pp_rule_ipver(const pp_rule *r)
{ return (uint8_t)(r->action_ipver >> 4); }

static PP_ALWAYS_INLINE uint8_t pp_rule_pack(uint8_t action, uint8_t ip_ver)
{ return (uint8_t)((ip_ver << 4) | (action & 0x0Fu)); }

/* 1-based rule number, matching the line order of the rules file, so that
 * "rule 7 matched 40,000 packets" points the author at a line they can find. */
static PP_ALWAYS_INLINE uint32_t pp_rule_id(uint32_t index) { return index + 1u; }

PP_STATIC_ASSERT(sizeof(pp_rule) == 32,
                 "pp_rule must be 32 bytes: two per cache line (SPEC §7.5)");
PP_STATIC_ASSERT(PP_CACHELINE % sizeof(pp_rule) == 0,
                 "pp_rule must tile a cache line exactly, or the linear scan "
                 "straddles lines and the size was pointless");

/* ---------------------------------------------------------------------------
 * pp_ruleset — immutable after compilation.
 *
 * `rules` points at an array carved from an arena, not from malloc, so the data
 * plane never touches the allocator even indirectly. Const because the data
 * plane must not write it: an immutable ruleset is also what makes the
 * multi-core story trivial (SPEC §7.10) — read-only data shards for free, with
 * no locking and no false sharing.
 * ------------------------------------------------------------------------- */
typedef struct pp_ruleset {
    const pp_rule *rules;
    uint32_t       n;
    uint8_t        default_action;   /* what happens when nothing matches */
    uint8_t        _pad[3];
} pp_ruleset;

/* ---------------------------------------------------------------------------
 * THE BOUNDARY.
 *
 * Implemented in C++17 (src/control/rules.cpp), callable from C11. Everything
 * on the far side of this declaration is std::string and std::vector; nothing
 * of that leaks through.
 *
 * `arena` supplies the rule array's storage, so the ruleset outlives the C++
 * objects that built it without anyone owning a std::vector across the
 * boundary — which would be a lifetime bug waiting to happen and, worse, would
 * mean the data plane's memory was owned by the C++ heap.
 *
 * Errors are returned in a caller-supplied buffer rather than thrown: an
 * exception cannot cross a C ABI, and a compile error in a rules file is
 * ordinary user error, not an exceptional condition.
 *
 * Returns 0 on success; -1 on error with a human-readable message in `err`.
 * ------------------------------------------------------------------------- */
struct pp_arena;

int pp_rules_compile_file(const char *path, struct pp_arena *arena,
                          pp_ruleset *out, char *err, size_t errlen);

/* Same, from a string. This is what the tests use — a rule language test that
 * needs a temp file per case is a rule language test nobody writes enough of. */
int pp_rules_compile_str(const char *text, const char *filename,
                         struct pp_arena *arena, pp_ruleset *out,
                         char *err, size_t errlen);

PP_END_DECLS

#endif /* PP_RULESET_H */
