/* parse.h — the zero-copy, zero-allocation, bounded packet parser.
 *
 * Contract (all four are tested, not just asserted):
 *
 *   1. ZERO COPY. Packet bytes are never copied. `pp_meta` records offsets into
 *      the caller's buffer; the buffer is borrowed and const.
 *   2. ZERO ALLOCATION. No malloc, no VLA, no recursion-by-heap. Everything
 *      lives in the caller's pp_meta and a few registers. Enforced by T9.
 *   3. BOUNDED. Every loop over attacker-controlled repetition (VLAN stacks,
 *      IPv6 extension headers, tunnel nesting) has a hard cap. A crafted packet
 *      cannot make the parser run long (SPEC §7.8).
 *   4. TOTAL. Every input returns. Malformed packets set `m->err` and stop at
 *      the last good layer; they never crash, never throw, never over-read.
 *      On a real link, malformed traffic is normal traffic.
 */
#ifndef PP_PARSE_H
#define PP_PARSE_H

#include "pp/pkt.h"

PP_BEGIN_DECLS

/* Parse one packet. `m` is fully initialized by this call (no need to call
 * pp_meta_init first — it does that).
 *
 * THE CONTRACT — two questions, two answers, deliberately not conflated:
 *
 *   "Is this packet malformed?"     -> the RETURN VALUE (and m->err).
 *        PP_OK      = nothing is wrong with it.
 *        pp_err     = it is truncated, lying, or hostile, and this is where
 *                     parsing stopped and why.
 *
 *   "How deep did we get?"          -> m->layers.
 *        PP_LAYER_L3 set but PP_LAYER_L4 clear means there is no L4 to find.
 *
 * These are genuinely different questions, and an ARP frame is the clearest
 * proof: it is a perfectly good packet (PP_OK) that has no L3 (layers == L2).
 * So is a later IP fragment: valid, classifiable at L3, and carrying no L4
 * header because the L4 header was in fragment #1. So is an ESP packet, whose
 * payload is encrypted. None of those is an error, and a parser that reports
 * them as errors forces its caller to treat "fine" and "broken" identically.
 *
 * An earlier version DID conflate them — it returned PP_ERR_UNSUPPORTED_L3 both
 * for "this packet has no L4" and for "the L4 parser isn't written yet". The
 * fragment test then could not express what it meant, which is how the flaw was
 * found. See docs/CHALLENGES.md T3.
 *
 * On error, `m` still holds everything decoded up to the stopping point: a
 * truncated TCP header still yields valid L2 and L3 metadata, which is exactly
 * what a rule matching only on IP needs. */
int pp_parse(const pp_rawpkt *pkt, pp_meta *m);

PP_END_DECLS

#endif /* PP_PARSE_H */
