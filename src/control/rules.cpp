// rules.cpp — the control plane: text rules -> immutable POD ruleset.
//
// C++17, and unapologetically so: std::string, std::vector, exceptions, RAII.
// This code runs ONCE, at startup, before the first packet. Its budget is
// milliseconds and its priority is good error messages. None of it escapes into
// the data plane — the output is a flat array of 32-byte PODs in an arena
// (SPEC §3.1).
//
// The language:
//
//     # comments run to end of line
//     default drop
//     accept tcp  192.168.1.0/24 any   -> 10.0.0.0/8  80,443
//     drop   tcp  any            any   -> any         22
//     count  udp  any            any   -> any         53
//     accept any  any            any   -> any         any    vlan 100
//     drop   tcp  any            any   -> any         any    vni 5000
//     accept icmp any            any   -> any         any    ip4
//
//     <action> <proto> <src-cidr> <src-ports> -> <dst-cidr> <dst-ports> [opts]
//
// Pipeline: tokenize -> parse -> sema -> compile. Same shape as a real compiler
// front end, because that is what it is.
#include "pp/ruleset.h"
#include "pp/arena.h"
#include "pp/pkt.h"
#include "pp/proto.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

namespace {

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

// A compile error is ordinary USER error — a typo in a config file — not an
// exceptional condition. It is thrown here only because that is the tidiest way
// to unwind a recursive-descent parser; it is caught at the C boundary and
// turned into a return code, because an exception cannot cross a C ABI.
struct RuleError : std::runtime_error {
    RuleError(const std::string& file, int line, const std::string& msg)
        : std::runtime_error(file + ":" + std::to_string(line) + ": " + msg) {}
};

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

struct Line {
    int line_no;
    std::vector<std::string> toks;
};

std::vector<Line> tokenize(const std::string& text) {
    std::vector<Line> out;
    std::istringstream in(text);
    std::string raw;
    int ln = 0;

    while (std::getline(in, raw)) {
        ++ln;
        // Comments run to end of line. Stripped before splitting so a '#' can
        // never be mistaken for a token.
        auto hash = raw.find('#');
        if (hash != std::string::npos) raw.erase(hash);

        std::istringstream ls(raw);
        Line l; l.line_no = ln;
        std::string t;
        while (ls >> t) l.toks.push_back(t);

        if (!l.toks.empty()) out.push_back(std::move(l));  // blank lines vanish
    }
    return out;
}

// ---------------------------------------------------------------------------
// Field parsers. Each validates and reports precisely what was wrong.
// ---------------------------------------------------------------------------

uint8_t parse_action(const std::string& s, const std::string& f, int ln) {
    if (s == "accept") return PP_ACTION_ACCEPT;
    if (s == "drop")   return PP_ACTION_DROP;
    if (s == "count")  return PP_ACTION_COUNT;
    if (s == "log")    return PP_ACTION_LOG;
    throw RuleError(f, ln, "unknown action '" + s + "' (want accept|drop|count|log)");
}

uint8_t parse_proto(const std::string& s, const std::string& f, int ln) {
    if (s == "any")   return PP_ANY_PROTO;
    if (s == "tcp")   return PP_IPPROTO_TCP;
    if (s == "udp")   return PP_IPPROTO_UDP;
    if (s == "icmp")  return PP_IPPROTO_ICMP;
    if (s == "icmp6") return PP_IPPROTO_ICMPV6;
    if (s == "sctp")  return PP_IPPROTO_SCTP;
    // A bare number, so a rule can name a protocol we have no keyword for.
    if (!s.empty() && s.find_first_not_of("0123456789") == std::string::npos) {
        long v = std::strtol(s.c_str(), nullptr, 10);
        if (v < 0 || v > 255) throw RuleError(f, ln, "protocol number " + s + " out of range 0-255");
        return uint8_t(v);
    }
    throw RuleError(f, ln, "unknown protocol '" + s + "' (want tcp|udp|icmp|icmp6|sctp|any|0-255)");
}

// "192.168.1.0/24" | "10.0.0.1" | "any"
void parse_cidr(const std::string& s, uint32_t& addr, uint32_t& mask,
                const std::string& f, int ln) {
    if (s == "any") { addr = 0; mask = 0; return; }

    auto slash = s.find('/');
    std::string ip = (slash == std::string::npos) ? s : s.substr(0, slash);
    int prefix = 32;   // a bare address is an implicit /32

    if (slash != std::string::npos) {
        std::string p = s.substr(slash + 1);
        if (p.empty() || p.find_first_not_of("0123456789") != std::string::npos)
            throw RuleError(f, ln, "bad prefix length in '" + s + "'");
        prefix = std::atoi(p.c_str());
        if (prefix < 0 || prefix > 32)
            throw RuleError(f, ln, "prefix /" + p + " out of range (want /0-/32)");
    }

    // Dotted quad, parsed strictly. inet_pton would do this, but it also
    // accepts "10" and "0x0a000001" and octal — historically a rich source of
    // access-control bypasses, because the parser writing the rule and the
    // parser reading the packet disagree about what "010.1.1.1" means. Ours
    // accepts exactly four decimal octets and nothing else.
    unsigned oct[4]; int n = 0;
    size_t pos = 0;
    while (n < 4) {
        size_t dot = ip.find('.', pos);
        std::string part = ip.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
        if (part.empty() || part.size() > 3 ||
            part.find_first_not_of("0123456789") != std::string::npos)
            throw RuleError(f, ln, "bad IPv4 address '" + ip + "'");
        long v = std::strtol(part.c_str(), nullptr, 10);
        if (v > 255) throw RuleError(f, ln, "octet " + part + " > 255 in '" + ip + "'");
        oct[n++] = unsigned(v);
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    if (n != 4) throw RuleError(f, ln, "IPv4 address '" + ip + "' needs 4 octets");

    uint32_t a = (oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3];
    // A /0 mask must be 0, and `1u << 32` is undefined behavior — so the shift
    // has to be special-cased rather than written naturally. A small trap, and
    // exactly the kind that only bites on the boundary case nobody tests.
    uint32_t m = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));

    // SEMA: reject host bits set outside the prefix. "192.168.1.5/24" almost
    // certainly means the author thinks it matches only .5, when it actually
    // matches the whole /24 — a silent, dangerous widening of an access rule.
    // Refusing it beats guessing which they meant.
    if ((a & ~m) != 0) {
        char buf[128];
        std::snprintf(buf, sizeof buf,
                      "%u.%u.%u.%u/%d has host bits set; did you mean %u.%u.%u.%u/%d ?",
                      oct[0], oct[1], oct[2], oct[3], prefix,
                      (a & m) >> 24, ((a & m) >> 16) & 0xFF, ((a & m) >> 8) & 0xFF,
                      (a & m) & 0xFF, prefix);
        throw RuleError(f, ln, buf);
    }

    // PRE-MASK at compile time (see ruleset.h). Costs nothing now; saves one
    // AND per rule per packet forever.
    addr = a & m;
    mask = m;
}

// "80" | "80-443" | "any"
void parse_ports(const std::string& s, uint16_t& lo, uint16_t& hi,
                 const std::string& f, int ln) {
    if (s == "any") { lo = 0; hi = 65535; return; }

    auto dash = s.find('-');
    auto num = [&](const std::string& t) -> long {
        if (t.empty() || t.find_first_not_of("0123456789") != std::string::npos)
            throw RuleError(f, ln, "bad port '" + t + "'");
        long v = std::strtol(t.c_str(), nullptr, 10);
        if (v < 0 || v > 65535) throw RuleError(f, ln, "port " + t + " out of range 0-65535");
        return v;
    };

    if (dash == std::string::npos) { lo = hi = uint16_t(num(s)); return; }

    long a = num(s.substr(0, dash));
    long b = num(s.substr(dash + 1));
    // SEMA: an inverted range matches NOTHING and is always a typo. Silently
    // accepting it gives you a rule that never fires and never complains —
    // which is how a "drop" rule you believe is protecting you does nothing.
    if (a > b)
        throw RuleError(f, ln, "port range " + s + " is inverted (" +
                               std::to_string(a) + " > " + std::to_string(b) +
                               "); it would match nothing");
    lo = uint16_t(a); hi = uint16_t(b);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Compiled {
    std::vector<pp_rule> rules;
    uint8_t default_action = PP_ACTION_ACCEPT;
};

Compiled parse(const std::vector<Line>& lines, const std::string& file) {
    Compiled out;
    uint32_t next_id = 1;

    for (const auto& L : lines) {
        const auto& t = L.toks;

        if (t[0] == "default") {
            if (t.size() != 2)
                throw RuleError(file, L.line_no, "'default' takes exactly one action");
            out.default_action = parse_action(t[1], file, L.line_no);
            continue;
        }

        // <action> <proto> <src> <sports> -> <dst> <dports> [opts...]
        //    0        1      2      3      4    5      6
        if (t.size() < 7)
            throw RuleError(file, L.line_no,
                "expected: <action> <proto> <src> <sports> -> <dst> <dports> [opts]");
        if (t[4] != "->")
            throw RuleError(file, L.line_no, "expected '->' between source and destination, found '" + t[4] + "'");

        pp_rule r{};
        uint8_t action = parse_action(t[0], file, L.line_no);
        uint8_t ip_ver = PP_ANY_IPVER;
        r.proto  = parse_proto(t[1], file, L.line_no);
        parse_cidr(t[2], r.src_addr, r.src_mask, file, L.line_no);
        parse_ports(t[3], r.sport_lo, r.sport_hi, file, L.line_no);
        parse_cidr(t[5], r.dst_addr, r.dst_mask, file, L.line_no);
        parse_ports(t[6], r.dport_lo, r.dport_hi, file, L.line_no);

        r.vlan   = PP_ANY_VLAN;
        r.vni    = PP_ANY_VNI;

        // Optional trailing qualifiers.
        for (size_t i = 7; i < t.size(); ++i) {
            if (t[i] == "vlan") {
                if (++i >= t.size()) throw RuleError(file, L.line_no, "'vlan' needs an ID");
                long v = std::atol(t[i].c_str());
                // 12-bit field. 4095 is reserved but real gear emits it, so it
                // is accepted; 4096 cannot exist on the wire at all.
                if (v < 0 || v > 4095)
                    throw RuleError(file, L.line_no, "VLAN " + t[i] + " out of range 0-4095");
                r.vlan = uint16_t(v);
            } else if (t[i] == "vni") {
                if (++i >= t.size()) throw RuleError(file, L.line_no, "'vni' needs an ID");
                long v = std::atol(t[i].c_str());
                if (v < 0 || v > 0xFFFFFF)   // VXLAN VNI is 24 bits
                    throw RuleError(file, L.line_no, "VNI " + t[i] + " out of range 0-16777215");
                r.vni = uint32_t(v);
            } else if (t[i] == "ip4") {
                ip_ver = 4;
            } else if (t[i] == "ip6") {
                ip_ver = 6;
            } else {
                throw RuleError(file, L.line_no,
                    "unknown qualifier '" + t[i] + "' (want vlan N | vni N | ip4 | ip6)");
            }
        }

        // SEMA: a rule matching an IPv4 CIDR *and* declaring ip6 can never
        // fire. Catch the contradiction at compile time rather than let it sit
        // in production doing nothing.
        if (ip_ver == 6 && (r.src_mask != 0 || r.dst_mask != 0))
            throw RuleError(file, L.line_no,
                "rule declares 'ip6' but matches an IPv4 address; "
                "IPv6 address matching is not supported (use 'any')");

        // Pack the two nibble-sized fields; see ruleset.h for why.
        r.action_ipver = pp_rule_pack(action, ip_ver);
        next_id++;   // ids are positional: pp_rule_id(index), not a stored field
        out.rules.push_back(r);
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// The C boundary. Exceptions stop here; return codes go out.
// ---------------------------------------------------------------------------
extern "C" {

const char *pp_action_str(int a)
{
    switch (a) {
    case PP_ACTION_ACCEPT: return "accept";
    case PP_ACTION_DROP:   return "drop";
    case PP_ACTION_COUNT:  return "count";
    case PP_ACTION_LOG:    return "log";
    default:               return "invalid";
    }
}

int pp_rules_compile_str(const char *text, const char *filename,
                         struct pp_arena *arena, pp_ruleset *out,
                         char *err, size_t errlen)
{
    if (err && errlen) err[0] = 0;
    try {
        std::string fname = filename ? filename : "<string>";
        auto lines = tokenize(text ? text : "");
        Compiled c = parse(lines, fname);

        // Carve the rule array out of the ARENA, not out of the C++ heap.
        //
        // This is the whole lifetime story in one line: the ruleset must
        // outlive every C++ object that built it, and the data plane must never
        // hold memory owned by the C++ runtime. Handing the data plane a
        // std::vector's buffer would work right up until the vector went out of
        // scope. The arena has process lifetime, so it cannot.
        pp_rule *dst = nullptr;
        if (!c.rules.empty()) {
            dst = static_cast<pp_rule*>(
                pp_arena_alloc(arena, c.rules.size() * sizeof(pp_rule), PP_CACHELINE));
            if (!dst) {
                std::snprintf(err, errlen, "arena exhausted: cannot fit %zu rules (%zu bytes)",
                              c.rules.size(), c.rules.size() * sizeof(pp_rule));
                return -1;
            }
            std::memcpy(dst, c.rules.data(), c.rules.size() * sizeof(pp_rule));
        }

        out->rules          = dst;
        out->n              = uint32_t(c.rules.size());
        out->default_action = c.default_action;
        return 0;
    }
    catch (const std::exception& e) {
        // The C ABI cannot carry an exception. Every throw in this file lands
        // here and becomes a message plus a return code.
        if (err && errlen) std::snprintf(err, errlen, "%s", e.what());
        return -1;
    }
    catch (...) {
        if (err && errlen) std::snprintf(err, errlen, "unknown error compiling rules");
        return -1;
    }
}

int pp_rules_compile_file(const char *path, struct pp_arena *arena,
                          pp_ruleset *out, char *err, size_t errlen)
{
    std::ifstream in(path ? path : "");
    if (!in) {
        if (err && errlen) std::snprintf(err, errlen, "cannot open rules file '%s'", path ? path : "(null)");
        return -1;
    }
    std::ostringstream ss; ss << in.rdbuf();
    return pp_rules_compile_str(ss.str().c_str(), path, arena, out, err, errlen);
}

} // extern "C"
