#!/usr/bin/env bash
# disasm_check.sh — prove the safe field-read idiom costs nothing.
#
# WHY THIS EXISTS
# proto.h reads every multi-byte wire field with byte loads composed by shifts:
#
#     static uint16_t pp_rd_be16(const uint8_t *p) { return p[0] << 8 | p[1]; }
#
# rather than the idiom nearly every packet parser uses:
#
#     ntohs(*(const uint16_t *)p);          // misaligned + strict-aliasing UB
#
# The safe version is alignment-safe (byte loads have no alignment
# requirement), aliasing-safe (uint8_t is a character type and may alias any
# object), and endian-independent (big-endian is spelled out arithmetically, so
# no ntohs and no #ifdef — the host's byte order never enters the picture).
#
# The objection is always "but that must be slower — you're reading it a byte at
# a time." It is not, and this script is the answer: both gcc and clang
# recognise the idiom and emit ONE unaligned load plus ONE byte-reverse. The
# safe version and the UB version compile to identical machine code.
#
# That is the whole argument. Choosing undefined behaviour here buys nothing —
# it is simply a worse way to write the same instructions. This script is
# checked in so that the claim is verifiable rather than believed, and so it
# stays true when the compiler is upgraded.
#
# Run inside the Linux container:  ./docker/dev.sh run ./tools/disasm_check.sh
set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/probe.c" <<'EOF'
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* (A) SAFE — the idiom pktpipe uses everywhere (proto.h: pp_rd_be16). */
uint16_t safe_byteload16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* (B) UNSAFE — cast + ntohs. Misaligned load AND strict-aliasing violation.
 *     This is what most packet parsers do. */
uint16_t unsafe_cast16(const uint8_t *p) {
    return ntohs(*(const uint16_t *)p);
}

/* (C) memcpy + ntohs — the usual "portable" compromise. Correct, but still
 *     needs ntohs at every field and therefore still an endianness footgun. */
uint16_t memcpy_ntohs16(const uint8_t *p) {
    uint16_t v; memcpy(&v, p, sizeof v); return ntohs(v);
}

/* Same three, 32-bit. */
uint32_t safe_byteload32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
uint32_t unsafe_cast32(const uint8_t *p) {
    return ntohl(*(const uint32_t *)p);
}
EOF

for CC in gcc clang; do
    command -v "$CC" >/dev/null 2>&1 || { echo "== $CC not present, skipping =="; continue; }
    echo "================================================================"
    echo "== $CC -O2 -std=c11   ($($CC --version | head -1))"
    echo "================================================================"
    "$CC" -O2 -std=c11 -c "$TMP/probe.c" -o "$TMP/probe-$CC.o"
    objdump -d --no-show-raw-insn "$TMP/probe-$CC.o" \
      | awk '/^[0-9a-f]+ <.*>:/{p=1} p' \
      | grep -vE '^\s*$|file format|Disassembly'
    echo
done

echo "================================================================"
echo "Expected result: safe_byteload16, unsafe_cast16 and memcpy_ntohs16 all"
echo "compile to the SAME two instructions (on arm64: ldrh + rev16; on x86-64:"
echo "movzwl + rolw or movbe). The safe idiom is free."
echo "================================================================"
