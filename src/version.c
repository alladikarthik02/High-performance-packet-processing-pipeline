/* version.c — build identification and hardware probing.
 *
 * Deliberately C, not C++: this file is part of the data-plane library, and the
 * data-plane library must be linkable without the C++ runtime (SPEC §3.1).
 */
#include "pp/pp.h"

#include <stdio.h>

#if defined(__APPLE__)
#  include <sys/sysctl.h>
#elif defined(__linux__)
#  include <unistd.h>
#endif

#define PP_VERSION_STR "0.1.0"

/* Platform identification is resolved here, at file scope, rather than inline
 * inside the snprintf() call below. That is not a style preference: snprintf is
 * permitted to be a function-like macro (glibc does this under
 * _FORTIFY_SOURCE), and C11 §6.10.3p11 makes a preprocessing directive inside a
 * function-like macro's arguments *undefined behavior*. The first draft of this
 * file did exactly that and -Wpedantic caught it. See docs/CHALLENGES.md T0. */
#if defined(__APPLE__)
#  define PP_OS_NAME "macOS"
#elif defined(__linux__)
#  define PP_OS_NAME "Linux"
#else
#  define PP_OS_NAME "unknown-os"
#endif

#if defined(__aarch64__) || defined(__arm64__)
#  define PP_ARCH_NAME "arm64"
#elif defined(__x86_64__)
#  define PP_ARCH_NAME "x86_64"
#else
#  define PP_ARCH_NAME "unknown-arch"
#endif

#if defined(__clang__)
#  define PP_CC_NAME "clang"
#elif defined(__GNUC__)
#  define PP_CC_NAME "gcc"
#else
#  define PP_CC_NAME "unknown-cc"
#endif

const char *pp_version(void) { return PP_VERSION_STR; }

const char *pp_build_info(void)
{
    /* Built once into a static buffer; called from reporting paths only, never
     * from the hot path, so the static is fine and costs nothing per packet. */
    static char buf[192];
    static int  built = 0;
    if (!built) {
        snprintf(buf, sizeof buf,
                 "pktpipe %s | %s | %s | %s | cacheline=%zuB (designed for %uB)",
                 PP_VERSION_STR, PP_OS_NAME, PP_ARCH_NAME, PP_CC_NAME,
                 pp_hw_cacheline(), PP_CACHELINE);
        built = 1;
    }
    return buf;
}

size_t pp_hw_cacheline(void)
{
    /* The two platforms expose this through completely different interfaces.
     * We ask rather than assume: on Apple M1 the answer is 128, on x86-64 it is
     * 64, and quoting the wrong one is exactly the kind of unchecked claim that
     * falls apart under questioning (SPEC §7.3). */
#if defined(__APPLE__)
    size_t line = 0, sz = sizeof line;
    if (sysctlbyname("hw.cachelinesize", &line, &sz, NULL, 0) == 0) return line;
    return 0;
#elif defined(__linux__)
    long line = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    return line > 0 ? (size_t)line : 0;
#else
    return 0;
#endif
}
