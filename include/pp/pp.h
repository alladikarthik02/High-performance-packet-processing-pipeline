/* pp.h — shared foundations for the pktpipe data plane.
 *
 * The data plane is C11 and the control plane is C++17 (see docs/SPEC.md §3.1).
 * Every public header is wrapped in PP_BEGIN_DECLS/PP_END_DECLS so the C++ side
 * can include it and link against the C objects across a stable C ABI.
 */
#ifndef PP_PP_H
#define PP_PP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#  define PP_BEGIN_DECLS extern "C" {
#  define PP_END_DECLS   }
#else
#  define PP_BEGIN_DECLS
#  define PP_END_DECLS
#endif

/* These headers are compiled by BOTH a C11 compiler (the data plane) and a C++17
 * compiler (the control plane and every test). The two languages spell the same
 * concepts differently — `_Alignas`/`alignas`, `_Static_assert`/`static_assert` —
 * so a shared header must not hardcode either spelling. This is the tax for the
 * C/C++ split in SPEC §3.1, and it is cheap: pay it once, here. */
#ifdef __cplusplus
#  define PP_ALIGNAS(n)          alignas(n)
#  define PP_ALIGNOF(t)          alignof(t)
#  define PP_STATIC_ASSERT(c, m) static_assert(c, m)
#else
#  define PP_ALIGNAS(n)          _Alignas(n)
#  define PP_ALIGNOF(t)          _Alignof(t)
#  define PP_STATIC_ASSERT(c, m) _Static_assert(c, m)
#endif

/* Cache line we design to. This is 64 on x86-64 and on most Arm server cores;
 * Apple silicon uses 128. We deliberately target the *smaller* value because a
 * struct that fits in 64 also fits in 128 — designing to the looser bound would
 * silently break the claim on the machines that matter (see SPEC §7.3).
 * PP_HW_CACHELINE is probed at build time and reported by tools/cacheinfo. */
#define PP_CACHELINE 64u

#define PP_CACHE_ALIGNED PP_ALIGNAS(PP_CACHELINE)

/* Branch hints. The hot path is overwhelmingly "well-formed packet"; error
 * paths are cold. Telling the compiler lets it lay out the fall-through for
 * the common case and push malformed-packet handling out of line. */
#if defined(__GNUC__) || defined(__clang__)
#  define PP_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define PP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define PP_ALWAYS_INLINE inline __attribute__((always_inline))
#  define PP_PREFETCH(addr) __builtin_prefetch((addr), 0 /*read*/, 3 /*high locality*/)
#else
#  define PP_LIKELY(x)   (x)
#  define PP_UNLIKELY(x) (x)
#  define PP_ALWAYS_INLINE inline
#  define PP_PREFETCH(addr) ((void)0)
#endif

PP_BEGIN_DECLS

/* Identifies the build so tests and benchmarks can report what they measured. */
const char *pp_version(void);
const char *pp_build_info(void);

/* Runtime cache-line size as reported by the OS, or 0 if unknown. Used by
 * tools/cacheinfo to state the real number rather than assume one. */
size_t pp_hw_cacheline(void);

PP_END_DECLS

#endif /* PP_PP_H */
