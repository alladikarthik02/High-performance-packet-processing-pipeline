// Minimal, dependency-free test harness (same shape as dslc's, plus byte-level
// helpers — packet work means reading hex). Each test file defines suites and
// runs them from main(); a non-zero exit code signals failure to ctest.
#pragma once
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <string>
#include <sstream>
#include <iomanip>

namespace pptest {

inline int& failures() { static int f = 0; return f; }
inline int& checks()   { static int c = 0; return c; }

inline void report_fail(const char* file, int line, const std::string& msg) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, msg.c_str());
}

// Promote small integer types so they print as numbers rather than characters.
template <typename T>
auto printable(const T& v) -> decltype(+v) { return +v; }
inline std::string printable(const std::string& s) { return s; }
inline const char* printable(const char* s) { return s; }

template <typename A, typename B>
void check_eq(const A& a, const B& b, const char* ea, const char* eb,
              const char* file, int line) {
    ++checks();
    if (!(a == b)) {
        std::ostringstream os;
        os << "CHECK_EQ(" << ea << ", " << eb << ")  ["
           << printable(a) << " != " << printable(b) << "]";
        report_fail(file, line, os.str());
    }
}

template <typename A, typename B>
void check_ne(const A& a, const B& b, const char* ea, const char* eb,
              const char* file, int line) {
    ++checks();
    if (!(a != b)) {
        std::ostringstream os;
        os << "CHECK_NE(" << ea << ", " << eb << ")  [both " << printable(a) << "]";
        report_fail(file, line, os.str());
    }
}

inline void check(bool cond, const char* expr, const char* file, int line) {
    ++checks();
    if (!cond) report_fail(file, line, std::string("CHECK(") + expr + ")");
}

// Renders bytes as hex. When a parser test fails, the first question is always
// "what were the actual bytes?" — so the harness answers it without ceremony.
inline std::string hex(const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    std::ostringstream os;
    for (size_t i = 0; i < n; ++i) {
        if (i && i % 16 == 0) os << "\n      ";
        else if (i) os << ' ';
        os << std::hex << std::setw(2) << std::setfill('0') << +b[i];
    }
    return os.str();
}

inline void dump(const char* label, const void* p, size_t n) {
    std::fprintf(stderr, "  %s (%zu bytes)\n      %s\n", label, n, hex(p, n).c_str());
}

inline int summary(const char* name) {
    std::fprintf(stderr, "[%s] %d checks, %d failures\n", name, checks(), failures());
    return failures() == 0 ? 0 : 1;
}

} // namespace pptest

#define CHECK(cond)       ::pptest::check((cond), #cond, __FILE__, __LINE__)
#define CHECK_EQ(a, b)    ::pptest::check_eq((a), (b), #a, #b, __FILE__, __LINE__)
#define CHECK_NE(a, b)    ::pptest::check_ne((a), (b), #a, #b, __FILE__, __LINE__)
#define TEST_SUMMARY(nm)  return ::pptest::summary(nm)
