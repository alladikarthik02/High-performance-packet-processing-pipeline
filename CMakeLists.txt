cmake_minimum_required(VERSION 3.16)
project(pktpipe C CXX)

# ---- Language split (SPEC §3.1) ----------------------------------------
#   C11   : the data plane. No hidden allocation, no exceptions, no vtables.
#   C++17 : the control plane. Rule parsing/compiling, runs once at startup.
# Both are first-class here; the boundary between them is a C ABI.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# This is a performance project. Benchmarking an -O0 build measures nothing
# real, so the default is optimized-with-symbols rather than Debug.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)

# Packet parsers are exactly where aliasing bugs live, so ask the compiler to
# help. Note we do NOT pass -fno-strict-aliasing: the lazy way to "fix" the
# type-punning UB in SPEC §7.2 is to disable the optimization that exposes it.
# Instead the parser is written with memcpy (which costs nothing after -O2) and
# strict aliasing stays enabled. See docs/CHALLENGES.md.
add_compile_options(-Wstrict-aliasing=2 -Wcast-align)

# perf needs frame pointers to unwind. Omitting them buys back one register and
# costs us readable call graphs in T13 — a bad trade for a project whose whole
# point is profiling.
add_compile_options(-fno-omit-frame-pointer)

# --- macOS libc++ header workaround (carried over from dslc) -------------
# Some Command Line Tools installs ship a broken stub include dir while the real
# libc++ headers live under the SDK. Applies to C++ only; C is unaffected.
if(APPLE)
  execute_process(COMMAND xcrun --show-sdk-path
                  OUTPUT_VARIABLE PP_SDK_PATH
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(PP_SDK_PATH AND EXISTS "${PP_SDK_PATH}/usr/include/c++/v1/string")
    message(STATUS "Using SDK libc++ headers: ${PP_SDK_PATH}/usr/include/c++/v1")
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
                        $<$<COMPILE_LANGUAGE:CXX>:-isystem${PP_SDK_PATH}/usr/include/c++/v1>)
  endif()
endif()

option(PP_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
if(PP_SANITIZE)
  # UBSan is not decoration here: it catches the misaligned-load and strict-
  # aliasing mistakes that packet parsers attract (SPEC §7.2).
  message(STATUS "Sanitizers: address, undefined")
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g)
  add_link_options(-fsanitize=address,undefined)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

# ---- Data plane: C11 ---------------------------------------------------
# Sources are appended as each task lands so the build and tests stay green at
# every step.
set(PPCORE_SOURCES
  src/version.c
  src/pkt.c        # T1: metadata lifecycle
  src/arena.c      # T1: the reason the hot path never calls malloc
  src/parse.c      # T2+: the zero-copy, bounded parser
  src/source_pcapfile.c  # T5: deterministic replay, mmap'd zero-copy
  src/classify.c   # T7: the linear-scan baseline (SPEC 7.5)
  src/pipeline.c   # T8: batching + prefetch, the hot loop
)

# AF_PACKET is a Linux kernel interface and exists nowhere else. Guarding the
# source at the BUILD level rather than wrapping the file in #ifdef __linux__
# keeps the fact visible: this is the platform-specific part, and it is the part
# the resume's R7 claim rests on (SPEC 5).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND PPCORE_SOURCES
    src/source_afpacket.c  # T10/T11: AF_PACKET + PACKET_MMAP TPACKET_V3 ring
  )
  message(STATUS "AF_PACKET capture backend: ENABLED (Linux)")
else()
  message(STATUS "AF_PACKET capture backend: disabled (not Linux)")
endif()
set(PPCORE_SOURCES ${PPCORE_SOURCES})
add_library(ppcore ${PPCORE_SOURCES})
target_include_directories(ppcore PUBLIC ${CMAKE_SOURCE_DIR}/include)

# ---- Control plane: C++17 ----------------------------------------------
# Rule parsing and compilation. Runs once at startup; may allocate, may throw,
# may use the whole STL. Its output is a flat POD ruleset the C data plane
# reads (SPEC §3.1). This library is the "and C++" half of the resume claim,
# and the separate target is what keeps the boundary honest and visible.
set(PPCONTROL_SOURCES
  src/control/rules.cpp   # T6: lexer -> parser -> sema -> compiler
)
add_library(ppcontrol ${PPCONTROL_SOURCES})
target_include_directories(ppcontrol PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ppcontrol PUBLIC ppcore)

# ---- The main binary ---------------------------------------------------
add_executable(pktpipe src/main.c)
target_link_libraries(pktpipe PRIVATE ppcore ppcontrol)
# main.c is C but links the C++ control plane, so the C++ runtime must come
# along. Naming the linker language is how CMake is told that.
set_target_properties(pktpipe PROPERTIES LINKER_LANGUAGE CXX)

# ---- Tools -------------------------------------------------------------
add_executable(cacheinfo tools/cacheinfo.c)
target_link_libraries(cacheinfo PRIVATE ppcore)

# pktgen builds the deterministic .pcap corpora the tests and benchmarks run
# against. It reuses tests/pktbuild.h: the corpus and the unit tests are built
# from the same packet-construction code, so they cannot drift apart.
add_executable(pktgen tools/pktgen.cpp)
target_link_libraries(pktgen PRIVATE ppcore)
target_include_directories(pktgen PRIVATE ${CMAKE_SOURCE_DIR}/tests)

# pktsend transmits raw frames via AF_PACKET, so the capture side has something
# to capture. Linux only, for the same reason the capture side is.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(pktsend tools/pktsend.c)
endif()

# ---- Benchmarks --------------------------------------------------------
add_executable(bench bench/bench.cpp)
target_link_libraries(bench PRIVATE ppcore ppcontrol)

# ---- Tests -------------------------------------------------------------
# Tests are C++ (the harness wants std::string) and link the C data plane
# through its extern "C" headers — which also continuously proves the ABI
# boundary in SPEC §3.1 actually holds.
enable_testing()
function(add_pp_test name)
  add_executable(${name} tests/${name}.cpp)
  target_link_libraries(${name} PRIVATE ppcore ppcontrol)
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_pp_test(test_smoke)
add_pp_test(test_layout)   # T1: the cache-line claim, mechanically enforced
add_pp_test(test_arena)
add_pp_test(test_l2)       # T2: Ethernet/VLAN/QinQ + hostile frames
add_pp_test(test_l3)       # T3: IPv4/IPv6, ext-header chains, fragments, liars
add_pp_test(test_l4)       # T4: TCP/UDP/ICMP + VXLAN tunnel re-entry
add_pp_test(test_pcap)     # T5: pcap replay backend + broken files
add_pp_test(test_rules)    # T6: the C++17 control plane
add_pp_test(test_classify) # T7: rules meeting packets
add_pp_test(test_noalloc)  # T9: THE zero-allocation proof (SPEC 7.1)
