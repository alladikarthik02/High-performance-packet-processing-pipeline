# pktpipe development environment — Linux, because the project targets Linux.
#
# WHY THIS EXISTS (SPEC §5):
# The résumé claim is "worked against the Linux networking stack". AF_PACKET and
# PACKET_MMAP are Linux kernel interfaces that simply do not exist on macOS —
# Darwin captures via /dev/bpf instead. Building on the host and #ifdef'ing the
# Linux paths would mean shipping code that was never executed. So the whole
# project is built and tested on Linux, and this file *is* that Linux.
#
# Reproducibility is the second reason. The compiler, libc, and toolchain are
# pinned here, so the benchmark numbers in the README are attributable to a
# named environment rather than to "my laptop". Anyone — including an
# interviewer — can rebuild and re-measure.
FROM debian:bookworm-slim

# One RUN layer: each RUN is a layer, and splitting these would cache-bust the
# whole apt tree every time one package changes.
RUN apt-get update && apt-get install -y --no-install-recommends \
      # --- toolchain ---
      build-essential \
      cmake \
      gcc \
      g++ \
      # clang as well as gcc, deliberately: the parser's strict-aliasing and
      # alignment behaviour (SPEC §7.2) is exactly the kind of thing where two
      # compilers disagree. Building with both is how that claim gets tested
      # rather than asserted.
      clang \
      # The compiler-rt runtimes. Debian ships these SEPARATELY from clang, so
      # `-fsanitize=fuzzer,address` compiles fine and then fails at LINK with
      # "cannot find libclang_rt.fuzzer-aarch64.a" — a confusing error that
      # looks like a code problem and is a packaging one. Needed for T14:
      # libFuzzer, ASan and UBSan all live here.
      libclang-rt-14-dev \
      # --- capture ---
      libpcap-dev \
      tcpdump \
      # --- networking: veth pairs and network namespaces, so we can generate
      # and capture real traffic with no physical NIC (SPEC §5) ---
      iproute2 \
      iputils-ping \
      netcat-openbsd \
      # --- profiling & debugging (T13) ---
      linux-perf \
      gdb \
      valgrind \
      strace \
      # --- misc ---
      python3 \
      git \
      vim-tiny \
      procps \
      file \
      bsdmainutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Reported by tools/cacheinfo and the benchmark harness so results name their
# environment instead of floating free.
ENV PP_ENV=docker-debian-bookworm

CMD ["/bin/bash"]
