#!/usr/bin/env bash
# dev.sh — run pktpipe's toolchain inside the Linux dev container.
#
# The project targets Linux (SPEC §5), so "build" and "test" mean "build and
# test on Linux". This wrapper is the single door to that environment.
#
#   ./docker/dev.sh build            # build the image
#   ./docker/dev.sh shell            # interactive Linux shell in /work
#   ./docker/dev.sh run <cmd...>     # run one command in the container
#   ./docker/dev.sh cmake            # configure the Linux build tree
#   ./docker/dev.sh make             # build it
#   ./docker/dev.sh test             # ctest
#   ./docker/dev.sh ci               # configure + build + test, from scratch
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=pktpipe-dev
BUILD_DIR=build-linux   # kept separate from the host's ./build so the two
                        # toolchains never fight over CMake's cache

# Docker Desktop's credential helper lives inside the .app and is not on PATH in
# a non-login shell. Prepending it here beats editing ~/.docker/config.json,
# which is the user's machine config and none of this project's business.
if [[ -d /Applications/Docker.app/Contents/Resources/bin ]]; then
  export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
fi

# Capabilities, granted deliberately rather than by reaching for --privileged:
#   NET_RAW   — open AF_PACKET sockets (T10). This is THE capability the
#               résumé's R7 claim depends on.
#   NET_ADMIN — create veth pairs and network namespaces, so we can generate
#               and capture real traffic without a physical NIC (SPEC §5).
#   SYS_ADMIN — perf_event_open for profiling (T13).
# Naming the three we need documents *why* each is needed; --privileged would
# work and would say nothing.
CAPS=(--cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN)

# perf_event_paranoid defaults to 2, which blocks the profiler. This is a
# sysctl INSIDE the container's Linux VM — it does not touch the macOS host.
SYSCTLS=()

dk() {
  docker run --rm -it \
    "${CAPS[@]}" \
    -v "$REPO":/work \
    -w /work \
    "$IMAGE" "$@"
}

# Non-interactive variant (no -t) so output pipes cleanly in scripts/CI.
dk_quiet() {
  docker run --rm \
    "${CAPS[@]}" \
    -v "$REPO":/work \
    -w /work \
    "$IMAGE" "$@"
}

cmd="${1:-shell}"; shift || true

case "$cmd" in
  build)
    docker build -f "$REPO/docker/Dockerfile" -t "$IMAGE" "$REPO"
    ;;
  shell)
    dk /bin/bash
    ;;
  run)
    dk_quiet "$@"
    ;;
  cmake)
    dk_quiet cmake -B "$BUILD_DIR" -S . "$@"
    ;;
  make)
    dk_quiet cmake --build "$BUILD_DIR" -j "$@"
    ;;
  test)
    dk_quiet ctest --test-dir "$BUILD_DIR" --output-on-failure "$@"
    ;;
  ci)
    dk_quiet bash -c "rm -rf $BUILD_DIR && cmake -B $BUILD_DIR -S . && cmake --build $BUILD_DIR -j && ctest --test-dir $BUILD_DIR --output-on-failure"
    ;;
  *)
    echo "usage: $0 {build|shell|run|cmake|make|test|ci}" >&2
    exit 2
    ;;
esac
