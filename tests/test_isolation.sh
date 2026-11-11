#!/usr/bin/env bash
# Automated checks that nanorock's namespace isolation actually holds.
# Run via `make test` (needs root - namespaces require CAP_SYS_ADMIN).
set -euo pipefail

BIN="./bin/nanorock"
ROOTFS="./rootfs"
FAILED=0

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=1; }

if [ ! -x "$BIN" ]; then
    echo "Build nanorock first: make"
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "Rootfs not found, building one..."
    bash scripts/setup-rootfs.sh "$ROOTFS"
fi

echo "== Test 1: UTS namespace (hostname isolation) =="
HOST_HOSTNAME=$(hostname)
CONTAINER_HOSTNAME=$("$BIN" run --rootfs "$ROOTFS" --hostname isolated-test-box -- /bin/hostname)
if [ "$CONTAINER_HOSTNAME" = "isolated-test-box" ] && [ "$CONTAINER_HOSTNAME" != "$HOST_HOSTNAME" ]; then
    pass "container hostname is isolated ($CONTAINER_HOSTNAME != $HOST_HOSTNAME)"
else
    fail "expected 'isolated-test-box', got '$CONTAINER_HOSTNAME'"
fi

echo "== Test 2: PID namespace (container process becomes PID 1) =="
CONTAINER_PID=$("$BIN" run --rootfs "$ROOTFS" --hostname box -- /bin/sh -c 'echo $$')
if [ "$CONTAINER_PID" = "1" ]; then
    pass "container's init is PID 1 inside its own namespace"
else
    fail "expected PID 1, got '$CONTAINER_PID'"
fi

echo "== Test 3: mount namespace (host filesystem not visible) =="
CONTAINER_ROOT_LISTING=$("$BIN" run --rootfs "$ROOTFS" --hostname box -- /bin/ls /)
if echo "$CONTAINER_ROOT_LISTING" | grep -qx "home"; then
    fail "container can see the host's /home - pivot_root isolation broken"
else
    pass "container's / does not expose the host filesystem"
fi

echo "== Test 4: network namespace (loopback present, isolated from host) =="
CONTAINER_IF=$("$BIN" run --rootfs "$ROOTFS" --hostname box -- /bin/sh -c "ip -o link show 2>/dev/null | wc -l")
if [ "$CONTAINER_IF" = "2" ] || [ "$CONTAINER_IF" = "1" ]; then
    pass "container network namespace has isolated interfaces (lo and eth0)"
else
    fail "expected isolated interfaces (got $CONTAINER_IF)"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
