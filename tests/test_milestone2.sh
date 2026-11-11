#!/usr/bin/env bash
# Tests for Milestone 2: Native Networking, FD Hygiene, Mount Isolation, tmpfs /dev, and Error Protocol.
set -euo pipefail

BIN="./bin/nanorock"
ROOTFS="./rootfs"
FAILED=0

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=1; }

if [ ! -x "$BIN" ]; then
    echo "Binary $BIN not found! Run make first."
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "Rootfs not found, building one..."
    bash scripts/setup-rootfs.sh "$ROOTFS"
fi

echo "=== Milestone 2 Verification Suite ==="

# 1. Native loopback setup
echo "[1] Testing native loopback setup via ioctl..."
LO_STATE=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip link show lo" 2>/dev/null || true)
if echo "$LO_STATE" | grep -q "UP"; then
    pass "loopback interface is UP in container network namespace"
else
    fail "loopback interface is not UP: '$LO_STATE'"
fi

# 2. Inherited FD cleanup
echo "[2] Testing inherited file descriptor hygiene..."
# Open extra descriptor 7 pointing to /etc/passwd in parent shell
EXTRA_FDS=$(bash -c 'exec 7</etc/passwd; '"$BIN"' run --rootfs '"$ROOTFS"' -- /bin/ls /proc/self/fd' 2>/dev/null || true)
# Descriptor 7 from parent must be gone. (Note: 3 is ls own opendir handle).
if echo "$EXTRA_FDS" | grep -qx "7"; then
    fail "leaked parent file descriptor 7 detected inside container: $(echo $EXTRA_FDS)"
else
    pass "inherited parent file descriptors (e.g. fd 7) were cleaned up before workload exec"
fi

# 3. Private /dev tmpfs and zero host rootfs mutation
echo "[3] Testing /dev private tmpfs isolation and host protection..."
HOST_DEV_BEFORE=$(ls "$ROOTFS/dev" 2>/dev/null || true)
DEV_TEST=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "touch /dev/test_marker && ls /dev/test_marker" 2>/dev/null || true)
if [ "$DEV_TEST" = "/dev/test_marker" ]; then
    pass "container can write to /dev tmpfs"
else
    fail "writing to /dev failed inside container"
fi

if [ -e "$ROOTFS/dev/test_marker" ]; then
    fail "host rootfs /dev was mutated by container! Host isolation broken."
    rm -f "$ROOTFS/dev/test_marker"
else
    pass "host rootfs ./rootfs/dev was not mutated (private tmpfs invariant holds)"
fi

# 4. Device nodes functionality
echo "[4] Testing device nodes (/dev/null, /dev/zero, /dev/urandom)..."
DEV_NODES_OK=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "echo 'hello' > /dev/null && head -c 4 /dev/zero | wc -c" 2>/dev/null || true)
if [ "$DEV_NODES_OK" = "4" ]; then
    pass "standard device nodes operate correctly in /dev tmpfs"
else
    fail "device node read/write test failed, got: '$DEV_NODES_OK'"
fi

# 5. Mount isolation & pivot_root
echo "[5] Testing mount isolation and old root detachment..."
OLDROOT_EXISTS=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ls -d /.oldroot* 2>/dev/null || true")
if [ -z "$OLDROOT_EXISTS" ]; then
    pass "old root directory is detached and unreachable"
else
    fail "old root remains visible at $OLDROOT_EXISTS"
fi

# 6. /proc mount flags and PID namespace visibility
echo "[6] Testing /proc mount isolation..."
PROC_CMDLINE=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "cat /proc/1/cmdline | tr '\0' ' '" 2>/dev/null || true)
if echo "$PROC_CMDLINE" | grep -q "/bin/sh"; then
    pass "/proc is correctly mounted for container PID namespace"
else
    fail "unexpected /proc/1/cmdline: '$PROC_CMDLINE'"
fi

# 7. Failure propagation: missing rootfs
echo "[7] Testing failure propagation: non-existent rootfs..."
ERR_OUTPUT=$("$BIN" run --rootfs "./nonexistent_dir_12345" -- /bin/sh 2>&1 || true)
if echo "$ERR_OUTPUT" | grep -q "rootfs validation failed"; then
    pass "non-existent rootfs rejected with structured error before launch"
else
    fail "expected rootfs validation failure, got: '$ERR_OUTPUT'"
fi

# 8. Failure propagation: host root protection
echo "[8] Testing failure propagation: host root '/' as rootfs..."
ROOT_REJECT=$("$BIN" run --rootfs "/" -- /bin/sh 2>&1 || true)
if echo "$ROOT_REJECT" | grep -q "refusing to use host root"; then
    pass "host root '/' explicitly rejected as container rootfs"
else
    fail "expected rejection of '/', got: '$ROOT_REJECT'"
fi

# 9. Failure propagation: non-directory rootfs
echo "[9] Testing failure propagation: file as rootfs..."
FILE_REJECT=$("$BIN" run --rootfs "./Makefile" -- /bin/sh 2>&1 || true)
if echo "$FILE_REJECT" | grep -q "rootfs path is not a directory"; then
    pass "file path rejected as rootfs directory"
else
    fail "expected not-a-directory error, got: '$FILE_REJECT'"
fi

# 10. Failure propagation: non-existent executable in container
echo "[10] Testing failure propagation: non-existent command in container..."
EXEC_FAIL=$("$BIN" run --rootfs "$ROOTFS" -- /nonexistent_command_xyz 2>&1 || true)
if echo "$EXEC_FAIL" | grep -q "failed at phase \[exec user workload\]"; then
    pass "execvp failure reported through structured error channel"
else
    fail "expected exec failure phase in error channel, got: '$EXEC_FAIL'"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 2 tests passed successfully."
    exit 0
else
    echo "Some Milestone 2 tests failed."
    exit 1
fi
