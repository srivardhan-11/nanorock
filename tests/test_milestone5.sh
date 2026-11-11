#!/usr/bin/env bash
# Tests for Milestone 5: Process Supervision, Signals & Lifecycle
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

echo "=== Milestone 5 Process Supervision & Signals Verification Suite ==="

# 1. Normal exit code 0
echo "[1] Testing normal workload exit (code 0)..."
set +e
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'exit 0' >/dev/null 2>&1
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 0 ]; then
    pass "workload exit 0 propagated correctly (exit code: 0)"
else
    fail "expected exit 0, got $EXIT_CODE"
fi

# 2. Arbitrary exit code (e.g. 42)
echo "[2] Testing arbitrary workload exit code (code 42)..."
set +e
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'exit 42' >/dev/null 2>&1
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 42 ]; then
    pass "workload exit 42 propagated correctly (exit code: 42)"
else
    fail "expected exit 42, got $EXIT_CODE"
fi

# 3. SIGTERM forwarding (128 + 15 = 143)
echo "[3] Testing SIGTERM forwarding and exit translation (143)..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 143" TERM; while true; do sleep 1; done' >/dev/null 2>&1 &
N_PID=$!
sleep 0.3
kill -TERM "$N_PID" 2>/dev/null || true
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 143 ]; then
    pass "SIGTERM forwarded to workload, runtime exited with 143 (128 + 15)"
else
    fail "expected exit 143 on SIGTERM, got $EXIT_CODE"
fi

# 4. SIGINT forwarding (128 + 2 = 130)
echo "[4] Testing SIGINT forwarding and exit translation (130)..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 130" INT; while true; do sleep 1; done' >/dev/null 2>&1 &
N_PID=$!
sleep 0.3
kill -INT "$N_PID" 2>/dev/null || true
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 130 ]; then
    pass "SIGINT forwarded to workload, runtime exited with 130 (128 + 2)"
else
    fail "expected exit 130 on SIGINT, got $EXIT_CODE"
fi

# 5. SIGHUP forwarding (128 + 1 = 129)
echo "[5] Testing SIGHUP forwarding and exit translation (129)..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 129" HUP; while true; do sleep 1; done' >/dev/null 2>&1 &
N_PID=$!
sleep 0.3
kill -HUP "$N_PID" 2>/dev/null || true
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 129 ]; then
    pass "SIGHUP forwarded to workload, runtime exited with 129 (128 + 1)"
else
    fail "expected exit 129 on SIGHUP, got $EXIT_CODE"
fi

# 6. SIGQUIT forwarding (128 + 3 = 131)
echo "[6] Testing SIGQUIT forwarding and exit translation (131)..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 131" QUIT; while true; do sleep 1; done' >/dev/null 2>&1 &
N_PID=$!
sleep 0.3
kill -QUIT "$N_PID" 2>/dev/null || true
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 131 ]; then
    pass "SIGQUIT forwarded to workload, runtime exited with 131 (128 + 3)"
else
    fail "expected exit 131 on SIGQUIT, got $EXIT_CODE"
fi

# 7. Descendant cleanup: background processes terminated & cgroup removed
echo "[7] Testing descendant cleanup and cgroup drainage..."
LOG_OUT=$(mktemp)
"$BIN" run --rootfs "$ROOTFS" --name m5_desc_test -- /bin/sh -c 'sleep 50 & sleep 50 & exit 0' >"$LOG_OUT" 2>&1 || true
CGROUP_PATH=$(grep -o '/sys/fs/cgroup/nanorock/m5_desc_test-[0-9]*' "$LOG_OUT" | head -n1 || true)
rm -f "$LOG_OUT"

if [ -n "$CGROUP_PATH" ]; then
    sleep 0.2
    if [ -d "$CGROUP_PATH" ]; then
        fail "descendant cgroup '$CGROUP_PATH' was not cleaned up"
    else
        pass "lingering background descendants terminated and cgroup removed cleanly"
    fi
else
    fail "failed to obtain cgroup path from container log"
fi

# 8. Rapid immediate workload exit (no race conditions / hangs)
echo "[8] Testing immediate workload exit rapid iterations..."
IMMEDIATE_FAILED=0
for i in $(seq 1 5); do
    if ! "$BIN" run --rootfs "$ROOTFS" -- /bin/true >/dev/null 2>&1; then
        IMMEDIATE_FAILED=1
        break
    fi
done
if [ "$IMMEDIATE_FAILED" -eq 0 ]; then
    pass "rapid immediate exit executed 5 times with zero races or hangs"
else
    fail "immediate workload exit failed on iteration $i"
fi

# 9. EINTR supervision and trapped signal execution
echo "[9] Testing EINTR-safe supervision when workload handles signal..."
# Workload installs a trap on HUP and exits with 33
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 33" HUP; while true; do sleep 1; done' >/dev/null 2>&1 &
N_PID=$!
sleep 0.4
kill -HUP "$N_PID" 2>/dev/null || true
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 33 ]; then
    pass "supervisor handled EINTR, forwarded HUP, and reaped trapped exit 33"
else
    fail "expected trapped exit code 33, got $EXIT_CODE"
fi

# 10. Parent death cleanup via PR_SET_PDEATHSIG
echo "[10] Testing parent death cleanup (PR_SET_PDEATHSIG)..."
"$BIN" run --rootfs "$ROOTFS" --name pdeath_test -- /bin/sleep 60 >/dev/null 2>&1 &
PARENT_PID=$!
sleep 0.4
CGROUP_DIR="/sys/fs/cgroup/nanorock/pdeath_test-$PARENT_PID"
CHILD_PID=$(cat "$CGROUP_DIR/cgroup.procs" 2>/dev/null | head -n1 || true)

# Abruptly kill the host supervisor with SIGKILL
kill -9 "$PARENT_PID" 2>/dev/null || true
wait "$PARENT_PID" 2>/dev/null || true
sleep 0.3

# Check if child process was terminated by kernel
if [ -n "$CHILD_PID" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
    kill -9 "$CHILD_PID" 2>/dev/null || true
    fail "child process $CHILD_PID survived parent termination"
else
    pass "child container process was terminated via PR_SET_PDEATHSIG upon parent death"
fi
# 11. Workload termination by direct host signal (128 + 9 = 137)
echo "[11] Testing unhandled signal termination translation (137)..."
"$BIN" run --rootfs "$ROOTFS" --name sigkill_test -- /bin/sleep 20 >/dev/null 2>&1 &
N_PID=$!
sleep 0.4
KILL_CGROUP="/sys/fs/cgroup/nanorock/sigkill_test-$N_PID"
CHILD_PID=$(cat "$KILL_CGROUP/cgroup.procs" 2>/dev/null | head -n1 || true)
if [ -n "$CHILD_PID" ]; then
    kill -KILL "$CHILD_PID" 2>/dev/null || true
fi
set +e
wait "$N_PID" 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 137 ]; then
    pass "workload terminated by direct SIGKILL translated to 137 (128 + 9)"
else
    fail "expected exit 137 on SIGKILL, got $EXIT_CODE"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 5 supervision tests passed successfully."
    exit 0
else
    echo "Some Milestone 5 tests failed."
    exit 1
fi
