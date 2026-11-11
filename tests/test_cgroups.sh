#!/usr/bin/env bash
# Tests for Milestone 3: Cgroup v2 Collision Resistance, Input Validation, Enforcement, and Teardown.
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

echo "=== Milestone 3 Cgroups v2 Verification Suite ==="

# 1. Strict container name validation
echo "[1] Testing container name validation and path traversal rejection..."
for BAD_NAME in "" "." ".." "../traversal" "../../traversal" "sub/dir" "sub\\dir" "-leading" ".dotstart" "name_exceeding_64_chars_12345678901234567890123456789012345678901234567890"; do
    ERR=$("$BIN" run --rootfs "$ROOTFS" --name "$BAD_NAME" -- /bin/true 2>&1 || true)
    if echo "$ERR" | grep -q "invalid container name"; then
        pass "rejected invalid name: '$BAD_NAME'"
    else
        fail "failed to reject invalid name: '$BAD_NAME' (output: '$ERR')"
    fi
done

# 2. Strict resource limit input validation
echo "[2] Testing resource limit numeric validation..."
for BAD_ARG in "--mem 0" "--mem -10" "--mem abc" "--cpu 0" "--cpu -5" "--cpu 1000000" "--pids-max 0" "--pids-max -1" "--pids-max 99999999"; do
    ERR=$("$BIN" run --rootfs "$ROOTFS" $BAD_ARG -- /bin/true 2>&1 || true)
    if echo "$ERR" | grep -q "invalid value for"; then
        pass "rejected invalid resource limit: '$BAD_ARG'"
    else
        fail "failed to reject invalid resource limit: '$BAD_ARG' (output: '$ERR')"
    fi
done

# 3. Collision resistance & unique instance naming (concurrent execution with identical names)
echo "[3] Testing concurrent container execution with identical names..."
LOG1=$(mktemp)
LOG2=$(mktemp)
"$BIN" run --rootfs "$ROOTFS" --name concurrent_test -- /bin/sleep 1 >"$LOG1" 2>&1 &
PID1=$!
"$BIN" run --rootfs "$ROOTFS" --name concurrent_test -- /bin/sleep 1 >"$LOG2" 2>&1 &
PID2=$!

wait $PID1 || true
wait $PID2 || true

CGROUP1=$(grep -o '/sys/fs/cgroup/nanorock/concurrent_test-[0-9]*' "$LOG1" | head -n1 || true)
CGROUP2=$(grep -o '/sys/fs/cgroup/nanorock/concurrent_test-[0-9]*' "$LOG2" | head -n1 || true)

if [ -n "$CGROUP1" ] && [ -n "$CGROUP2" ] && [ "$CGROUP1" != "$CGROUP2" ]; then
    pass "concurrent containers allocated distinct cgroups ($CGROUP1 != $CGROUP2)"
else
    fail "concurrent containers did not receive distinct cgroups: '$CGROUP1' vs '$CGROUP2'"
fi

# Ensure both cgroups were cleaned up
if [ -d "$CGROUP1" ] || [ -d "$CGROUP2" ]; then
    fail "cgroup directory left behind after exit: '$CGROUP1' or '$CGROUP2'"
else
    pass "both concurrent cgroup directories removed cleanly"
fi
rm -f "$LOG1" "$LOG2"

# 4. Limit readback and verification
echo "[4] Testing limit configuration readback verification..."
VERIFY_OUT=$("$BIN" run --rootfs "$ROOTFS" --name verify_test --mem 32 --cpu 50 --pids-max 20 -- /bin/true 2>&1 || true)
if echo "$VERIFY_OUT" | grep -q "memory limit verified: 32 MB" && \
   echo "$VERIFY_OUT" | grep -q "cpu quota verified: 50%" && \
   echo "$VERIFY_OUT" | grep -q "pids limit verified: 20"; then
    pass "memory, cpu, and pids limits successfully written and verified by readback"
else
    fail "limit readback verification failed: '$VERIFY_OUT'"
fi

# 5. Behavioral enforcement: memory.max (OOM trigger)
echo "[5] Testing behavioral enforcement: memory.max OOM..."
OOM_OUT=$("$BIN" run --rootfs "$ROOTFS" --name oom_test --mem 16 -- /bin/dd if=/dev/zero of=/dev/test_blob bs=1M count=32 2>&1 || true)
if echo "$OOM_OUT" | grep -q "was killed by signal 9"; then
    pass "kernel OOM killer terminated process exceeding memory.max (16MB)"
else
    fail "expected OOM killer signal 9, got: '$OOM_OUT'"
fi

# 6. Behavioral enforcement: pids.max
echo "[6] Testing behavioral enforcement: pids.max fork restriction..."
PID_TEST_OUT=$("$BIN" run --rootfs "$ROOTFS" --name pids_test --pids-max 4 -- /bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do sleep 5 & done; wait' 2>&1 || true)
if echo "$PID_TEST_OUT" | grep -qi "fork" || echo "$PID_TEST_OUT" | grep -qi "Resource temporarily unavailable"; then
    pass "pids.max (4) successfully blocked excess process creation"
else
    fail "pids.max did not prevent fork bomb / excess processes: '$PID_TEST_OUT'"
fi

# 7. Descendant cleanup & lingering process termination (cgroup.kill)
echo "[7] Testing descendant cleanup and cgroup drainage..."
LINGER_LOG=$(mktemp)
"$BIN" run --rootfs "$ROOTFS" --name linger_test -- /bin/sh -c "sleep 50 & sleep 50 & exit 0" >"$LINGER_LOG" 2>&1 || true
LINGER_CGROUP=$(grep -o '/sys/fs/cgroup/nanorock/linger_test-[0-9]*' "$LINGER_LOG" | head -n1 || true)

if [ -n "$LINGER_CGROUP" ]; then
    sleep 0.2
    if [ -d "$LINGER_CGROUP" ]; then
        fail "lingering cgroup '$LINGER_CGROUP' still exists after container termination"
    else
        pass "cgroup with lingering background descendants was drained and removed cleanly"
    fi
else
    fail "could not identify linger cgroup path from log: $(cat "$LINGER_LOG")"
fi
rm -f "$LINGER_LOG"

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 3 cgroup tests passed successfully."
    exit 0
else
    echo "Some Milestone 3 tests failed."
    exit 1
fi
