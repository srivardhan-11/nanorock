#!/usr/bin/env bash
# Tests for Milestone 4: Security Hardening (Capabilities, PR_SET_NO_NEW_PRIVS, Raw Seccomp-BPF)
set -euo pipefail

BIN="./bin/nanorock"
ROOTFS="./rootfs"
PROBE_SRC="./tests/security_probe.c"
PROBE_BIN="./rootfs/bin/security_probe"
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

# Compile security probe helper into rootfs
gcc -static -Wall -Wextra "$PROBE_SRC" -o "$PROBE_BIN"

echo "=== Milestone 4 Security Hardening Verification Suite ==="

# 1. Verify NoNewPrivs in /proc/self/status
echo "[1] Testing PR_SET_NO_NEW_PRIVS state..."
NNP_VAL=$("$BIN" run --rootfs "$ROOTFS" -- /bin/grep -E '^NoNewPrivs:' /proc/self/status | awk '{print $2}')
if [ "$NNP_VAL" = "1" ]; then
    pass "NoNewPrivs is active inside container (1)"
else
    fail "expected NoNewPrivs=1, got '$NNP_VAL'"
fi

# 2. Verify Seccomp filter active in /proc/self/status
echo "[2] Testing Seccomp mode and filter count..."
SEC_VAL=$("$BIN" run --rootfs "$ROOTFS" -- /bin/grep -E '^Seccomp:' /proc/self/status | awk '{print $2}')
SEC_FILTERS=$("$BIN" run --rootfs "$ROOTFS" -- /bin/grep -E '^Seccomp_filters:' /proc/self/status | awk '{print $2}')
if [ "$SEC_VAL" = "2" ] && [ "$SEC_FILTERS" = "1" ]; then
    pass "Seccomp is active in mode 2 (SECCOMP_MODE_FILTER) with 1 filter"
else
    fail "expected Seccomp=2 with 1 filter, got Seccomp=$SEC_VAL filters=$SEC_FILTERS"
fi

# 3. Verify Capability Sets (Ambient, Inheritable, Bounding, Permitted, Effective)
echo "[3] Testing Capability sets state..."
STATUS_OUT=$("$BIN" run --rootfs "$ROOTFS" -- /bin/grep -E '^Cap' /proc/self/status)
CAP_INH=$(echo "$STATUS_OUT" | grep '^CapInh:' | awk '{print $2}')
CAP_AMB=$(echo "$STATUS_OUT" | grep '^CapAmb:' | awk '{print $2}')
CAP_BND=$(echo "$STATUS_OUT" | grep '^CapBnd:' | awk '{print $2}')
CAP_PRM=$(echo "$STATUS_OUT" | grep '^CapPrm:' | awk '{print $2}')
CAP_EFF=$(echo "$STATUS_OUT" | grep '^CapEff:' | awk '{print $2}')

if [ "$CAP_AMB" = "0000000000000000" ]; then
    pass "ambient capabilities completely cleared (CapAmb=0)"
else
    fail "ambient capabilities not cleared: '$CAP_AMB'"
fi

if [ "$CAP_INH" = "0000000000000000" ]; then
    pass "inheritable capabilities zeroed (CapInh=0)"
else
    fail "inheritable capabilities not zero: '$CAP_INH'"
fi

if [ "$CAP_BND" = "00000000b884effb" ]; then
    pass "bounding set stripped of all 21 dangerous capabilities (CapBnd=$CAP_BND)"
else
    fail "bounding set mismatch: expected '00000000b884effb', got '$CAP_BND'"
fi

if [ "$CAP_PRM" = "$CAP_BND" ] && [ -n "$CAP_PRM" ]; then
    pass "permitted set strictly constrained to bounding set post-exec (CapPrm=$CAP_PRM)"
else
    fail "permitted set mismatch: expected '$CAP_BND', got '$CAP_PRM'"
fi

if [ "$CAP_EFF" = "$CAP_BND" ] && [ -n "$CAP_EFF" ]; then
    pass "effective set strictly constrained to bounding set post-exec (CapEff=$CAP_EFF)"
else
    fail "effective set mismatch: expected '$CAP_BND', got '$CAP_EFF'"
fi

# 4. Behavioral syscall denial and capability probe
echo "[4] Running in-container behavioral security probe..."
PROBE_OUT=$("$BIN" run --rootfs "$ROOTFS" -- /bin/security_probe 2>&1 || true)
if echo "$PROBE_OUT" | grep -q "SECURITY_PROBE_SUCCESS"; then
    pass "in-container probe verified credential state, capability restrictions, and 20+ syscall denials"
else
    fail "security probe reported failure: $(echo "$PROBE_OUT" | grep -E '(FAIL|SECURITY)')"
fi

# 5. Workload compatibility with standard userland tools
echo "[5] Testing workload compatibility with standard programs..."
if "$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "echo shell_ok" >/dev/null 2>&1; then
    pass "workload executes cleanly under seccomp: /bin/sh -c 'echo shell_ok'"
else
    fail "workload broke under seccomp: /bin/sh -c 'echo shell_ok'"
fi

for CMD in "/bin/ls /" "/bin/cat /etc/passwd" "/bin/sleep 0.1"; do
    if "$BIN" run --rootfs "$ROOTFS" -- $CMD >/dev/null 2>&1; then
        pass "workload executes cleanly under seccomp: $CMD"
    else
        fail "workload broke under seccomp: $CMD"
    fi
done

# 6. Insecure development bypass flag (--no-seccomp)
echo "[6] Testing --no-seccomp development bypass..."
NOSEC_OUT=$("$BIN" run --rootfs "$ROOTFS" --no-seccomp -- /bin/grep -E '^Seccomp:' /proc/self/status 2>&1 || true)
if echo "$NOSEC_OUT" | grep -q "running in insecure mode: seccomp-BPF filter is DISABLED"; then
    pass "insecure mode warning displayed when --no-seccomp passed"
else
    fail "missing insecure mode warning on --no-seccomp"
fi

NOSEC_MODE=$(echo "$NOSEC_OUT" | grep '^Seccomp:' | awk '{print $2}')
if [ "$NOSEC_MODE" = "0" ]; then
    pass "seccomp is mode 0 (disabled) when --no-seccomp passed"
else
    fail "expected Seccomp=0 with --no-seccomp, got '$NOSEC_MODE'"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 4 security tests passed successfully."
    exit 0
else
    echo "Some Milestone 4 security tests failed."
    exit 1
fi
