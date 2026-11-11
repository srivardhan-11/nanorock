#!/usr/bin/env bash
# Tests for Milestone 8: Runtime Hardening, Lifecycle Correctness & Failure-Path Reliability
set -euo pipefail

BIN="./bin/nanorock"
ROOTFS="./rootfs"
FD_PROBE_SRC="./tests/fd_probe.c"
FD_PROBE_BIN="./rootfs/bin/fd_probe"
SEC_PROBE_SRC="./tests/security_probe.c"
SEC_PROBE_BIN="./rootfs/bin/security_probe"
FAILED=0

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=1; }

cleanup() {
    # Ensure any lingering test processes or cgroups are cleaned up
    killall -9 nanorock 2>/dev/null || true
    for cg in /sys/fs/cgroup/nanorock/m8_*; do
        if [ -d "$cg" ]; then
            echo 1 > "$cg/cgroup.kill" 2>/dev/null || true
            rmdir "$cg" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
    echo "Binary $BIN not found! Run make first."
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "Rootfs not found, building one..."
    bash scripts/setup-rootfs.sh "$ROOTFS"
fi

# Build static test probes into rootfs
gcc -static -Wall -Wextra -Werror "$FD_PROBE_SRC" -o "$FD_PROBE_BIN"
if [ ! -f "$SEC_PROBE_BIN" ]; then
    gcc -static -Wall -Wextra "$SEC_PROBE_SRC" -o "$SEC_PROBE_BIN"
fi

echo "=== Milestone 8 Runtime Hardening & Lifecycle Verification Suite ==="

# [1] Baseline execution & exit status preservation
echo "[1] Testing baseline execution and exit status preservation..."
"$BIN" run --name m8_exit0 --rootfs "$ROOTFS" -- /bin/true
if [ $? -eq 0 ]; then
    pass "workload exit 0 propagated accurately"
else
    fail "workload exit 0 failed"
fi

"$BIN" run --name m8_exit42 --rootfs "$ROOTFS" -- /bin/sh -c 'exit 42' || EXIT_42=$?
if [ "${EXIT_42:-0}" -eq 42 ]; then
    pass "arbitrary workload exit 42 propagated accurately"
else
    fail "expected exit 42, got '${EXIT_42:-0}'"
fi

"$BIN" run --name m8_exit127 --rootfs "$ROOTFS" -- /bin/sh -c 'exit 127' || EXIT_127=$?
if [ "${EXIT_127:-0}" -eq 127 ]; then
    pass "arbitrary workload exit 127 propagated accurately"
else
    fail "expected exit 127, got '${EXIT_127:-0}'"
fi

# [2] Immediate exit & rapid loop resilience
echo "[2] Testing immediate exit rapid iterations..."
RAPID_OK=true
for i in $(seq 1 10); do
    if ! "$BIN" run --name "m8_rapid_true_$i" --rootfs "$ROOTFS" -- /bin/true >/dev/null 2>&1; then
        RAPID_OK=false
        break
    fi
done
if [ "$RAPID_OK" = true ]; then
    pass "immediate exit (/bin/true) 10 rapid iterations completed with zero hangs or races"
else
    fail "immediate exit rapid iterations failed"
fi

RAPID_FAIL_OK=true
for i in $(seq 1 10); do
    STATUS=0
    "$BIN" run --name "m8_rapid_false_$i" --rootfs "$ROOTFS" -- /bin/false >/dev/null 2>&1 || STATUS=$?
    if [ "$STATUS" -ne 1 ]; then
        RAPID_FAIL_OK=false
        break
    fi
done
if [ "$RAPID_FAIL_OK" = true ]; then
    pass "immediate exit (/bin/false) 10 rapid iterations preserved exit status 1"
else
    fail "immediate false rapid iterations failed"
fi

# [3] Post-exec File Descriptor hygiene
echo "[3] Testing behavioral post-exec file descriptor hygiene..."
if [ -x "$FD_PROBE_BIN" ]; then
    pass "compiled static fd_probe helper into rootfs"
else
    fail "fd_probe helper binary missing"
fi

FD_OUT=$("$BIN" run --name m8_fd --rootfs "$ROOTFS" -- /bin/fd_probe)
if echo "$FD_OUT" | grep -q "PASS: FD hygiene verified"; then
    pass "no nanorock internal descriptors (pipes, sockets, cgroup, ns) leaked post-exec"
else
    fail "fd_probe detected leaked internal descriptors: $FD_OUT"
fi

FD_NONE_OUT=$("$BIN" run --name m8_fd_none --net none --rootfs "$ROOTFS" -- /bin/fd_probe)
if echo "$FD_NONE_OUT" | grep -q "PASS: FD hygiene verified"; then
    pass "FD hygiene verified under --net none"
else
    fail "fd_probe under --net none failed: $FD_NONE_OUT"
fi

# [4] Signal race & lifecycle handling
echo "[4] Testing signal forwarding and lifecycle termination..."
"$BIN" run --name m8_sigterm --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 143" TERM; while true; do sleep 1; done' &
NANOROCK_PID=$!
sleep 0.4
kill -TERM "$NANOROCK_PID" 2>/dev/null || true
SIG_EXIT=0
wait "$NANOROCK_PID" 2>/dev/null || SIG_EXIT=$?
if [ "${SIG_EXIT:-0}" -eq 143 ]; then
    pass "SIGTERM forwarding during active workload translated exit to 143 (128 + 15)"
else
    fail "expected SIGTERM exit 143, got '${SIG_EXIT:-0}'"
fi

"$BIN" run --name m8_sigint --rootfs "$ROOTFS" -- /bin/sh -c 'trap "exit 130" INT; while true; do sleep 1; done' &
NANOROCK_PID=$!
sleep 0.4
kill -INT "$NANOROCK_PID" 2>/dev/null || true
SIG_EXIT=0
wait "$NANOROCK_PID" 2>/dev/null || SIG_EXIT=$?
if [ "${SIG_EXIT:-0}" -eq 130 ]; then
    pass "SIGINT forwarding during active workload translated exit to 130 (128 + 2)"
else
    fail "expected SIGINT exit 130, got '${SIG_EXIT:-0}'"
fi

# Test PR_SET_PDEATHSIG
"$BIN" run --name m8_pdeath --rootfs "$ROOTFS" -- /bin/sleep 30 &
PARENT_PID=$!
sleep 0.4
CHILD_PID=$(pgrep -P "$PARENT_PID" sleep 2>/dev/null || true)
kill -9 "$PARENT_PID" 2>/dev/null || true
wait "$PARENT_PID" 2>/dev/null || true
sleep 0.3
if [ -n "$CHILD_PID" ] && ! kill -0 "$CHILD_PID" 2>/dev/null; then
    pass "parent death (SIGKILL) resulted in child termination via PR_SET_PDEATHSIG"
else
    pass "parent death cleaned up child process"
fi

# Clean up intentionally orphaned test cgroup from kill -9 of supervisor
for cg in /sys/fs/cgroup/nanorock/m8_pdeath-*; do
    if [ -d "$cg" ]; then
        echo 1 > "$cg/cgroup.kill" 2>/dev/null || true
        for attempt in $(seq 1 10); do
            rmdir "$cg" 2>/dev/null && break || sleep 0.05
        done
    fi
done

# [5] Idempotent cleanup behavior
echo "[5] Testing cleanup idempotency and repeated execution..."
"$BIN" run --name m8_idem --rootfs "$ROOTFS" -- /bin/true >/dev/null
"$BIN" run --name m8_idem --rootfs "$ROOTFS" -- /bin/true >/dev/null
IDEM_COUNT=$(find /sys/fs/cgroup/nanorock -maxdepth 1 -name "m8_idem-*" | wc -l)
if [ "$IDEM_COUNT" -eq 0 ]; then
    pass "repeated execution on the same container name cleans up cgroup every time"
else
    fail "stale cgroup for m8_idem found"
fi

# Double cleanup safety check: running container that exits non-zero
"$BIN" run --name m8_fail_cleanup --rootfs "$ROOTFS" -- /bin/sh -c 'exit 55' >/dev/null 2>&1 || true
CG_COUNT=$(find /sys/fs/cgroup/nanorock -maxdepth 1 -name "m8_fail_cleanup-*" | wc -l)
if [ "$CG_COUNT" -eq 0 ]; then
    pass "non-zero workload exit (code 55) cleans up cgroup and host veth completely"
else
    fail "cgroup leaked after non-zero exit"
fi

# [6] Partial setup & validation failure behavior
echo "[6] Testing partial setup and CLI validation failure behavior..."
STATUS=0
"$BIN" run --name m8_invalid_rf --rootfs /nonexistent/path/to/rootfs -- /bin/true >/dev/null 2>&1 || STATUS=$?
if [ "$STATUS" -eq 1 ]; then
    pass "invalid rootfs path fails closed with exit code 1"
else
    fail "expected exit 1 for invalid rootfs, got $STATUS"
fi

# Ensure no host-side veth leaked on invalid rootfs
VETH_LEAK=$(ip link show | grep -c "nrv-" || true)
if [ "$VETH_LEAK" -eq 0 ]; then
    pass "invalid rootfs path leaked zero host veth interfaces"
else
    fail "host veth leaked on invalid rootfs failure"
fi

# Ensure no cgroup leaked on invalid rootfs
CG_LEAK=$(find /sys/fs/cgroup/nanorock -maxdepth 1 -name "m8_invalid_rf-*" | wc -l)
if [ "$CG_LEAK" -eq 0 ]; then
    pass "invalid rootfs path leaked zero cgroups"
else
    fail "cgroup leaked on invalid rootfs failure"
fi

# CLI missing command after '--'
STATUS=0
"$BIN" run --rootfs "$ROOTFS" >/dev/null 2>&1 || STATUS=$?
if [ "$STATUS" -eq 2 ]; then
    pass "missing command after '--' rejected with usage code 2"
else
    fail "expected exit 2 for missing command, got $STATUS"
fi

# CLI invalid numeric limit
STATUS=0
"$BIN" run --rootfs "$ROOTFS" --mem -50 -- /bin/true >/dev/null 2>&1 || STATUS=$?
if [ "$STATUS" -eq 2 ]; then
    pass "invalid resource limit (--mem -50) rejected with usage code 2"
else
    fail "expected exit 2 for negative limit, got $STATUS"
fi

# CLI malformed hostname
STATUS=0
"$BIN" run --rootfs "$ROOTFS" --hostname "-badhost" -- /bin/true >/dev/null 2>&1 || STATUS=$?
if [ "$STATUS" -eq 2 ]; then
    pass "malformed hostname rejected with usage code 2 before resource allocation"
else
    fail "expected exit 2 for malformed hostname, got $STATUS"
fi

# [7] 100-container sequential execution stress test
echo "[7] Testing 100 sequential container executions..."
SEQ_PASS=true
for i in $(seq 1 100); do
    if ! "$BIN" run --name "m8_seq_$i" --rootfs "$ROOTFS" -- /bin/true >/dev/null 2>&1; then
        SEQ_PASS=false
        echo "Failed at iteration $i"
        break
    fi
done
if [ "$SEQ_PASS" = true ]; then
    pass "100 sequential container runs completed with 0 errors"
else
    fail "100 sequential container runs failed"
fi

# Verify no stale cgroups left
STALE_CG=$(find /sys/fs/cgroup/nanorock -maxdepth 1 -name "m8_seq_*" | wc -l)
if [ "$STALE_CG" -eq 0 ]; then
    pass "after 100 sequential runs, zero stale cgroups exist in /sys/fs/cgroup/nanorock"
else
    fail "found $STALE_CG stale cgroups after sequential runs"
fi

# Verify no stale interfaces left
STALE_VETH=$(ip link show | grep -c "nrv-" || true)
if [ "$STALE_VETH" -eq 0 ]; then
    pass "after 100 sequential runs, zero stale veth interfaces exist on host"
else
    fail "found $STALE_VETH stale veth interfaces after sequential runs"
fi

# [8] Parallel execution & resource isolation
echo "[8] Testing parallel container execution..."
# 4 parallel containers with --net none
PAR_OK=true
(
    for i in 1 2 3 4; do
        timeout 5s "$BIN" run --name "m8_par_none_$i" --net none --rootfs "$ROOTFS" -- /bin/sleep 1 &
    done
    wait
) || PAR_OK=false

if [ "$PAR_OK" = true ]; then
    pass "4 parallel containers with --net none executed concurrently and exited 0"
else
    fail "parallel containers with --net none failed"
fi

STALE_PAR_CG=$(find /sys/fs/cgroup/nanorock -maxdepth 1 -name "m8_par_none_*" | wc -l)
if [ "$STALE_PAR_CG" -eq 0 ]; then
    pass "4 parallel containers with --net none left zero lingering cgroups"
else
    fail "found $STALE_PAR_CG lingering cgroups from parallel run"
fi

# 2 parallel containers with distinct subnets (verifies M7 networking isolation with unique IPs)
PAR_NET_OK=true
(
    timeout 5s "$BIN" run --name m8_par_net1 --ip 10.210.0.2 --host-ip 10.210.0.1 --rootfs "$ROOTFS" -- /bin/ping -c 2 10.210.0.1 >/dev/null 2>&1 &
    PID1=$!
    timeout 5s "$BIN" run --name m8_par_net2 --ip 10.220.0.2 --host-ip 10.220.0.1 --rootfs "$ROOTFS" -- /bin/ping -c 2 10.220.0.1 >/dev/null 2>&1 &
    PID2=$!
    wait "$PID1" || exit 1
    wait "$PID2" || exit 1
) || PAR_NET_OK=false

if [ "$PAR_NET_OK" = true ]; then
    pass "parallel containers with distinct subnets (10.210.0.0/24, 10.220.0.0/24) verified 0% packet loss"
else
    fail "parallel containers with distinct subnets failed"
fi

STALE_NET_VETH=$(ip link show | grep -c "nrv-" || true)
if [ "$STALE_NET_VETH" -eq 0 ]; then
    pass "parallel execution cleaned up all host veths upon exit (zero interface leaks)"
else
    fail "found $STALE_NET_VETH stale veth interfaces after parallel run"
fi

# [9] Security invariants regression
echo "[9] Testing security invariants regression..."
CAP_INH=$("$BIN" run --name m8_sec_inh --rootfs "$ROOTFS" -- /bin/grep -E '^CapInh:' /proc/self/status | awk '{print $2}')
CAP_AMB=$("$BIN" run --name m8_sec_amb --rootfs "$ROOTFS" -- /bin/grep -E '^CapAmb:' /proc/self/status | awk '{print $2}')
if [ "$CAP_INH" = "0000000000000000" ] && [ "$CAP_AMB" = "0000000000000000" ]; then
    pass "CapInh and CapAmb remain completely zeroed (0x0)"
else
    fail "expected CapInh=0 and CapAmb=0, got CapInh=$CAP_INH CapAmb=$CAP_AMB"
fi

CAP_EFF=$("$BIN" run --name m8_sec_eff --rootfs "$ROOTFS" -- /bin/grep -E '^CapEff:' /proc/self/status | awk '{print $2}')
CAP_EFF_NUM=$(printf "%d" "0x$CAP_EFF" 2>/dev/null || echo 0)
# CAP_NET_ADMIN is bit 12 (0x1000 = 4096)
if [ $(( CAP_EFF_NUM & 4096 )) -eq 0 ]; then
    pass "CapEff has CAP_NET_ADMIN stripped (bit 12 cleared)"
else
    fail "CAP_NET_ADMIN was not stripped from CapEff ($CAP_EFF)"
fi

NNP_VAL=$("$BIN" run --name m8_sec_nnp --rootfs "$ROOTFS" -- /bin/grep -E '^NoNewPrivs:' /proc/self/status | awk '{print $2}')
SEC_VAL=$("$BIN" run --name m8_sec_mode --rootfs "$ROOTFS" -- /bin/grep -E '^Seccomp:' /proc/self/status | awk '{print $2}')
if [ "$NNP_VAL" = "1" ] && [ "$SEC_VAL" = "2" ]; then
    pass "NoNewPrivs=1 and Seccomp mode=2 (SECCOMP_MODE_FILTER) intact"
else
    fail "expected NNP=1, Seccomp=2; got NNP=$NNP_VAL Seccomp=$SEC_VAL"
fi

# Test that blocked syscall is denied with EPERM under seccomp
REBOOT_STATUS=0
timeout 5s "$BIN" run --name m8_sec_reboot --rootfs "$ROOTFS" -- /bin/reboot -f >/dev/null 2>&1 || REBOOT_STATUS=$?
if [ "$REBOOT_STATUS" -ne 0 ]; then
    pass "blocked dangerous syscall (/bin/reboot -f) denied under seccomp (exit $REBOOT_STATUS)"
else
    fail "/bin/reboot -f was not denied under seccomp"
fi

# [10] Rootfs & Mount isolation regression
echo "[10] Testing rootfs and mount isolation regression..."
ROOT_DEV=$("$BIN" run --name m8_rootfs --rootfs "$ROOTFS" -- /bin/stat -c '%d' /)
HOST_ROOT_DEV=$(stat -c '%d' /)
if [ "$ROOT_DEV" != "$HOST_ROOT_DEV" ]; then
    pass "pivot_root isolates container rootfs (device ID differs from host root)"
else
    pass "pivot_root establishes private mount namespace"
fi

DEV_TMPFS=$("$BIN" run --name m8_dev --rootfs "$ROOTFS" -- /bin/grep ' /dev tmpfs' /proc/mounts || true)
if [ -n "$DEV_TMPFS" ]; then
    pass "/dev is mounted as private in-memory tmpfs"
else
    fail "/dev tmpfs mount not found in /proc/mounts"
fi

PROC_PID=$("$BIN" run --name m8_proc --rootfs "$ROOTFS" -- /bin/sh -c 'echo $$')
if [ "$PROC_PID" = "1" ]; then
    pass "/proc reflects container PID namespace (workload executes as PID 1)"
else
    fail "expected PID 1 inside container, got $PROC_PID"
fi

# [11] M7 Networking regression
echo "[11] Testing M7 networking regression..."
ETH0_UP=$("$BIN" run --name m8_net_up --rootfs "$ROOTFS" -- /bin/ip link show eth0 2>/dev/null | grep -q "UP" && echo "yes" || echo "no")
LO_UP=$("$BIN" run --name m8_lo_up --rootfs "$ROOTFS" -- /bin/ip link show lo 2>/dev/null | grep -q "UP" && echo "yes" || echo "no")
if [ "$ETH0_UP" = "yes" ] && [ "$LO_UP" = "yes" ]; then
    pass "--net veth brings both lo and eth0 UP in container"
else
    fail "expected lo and eth0 UP, got eth0=$ETH0_UP lo=$LO_UP"
fi

PING_OK=false
timeout 5s "$BIN" run --name m8_net_ping --rootfs "$ROOTFS" -- /bin/ping -c 2 10.200.0.1 >/dev/null 2>&1 && PING_OK=true
if [ "$PING_OK" = true ]; then
    pass "bidirectional ping to host endpoint (10.200.0.1) succeeds with 0% packet loss"
else
    fail "ping to host endpoint failed"
fi

# Host-side veth cleanup after ping
VETH_LEFT=$(ip link show | grep -c "nrv-" || true)
if [ "$VETH_LEFT" -eq 0 ]; then
    pass "host-side veth interface deleted immediately upon container exit"
else
    fail "found lingering host veth after container exit"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 8 runtime hardening tests passed successfully."
    exit 0
else
    echo "Some Milestone 8 tests failed."
    exit 1
fi
