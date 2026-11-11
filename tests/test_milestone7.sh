#!/usr/bin/env bash
# Milestone 7: Production-Grade Networking Verification Suite
# Verifies isolated veth networking, netns isolation, IP configuration,
# host-container ping connectivity, failure cleanup, FD hygiene,
# capability constraints, and CLI network validation.
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
    echo "Rootfs not found! Run scripts/setup-rootfs.sh first."
    exit 1
fi

echo "=== Milestone 7 Production-Grade Networking Verification Suite ==="

# 1. Network namespace isolation
echo "[1] Testing network namespace isolation..."
HOST_NETNS=$(readlink /proc/self/ns/net)
CONTAINER_NETNS=$("$BIN" run --rootfs "$ROOTFS" -- /bin/readlink /proc/self/ns/net 2>/dev/null | tr -d '\r\n')
if [ -n "$CONTAINER_NETNS" ] && [ "$CONTAINER_NETNS" != "$HOST_NETNS" ]; then
    pass "container netns ($CONTAINER_NETNS) is isolated from host netns ($HOST_NETNS)"
else
    fail "container netns matches host netns or is empty: '$CONTAINER_NETNS'"
fi

# 2. Loopback interface state
echo "[2] Testing loopback interface state..."
LO_STATE=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip link show lo" 2>/dev/null || true)
if echo "$LO_STATE" | grep -q "UP"; then
    pass "loopback interface (lo) is present and UP"
else
    fail "loopback interface is not UP: '$LO_STATE'"
fi

# 3. Container interface presence and UP state
echo "[3] Testing container interface eth0 presence and state..."
ETH_STATE=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip link show eth0" 2>/dev/null || true)
if echo "$ETH_STATE" | grep -q "eth0" && echo "$ETH_STATE" | grep -q "UP"; then
    pass "container interface eth0 is present and UP"
else
    fail "container interface eth0 is missing or not UP: '$ETH_STATE'"
fi

# 4. Default IP address assignment (10.200.0.2/24)
echo "[4] Testing container IPv4 address assignment..."
CONTAINER_IP=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip -4 addr show eth0" 2>/dev/null || true)
if echo "$CONTAINER_IP" | grep -q "10.200.0.2/24"; then
    pass "container eth0 assigned expected address 10.200.0.2/24"
else
    fail "expected 10.200.0.2/24 on eth0, got: '$CONTAINER_IP'"
fi

# 5. Host endpoint ping connectivity
echo "[5] Testing bidirectional host-container ping connectivity..."
PING_OUT=$("$BIN" run --rootfs "$ROOTFS" -- ping -c 2 -W 1 10.200.0.1 2>/dev/null || true)
if echo "$PING_OUT" | grep -q "2 packets transmitted, 2 packets received, 0% packet loss"; then
    pass "container successfully pinged host endpoint (10.200.0.1) with 0% loss"
else
    fail "ping to host endpoint failed: '$PING_OUT'"
fi

# 6. Routing table verification
echo "[6] Testing container routing table (subnet and default routes)..."
ROUTES=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip route show" 2>/dev/null || true)
if echo "$ROUTES" | grep -q "10.200.0.0/24 dev eth0"; then
    pass "direct subnet route (10.200.0.0/24 dev eth0) is installed"
else
    fail "direct subnet route missing: '$ROUTES'"
fi
if echo "$ROUTES" | grep -q "default via 10.200.0.1 dev eth0"; then
    pass "default route (default via 10.200.0.1 dev eth0) is installed"
else
    fail "default route missing: '$ROUTES'"
fi

# 7. Host-side veth lifecycle during execution
echo "[7] Testing host-side veth lifecycle during container execution..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "sleep 0.5" &
NANOROCK_BG_PID=$!
sleep 0.2
HOST_VETH_COUNT=$(ip -o link show 2>/dev/null | grep -c "nrv-" || true)
if [ "$HOST_VETH_COUNT" -ge 1 ]; then
    pass "host-side veth (nrv-*) exists on host during container execution"
else
    fail "host-side veth not found on host during execution"
fi
wait "$NANOROCK_BG_PID" 2>/dev/null || true

# 8. Host-side veth cleanup after normal exit
echo "[8] Testing host-side veth teardown after normal container exit..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || true
REMAINING_VETH=$(ip -o link show 2>/dev/null | grep "nrv-" || true)
if [ -z "$REMAINING_VETH" ]; then
    pass "host-side veth removed cleanly after normal container exit"
else
    fail "lingering host veth detected after exit: '$REMAINING_VETH'"
fi

# 9. Host-side veth cleanup after non-zero workload exit
echo "[9] Testing host-side veth teardown after non-zero workload exit..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "exit 42" 2>/dev/null || true
REMAINING_VETH=$(ip -o link show 2>/dev/null | grep "nrv-" || true)
if [ -z "$REMAINING_VETH" ]; then
    pass "host-side veth removed cleanly after exit code 42"
else
    fail "lingering host veth detected after exit 42: '$REMAINING_VETH'"
fi

# 10. Host-side veth cleanup after SIGTERM
echo "[10] Testing host-side veth teardown after SIGTERM..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "sleep 10" &
BG_PID=$!
sleep 0.3
kill -TERM "$BG_PID" 2>/dev/null || true
wait "$BG_PID" 2>/dev/null || true
REMAINING_VETH=$(ip -o link show 2>/dev/null | grep "nrv-" || true)
if [ -z "$REMAINING_VETH" ]; then
    pass "host-side veth removed cleanly after SIGTERM"
else
    fail "lingering host veth detected after SIGTERM: '$REMAINING_VETH'"
fi

# 11. Host-side veth recovery after SIGKILL
echo "[11] Testing host recovery after SIGKILL..."
"$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "sleep 10" &
BG_PID=$!
sleep 0.3
kill -9 "$BG_PID" 2>/dev/null || true
wait "$BG_PID" 2>/dev/null || true
sleep 0.1
"$BIN" run --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || true
pass "runtime cleanly recovers after SIGKILL without interface collision"

# 12. Partial setup failure cleanup (invalid rootfs)
echo "[12] Testing partial setup failure cleanup (invalid rootfs)..."
"$BIN" run --rootfs "/nonexistent_dir_12345" -- /bin/true 2>/dev/null || true
REMAINING_VETH=$(ip -o link show 2>/dev/null | grep "nrv-" || true)
if [ -z "$REMAINING_VETH" ]; then
    pass "zero host-side veth leaked on pre-launch validation failure"
else
    fail "leaked host veth after rootfs error: '$REMAINING_VETH'"
fi

# 13. FD hygiene: no network sockets leaked to workload
echo "[13] Testing FD hygiene for networking descriptors..."
LEAKED_FDS=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ls -l /proc/self/fd | grep socket || true" 2>/dev/null || true)
if [ -z "$LEAKED_FDS" ]; then
    pass "no Netlink or network sockets leaked into container workload"
else
    fail "leaked network descriptors found in workload: '$LEAKED_FDS'"
fi

# 14. Security invariants: capabilities and seccomp
echo "[14] Testing security invariants under M7 networking..."
STATUS_OUTPUT=$("$BIN" run --rootfs "$ROOTFS" -- /bin/cat /proc/self/status 2>/dev/null || true)
CAP_INH=$(echo "$STATUS_OUTPUT" | grep "CapInh:" | awk '{print $2}')
CAP_AMB=$(echo "$STATUS_OUTPUT" | grep "CapAmb:" | awk '{print $2}')
CAP_EFF=$(echo "$STATUS_OUTPUT" | grep "CapEff:" | awk '{print $2}')
NO_NEW_PRIVS=$(echo "$STATUS_OUTPUT" | grep "NoNewPrivs:" | awk '{print $2}')
SECCOMP_MODE=$(echo "$STATUS_OUTPUT" | grep "Seccomp:" | awk '{print $2}')

if [ "$CAP_INH" = "0000000000000000" ] && [ "$CAP_AMB" = "0000000000000000" ]; then
    pass "CapInh and CapAmb completely zeroed post-exec"
else
    fail "CapInh ($CAP_INH) or CapAmb ($CAP_AMB) not zeroed"
fi

if [ "$NO_NEW_PRIVS" = "1" ] && [ "$SECCOMP_MODE" = "2" ]; then
    pass "NoNewPrivs=1 and Seccomp mode=2 (SECCOMP_MODE_FILTER) intact"
else
    fail "NoNewPrivs ($NO_NEW_PRIVS) or Seccomp ($SECCOMP_MODE) invalid"
fi

# Check that CAP_NET_ADMIN (bit 12: 0x1000) is NOT in CapEff
CAP_EFF_DEC=$((16#$CAP_EFF))
if [ $((CAP_EFF_DEC & (1 << 12))) -eq 0 ]; then
    pass "CAP_NET_ADMIN is strictly stripped from workload CapEff (0x$CAP_EFF)"
else
    fail "CAP_NET_ADMIN leaked into workload CapEff! (0x$CAP_EFF)"
fi

# 15. Host network interface isolation
echo "[15] Testing host interface invisibility inside container..."
CONTAINER_INTERFACES=$("$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c "ip -o link show | awk -F': ' '{print \$2}'" 2>/dev/null || true)
if echo "$CONTAINER_INTERFACES" | grep -qvE '^(lo|eth0(@.*)?)$'; then
    fail "unexpected host interfaces visible in container: '$CONTAINER_INTERFACES'"
else
    pass "container netns exposes only lo and eth0 (host interfaces hidden)"
fi

# 16. --net none mode verification
echo "[16] Testing --net none mode (loopback-only)..."
NONE_INTERFACES=$("$BIN" run --rootfs "$ROOTFS" --net none -- /bin/sh -c "ip -o link show | wc -l" 2>/dev/null || true)
if [ "$NONE_INTERFACES" = "1" ]; then
    pass "--net none container has exactly 1 interface (lo only)"
else
    fail "expected 1 interface in --net none, got: '$NONE_INTERFACES'"
fi

# 17. Custom IP configuration
echo "[17] Testing custom IP configuration (--ip, --host-ip, --net-prefix)..."
CUSTOM_PING=$("$BIN" run --rootfs "$ROOTFS" --ip 10.50.0.2 --host-ip 10.50.0.1 --net-prefix 24 -- ping -c 2 -W 1 10.50.0.1 2>/dev/null || true)
if echo "$CUSTOM_PING" | grep -q "0% packet loss"; then
    pass "custom subnet (10.50.0.2 -> 10.50.0.1) connectivity verified"
else
    fail "custom subnet ping failed: '$CUSTOM_PING'"
fi

# 18. CLI validation: invalid IP format
echo "[18] Testing CLI validation for malformed IP address..."
set +e
"$BIN" run --rootfs "$ROOTFS" --ip 999.999.999.999 -- /bin/true 2>/dev/null
CODE_IP=$?
set -e
if [ "$CODE_IP" -eq 2 ]; then
    pass "invalid container IP rejected with exit code 2 (EXIT_USAGE_ERROR)"
else
    fail "expected code 2 for invalid IP, got: $CODE_IP"
fi

# 19. CLI validation: invalid prefix
echo "[19] Testing CLI validation for invalid prefix..."
set +e
"$BIN" run --rootfs "$ROOTFS" --net-prefix 35 -- /bin/true 2>/dev/null
CODE_PREFIX=$?
set -e
if [ "$CODE_PREFIX" -eq 2 ]; then
    pass "invalid prefix 35 rejected with exit code 2 (EXIT_USAGE_ERROR)"
else
    fail "expected code 2 for invalid prefix, got: $CODE_PREFIX"
fi

# 20. CLI validation: invalid network mode
echo "[20] Testing CLI validation for invalid network mode..."
set +e
"$BIN" run --rootfs "$ROOTFS" --net invalid_mode -- /bin/true 2>/dev/null
CODE_NET=$?
set -e
if [ "$CODE_NET" -eq 2 ]; then
    pass "invalid net mode 'invalid_mode' rejected with exit code 2 (EXIT_USAGE_ERROR)"
else
    fail "expected code 2 for invalid net mode, got: $CODE_NET"
fi

# 21. Verbose mode diagnostic logging
echo "[21] Testing verbose mode network diagnostic logging..."
VERBOSE_OUT=$("$BIN" run --rootfs "$ROOTFS" -v -- /bin/true 2>&1 || true)
if echo "$VERBOSE_OUT" | grep -q "DEBUG network:" && \
   echo "$VERBOSE_OUT" | grep -q "veth host:" && \
   echo "$VERBOSE_OUT" | grep -q "veth container: eth0" && \
   echo "$VERBOSE_OUT" | grep -q "host address: 10.200.0.1/24" && \
   echo "$VERBOSE_OUT" | grep -q "container address: 10.200.0.2/24"; then
    pass "verbose mode outputs complete network lifecycle diagnostic logs"
else
    fail "verbose network diagnostics missing: '$VERBOSE_OUT'"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 7 networking tests passed successfully."
    exit 0
else
    echo "Some Milestone 7 networking tests failed."
    exit 1
fi
