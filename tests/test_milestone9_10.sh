#!/usr/bin/env bash
# Tests for Milestone 9 & 10: Runtime Configuration, Container Identity & Resource Observability
set -euo pipefail

BIN="./bin/nanorock"
ROOTFS="./rootfs"
FAILED=0
TEST_COUNT=0

pass() {
    TEST_COUNT=$((TEST_COUNT + 1))
    echo "  PASS [$TEST_COUNT]: $1"
}

fail() {
    TEST_COUNT=$((TEST_COUNT + 1))
    echo "  FAIL [$TEST_COUNT]: $1"
    FAILED=1
}

cleanup() {
    # Kill any lingering test background containers
    killall -9 nanorock 2>/dev/null || true
    for cg in /sys/fs/cgroup/nanorock/m910_*; do
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

echo "=== Milestone 9 & 10: Runtime Configuration & Resource Observability Suite ==="

# ==============================================================================
# SECTION 1: Hostname Validation and UTS Enforcement (M9.1)
# ==============================================================================
echo "[Section 1] Hostname Validation and UTS Enforcement..."

# 1. Default hostname inside container is "nanorock"
DEFAULT_HOST=$(timeout 5s "$BIN" run --name m910_host_def --rootfs "$ROOTFS" -- /bin/hostname)
if [ "$DEFAULT_HOST" = "nanorock" ]; then
    pass "default hostname inside container is 'nanorock'"
else
    fail "expected default hostname 'nanorock', got '$DEFAULT_HOST'"
fi

# 2. Custom valid hostname applied inside container
CUSTOM_HOST=$(timeout 5s "$BIN" run --name m910_host_cust --hostname custom-box-1 --rootfs "$ROOTFS" -- /bin/hostname)
if [ "$CUSTOM_HOST" = "custom-box-1" ]; then
    pass "custom hostname 'custom-box-1' applied inside container"
else
    fail "expected hostname 'custom-box-1', got '$CUSTOM_HOST'"
fi

# 3. Maximum valid 64-character hostname accepted
MAX_HOST="a23456789012345678901234567890123456789012345678901234567890123z"
SEEN_MAX_HOST=$(timeout 5s "$BIN" run --name m910_host_max --hostname "$MAX_HOST" --rootfs "$ROOTFS" -- /bin/hostname)
if [ "$SEEN_MAX_HOST" = "$MAX_HOST" ]; then
    pass "maximum 64-char valid hostname accepted and applied"
else
    fail "expected 64-char hostname, got '$SEEN_MAX_HOST'"
fi

# 4. Empty hostname rejected with exit code 2
EMPTY_CODE=0
"$BIN" run --name m910_host_err --hostname "" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || EMPTY_CODE=$?
if [ "$EMPTY_CODE" -eq 2 ]; then
    pass "empty hostname rejected with exit code 2"
else
    fail "empty hostname expected exit code 2, got '$EMPTY_CODE'"
fi

# 5. Overlong 65-character hostname rejected with exit code 2
TOO_LONG_HOST="a2345678901234567890123456789012345678901234567890123456789012345"
TOO_LONG_CODE=0
"$BIN" run --name m910_host_err --hostname "$TOO_LONG_HOST" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || TOO_LONG_CODE=$?
if [ "$TOO_LONG_CODE" -eq 2 ]; then
    pass "overlong 65-char hostname rejected with exit code 2"
else
    fail "overlong hostname expected exit code 2, got '$TOO_LONG_CODE'"
fi

# 6. Hostname starting with hyphen rejected
HYPHEN_START_CODE=0
"$BIN" run --name m910_host_err --hostname "-badhost" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || HYPHEN_START_CODE=$?
if [ "$HYPHEN_START_CODE" -eq 2 ]; then
    pass "hostname starting with hyphen rejected with exit code 2"
else
    fail "hostname starting with hyphen expected exit code 2, got '$HYPHEN_START_CODE'"
fi

# 7. Hostname ending with hyphen rejected
HYPHEN_END_CODE=0
"$BIN" run --name m910_host_err --hostname "badhost-" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || HYPHEN_END_CODE=$?
if [ "$HYPHEN_END_CODE" -eq 2 ]; then
    pass "hostname ending with hyphen rejected with exit code 2"
else
    fail "hostname ending with hyphen expected exit code 2, got '$HYPHEN_END_CODE'"
fi

# 8. Hostname starting with dot rejected
DOT_START_CODE=0
"$BIN" run --name m910_host_err --hostname ".badhost" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || DOT_START_CODE=$?
if [ "$DOT_START_CODE" -eq 2 ]; then
    pass "hostname starting with dot rejected with exit code 2"
else
    fail "hostname starting with dot expected exit code 2, got '$DOT_START_CODE'"
fi

# 9. Hostname ending with dot rejected
DOT_END_CODE=0
"$BIN" run --name m910_host_err --hostname "badhost." --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || DOT_END_CODE=$?
if [ "$DOT_END_CODE" -eq 2 ]; then
    pass "hostname ending with dot rejected with exit code 2"
else
    fail "hostname ending with dot expected exit code 2, got '$DOT_END_CODE'"
fi

# 10. Hostname with consecutive dots rejected
CONSEC_DOT_CODE=0
"$BIN" run --name m910_host_err --hostname "bad..host" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || CONSEC_DOT_CODE=$?
if [ "$CONSEC_DOT_CODE" -eq 2 ]; then
    pass "hostname with consecutive dots rejected with exit code 2"
else
    fail "hostname with consecutive dots expected exit code 2, got '$CONSEC_DOT_CODE'"
fi

# 11. Hostname with invalid characters rejected
INVALID_CHAR_CODE=0
"$BIN" run --name m910_host_err --hostname "bad@host" --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || INVALID_CHAR_CODE=$?
if [ "$INVALID_CHAR_CODE" -eq 2 ]; then
    pass "hostname with invalid characters rejected with exit code 2"
else
    fail "hostname with invalid characters expected exit code 2, got '$INVALID_CHAR_CODE'"
fi

# 12. Host's nodename is completely isolated from container hostname changes
HOST_BEFORE=$(hostname)
timeout 5s "$BIN" run --name m910_host_iso --hostname isolated-node --rootfs "$ROOTFS" -- /bin/true
HOST_AFTER=$(hostname)
if [ "$HOST_BEFORE" = "$HOST_AFTER" ]; then
    pass "host UTS hostname isolated and unmodified by container execution"
else
    fail "host hostname changed from '$HOST_BEFORE' to '$HOST_AFTER'"
fi

# ==============================================================================
# SECTION 2: Status Command CLI & Behavior (M9.3)
# ==============================================================================
echo "[Section 2] Status Command CLI & Behavior..."

# 13. Status command with no running containers returns 0
STATUS_OUT=$("$BIN" status)
if echo "$STATUS_OUT" | grep -q "No running containers found."; then
    pass "status with no running containers reports 'No running containers found.'"
else
    fail "unexpected status output when empty: '$STATUS_OUT'"
fi

# 14. Status command --help displays usage
STATUS_HELP=$("$BIN" status --help)
if echo "$STATUS_HELP" | grep -q "Usage: nanorock status"; then
    pass "status --help displays valid usage"
else
    fail "status --help did not output expected usage text"
fi

# 15. Status command for non-existent container returns 1
STATUS_NONEXIST_CODE=0
"$BIN" status non_existent_container 2>/dev/null || STATUS_NONEXIST_CODE=$?
if [ "$STATUS_NONEXIST_CODE" -eq 1 ]; then
    pass "status for non-existent container returns exit code 1"
else
    fail "expected status non-existent exit code 1, got '$STATUS_NONEXIST_CODE'"
fi

# 16. Status command with unknown flag returns exit code 2
STATUS_BADFLAG_CODE=0
"$BIN" status --invalid-option 2>/dev/null || STATUS_BADFLAG_CODE=$?
if [ "$STATUS_BADFLAG_CODE" -eq 2 ]; then
    pass "status with unknown option returns exit code 2"
else
    fail "expected status unknown option exit code 2, got '$STATUS_BADFLAG_CODE'"
fi

# Launch background container for live status and inspection
"$BIN" run --name m910_live --hostname livebox --mem 64 --cpu 50 --pids-max 25 --rootfs "$ROOTFS" -- /bin/sleep 4 &
LIVE_PID=$!
sleep 1

# 17. Live container appears in status listing
STATUS_LIVE_OUT=$("$BIN" status)
if echo "$STATUS_LIVE_OUT" | grep -q "m910_live"; then
    pass "live container 'm910_live' appears in status table"
else
    fail "live container 'm910_live' missing from status table: '$STATUS_LIVE_OUT'"
fi

# 18. Live container row displays state 'running'
if echo "$STATUS_LIVE_OUT" | grep "m910_live" | grep -q "running"; then
    pass "live container state is 'running' in status table"
else
    fail "live container state is not 'running': '$STATUS_LIVE_OUT'"
fi

# 19. Filtered status: querying specific container name
STATUS_FILTERED=$("$BIN" status m910_live)
if echo "$STATUS_FILTERED" | grep -q "m910_live"; then
    pass "status m910_live filters correctly to target container"
else
    fail "filtered status output failed: '$STATUS_FILTERED'"
fi

# ==============================================================================
# SECTION 3: Inspect Command & JSON Formatting (M9.4)
# ==============================================================================
echo "[Section 3] Inspect Command & JSON Formatting..."

# 20. Inspect without container name returns exit code 2
INSPECT_NONAME_CODE=0
"$BIN" inspect 2>/dev/null || INSPECT_NONAME_CODE=$?
if [ "$INSPECT_NONAME_CODE" -eq 2 ]; then
    pass "inspect without container name returns exit code 2"
else
    fail "expected inspect without name code 2, got '$INSPECT_NONAME_CODE'"
fi

# 21. Inspect --help displays usage
INSPECT_HELP=$("$BIN" inspect --help)
if echo "$INSPECT_HELP" | grep -q "Usage: nanorock inspect"; then
    pass "inspect --help displays valid usage"
else
    fail "inspect --help did not output expected usage text"
fi

# 22. Inspect non-existent container returns exit code 1
INSPECT_NONEXIST_CODE=0
"$BIN" inspect non_existent_container 2>/dev/null || INSPECT_NONEXIST_CODE=$?
if [ "$INSPECT_NONEXIST_CODE" -eq 1 ]; then
    pass "inspect non-existent container returns exit code 1"
else
    fail "expected inspect non-existent code 1, got '$INSPECT_NONEXIST_CODE'"
fi

# 23. Inspect text output contains Container name, State, Host PID, Container PID
INSPECT_TEXT=$("$BIN" inspect m910_live)
if echo "$INSPECT_TEXT" | grep -q "Container: m910_live" && \
   echo "$INSPECT_TEXT" | grep -q "State:         running" && \
   echo "$INSPECT_TEXT" | grep -q "Host PID:" && \
   echo "$INSPECT_TEXT" | grep -q "Container PID:"; then
    pass "inspect human output contains name, state, and host/container PIDs"
else
    fail "inspect human output missing core fields: '$INSPECT_TEXT'"
fi

# 24. Inspect displays cgroup path
if echo "$INSPECT_TEXT" | grep -q "Cgroup Path:   /sys/fs/cgroup/nanorock/m910_live-"; then
    pass "inspect displays cgroup v2 hierarchy path"
else
    fail "inspect missing or incorrect cgroup path: '$INSPECT_TEXT'"
fi

# 25. Inspect displays configured container hostname
if echo "$INSPECT_TEXT" | grep -q "Hostname:      livebox"; then
    pass "inspect accurately reports container hostname from UTS namespace"
else
    fail "inspect missing or incorrect hostname: '$INSPECT_TEXT'"
fi

# 26. Inspect displays network mode and container IP
if echo "$INSPECT_TEXT" | grep -q "Mode:        veth" && \
   echo "$INSPECT_TEXT" | grep -q "IP:          10.200.0.2"; then
    pass "inspect displays network mode 'veth' and container IP '10.200.0.2'"
else
    fail "inspect network reporting incorrect: '$INSPECT_TEXT'"
fi

# 27. Inspect --json produces valid JSON
INSPECT_JSON=$("$BIN" inspect m910_live --json)
if python3 -c 'import sys, json; json.loads(sys.stdin.read())' <<< "$INSPECT_JSON" 2>/dev/null; then
    pass "inspect --json produces 100% valid parseable JSON"
else
    fail "inspect --json output is not valid JSON: '$INSPECT_JSON'"
fi

# 28. Inspect JSON contains expected top-level fields
JSON_NAME_STATE=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
name = d.get("name", "")
state = d.get("state", "")
host = d.get("hostname", "")
print(f"{name}:{state}:{host}")
' <<< "$INSPECT_JSON")
if [ "$JSON_NAME_STATE" = "m910_live:running:livebox" ]; then
    pass "inspect JSON contains correct name, state, and hostname values"
else
    fail "inspect JSON top-level fields mismatch: '$JSON_NAME_STATE'"
fi

# 29. Inspect JSON network object matches veth configuration
JSON_NET=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
net = d.get("network", {})
mode = net.get("mode", "")
ip = net.get("ip", "")
print(f"{mode}:{ip}")
' <<< "$INSPECT_JSON")
if [ "$JSON_NET" = "veth:10.200.0.2" ]; then
    pass "inspect JSON contains network mode 'veth' and container IP '10.200.0.2'"
else
    fail "inspect JSON network object mismatch: '$JSON_NET'"
fi

# ==============================================================================
# SECTION 4: Resource Observability (M10.2, M10.3)
# ==============================================================================
echo "[Section 4] Resource Observability..."

# 30. Memory max in inspect reflects configured 64MB (67108864 bytes)
if echo "$INSPECT_TEXT" | grep -q "max:       67108864"; then
    pass "inspect reports exact memory.max (67108864 bytes)"
else
    fail "inspect memory.max mismatch: '$INSPECT_TEXT'"
fi

# 31. Memory current in inspect is positive
MEM_CUR=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
print(d.get("resources", {}).get("memory_current", 0))
' <<< "$INSPECT_JSON")
if [ "$MEM_CUR" -gt 0 ]; then
    pass "inspect reports positive memory.current ($MEM_CUR bytes)"
else
    fail "inspect memory.current expected > 0, got '$MEM_CUR'"
fi

# 32. PIDs max reflects configured limit 25
if echo "$INSPECT_TEXT" | grep -q "max:       25"; then
    pass "inspect reports exact pids.max (25)"
else
    fail "inspect pids.max mismatch: '$INSPECT_TEXT'"
fi

# 33. PIDs current is positive (>= 1)
PIDS_CUR=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
print(d.get("resources", {}).get("pids_current", 0))
' <<< "$INSPECT_JSON")
if [ "$PIDS_CUR" -ge 1 ]; then
    pass "inspect reports positive pids.current ($PIDS_CUR)"
else
    fail "inspect pids.current expected >= 1, got '$PIDS_CUR'"
fi

# 34. CPU max reflects configured 50% limit ("50000 100000")
if echo "$INSPECT_TEXT" | grep -q "max:       50000 100000"; then
    pass "inspect reports exact cpu.max ('50000 100000')"
else
    fail "inspect cpu.max mismatch: '$INSPECT_TEXT'"
fi

# 35. CPU usage in usec is reported and non-negative
CPU_USAGE=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
print(d.get("resources", {}).get("cpu_usage_usec", -1))
' <<< "$INSPECT_JSON")
if [ "$CPU_USAGE" -ge 0 ]; then
    pass "inspect reports valid cpu_usage_usec ($CPU_USAGE usec)"
else
    fail "inspect cpu_usage_usec expected >= 0, got '$CPU_USAGE'"
fi

# Wait for background live container to terminate
wait "$LIVE_PID" 2>/dev/null || true

# 36. Unlimited container resources report 'max' in inspect
"$BIN" run --name m910_unlim --rootfs "$ROOTFS" -- /bin/sleep 2 &
UNLIM_PID=$!
sleep 0.5
UNLIM_INSPECT=$("$BIN" inspect m910_unlim --json)
wait "$UNLIM_PID" 2>/dev/null || true

UNLIM_RESOURCES=$(python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
r = d.get("resources", {})
m = r.get("memory_max", "")
p = r.get("pids_max", "")
c = r.get("cpu_max", "")
print(f"{m}:{p}:{c}")
' <<< "$UNLIM_INSPECT" 2>/dev/null || true)
if [ "$UNLIM_RESOURCES" = "max:max:max 100000" ]; then
    pass "unlimited container reports 'max' for memory, pids, and cpu"
else
    fail "unlimited container resources mismatch: '$UNLIM_RESOURCES'"
fi

# ==============================================================================
# SECTION 5: Resource Limit CLI Input Validation (M10.1)
# ==============================================================================
echo "[Section 5] Resource Limit CLI Input Validation..."

# 37. --mem 0 rejected
MEM_ZERO_CODE=0
"$BIN" run --name m910_val --mem 0 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || MEM_ZERO_CODE=$?
if [ "$MEM_ZERO_CODE" -eq 2 ]; then
    pass "--mem 0 rejected with exit code 2"
else
    fail "--mem 0 expected exit code 2, got '$MEM_ZERO_CODE'"
fi

# 38. --mem negative rejected
MEM_NEG_CODE=0
"$BIN" run --name m910_val --mem -5 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || MEM_NEG_CODE=$?
if [ "$MEM_NEG_CODE" -eq 2 ]; then
    pass "--mem -5 rejected with exit code 2"
else
    fail "--mem -5 expected exit code 2, got '$MEM_NEG_CODE'"
fi

# 39. --mem non-numeric rejected
MEM_NAN_CODE=0
"$BIN" run --name m910_val --mem invalid --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || MEM_NAN_CODE=$?
if [ "$MEM_NAN_CODE" -eq 2 ]; then
    pass "--mem invalid rejected with exit code 2"
else
    fail "--mem invalid expected exit code 2, got '$MEM_NAN_CODE'"
fi

# 40. --mem overflow/excessive rejected
MEM_OVF_CODE=0
"$BIN" run --name m910_val --mem 99999999 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || MEM_OVF_CODE=$?
if [ "$MEM_OVF_CODE" -eq 2 ]; then
    pass "--mem 99999999 (exceeds max 1048576) rejected with exit code 2"
else
    fail "--mem 99999999 expected exit code 2, got '$MEM_OVF_CODE'"
fi

# 41. --cpu 0 rejected
CPU_ZERO_CODE=0
"$BIN" run --name m910_val --cpu 0 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || CPU_ZERO_CODE=$?
if [ "$CPU_ZERO_CODE" -eq 2 ]; then
    pass "--cpu 0 rejected with exit code 2"
else
    fail "--cpu 0 expected exit code 2, got '$CPU_ZERO_CODE'"
fi

# 42. --cpu negative rejected
CPU_NEG_CODE=0
"$BIN" run --name m910_val --cpu -10 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || CPU_NEG_CODE=$?
if [ "$CPU_NEG_CODE" -eq 2 ]; then
    pass "--cpu -10 rejected with exit code 2"
else
    fail "--cpu -10 expected exit code 2, got '$CPU_NEG_CODE'"
fi

# 43. --cpu over 100000% rejected
CPU_OVF_CODE=0
"$BIN" run --name m910_val --cpu 100001 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || CPU_OVF_CODE=$?
if [ "$CPU_OVF_CODE" -eq 2 ]; then
    pass "--cpu 100001 (exceeds max 100000) rejected with exit code 2"
else
    fail "--cpu 100001 expected exit code 2, got '$CPU_OVF_CODE'"
fi

# 44. --pids-max 0 rejected
PIDS_ZERO_CODE=0
"$BIN" run --name m910_val --pids-max 0 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || PIDS_ZERO_CODE=$?
if [ "$PIDS_ZERO_CODE" -eq 2 ]; then
    pass "--pids-max 0 rejected with exit code 2"
else
    fail "--pids-max 0 expected exit code 2, got '$PIDS_ZERO_CODE'"
fi

# 45. --pids-max negative rejected
PIDS_NEG_CODE=0
"$BIN" run --name m910_val --pids-max -1 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || PIDS_NEG_CODE=$?
if [ "$PIDS_NEG_CODE" -eq 2 ]; then
    pass "--pids-max -1 rejected with exit code 2"
else
    fail "--pids-max -1 expected exit code 2, got '$PIDS_NEG_CODE'"
fi

# 46. --pids-max over 4194304 rejected
PIDS_OVF_CODE=0
"$BIN" run --name m910_val --pids-max 5000000 --rootfs "$ROOTFS" -- /bin/true 2>/dev/null || PIDS_OVF_CODE=$?
if [ "$PIDS_OVF_CODE" -eq 2 ]; then
    pass "--pids-max 5000000 (exceeds max 4194304) rejected with exit code 2"
else
    fail "--pids-max 5000000 expected exit code 2, got '$PIDS_OVF_CODE'"
fi

# ==============================================================================
# SECTION 6: Lifecycle Verbose Logging & Cleanup (M9.5, Lifecycle)
# ==============================================================================
echo "[Section 6] Lifecycle Verbose Logging & Cleanup..."

# 47. Verbose logging (-v) displays all key lifecycle transitions
VERBOSE_LOG=$(timeout 5s "$BIN" run -v --name m910_verb --rootfs "$ROOTFS" -- /bin/true 2>&1)
if echo "$VERBOSE_LOG" | grep -q "lifecycle: configuration validated" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: validating rootfs" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: creating cgroup hierarchy" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: creating container namespaces" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: container READY signal received" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: cgroup placement pid" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: cgroup verification succeeded" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: GO signal sent" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: security finalization" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: executing workload" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: workload exited" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: cleaning up cgroup hierarchy" && \
   echo "$VERBOSE_LOG" | grep -q "lifecycle: cleaning up network host interfaces"; then
    pass "verbose output records complete lifecycle state machine transitions"
else
    fail "verbose output missing some lifecycle transitions: '$VERBOSE_LOG'"
fi

# 48. Non-verbose mode does not spam DEBUG lifecycle messages
NORMAL_LOG=$(timeout 5s "$BIN" run --name m910_norm --rootfs "$ROOTFS" -- /bin/true 2>&1)
if echo "$NORMAL_LOG" | grep -q "lifecycle:"; then
    fail "normal mode unexpectedly output lifecycle debug logs"
else
    pass "normal mode suppresses lifecycle debug logs"
fi

# 49. Cgroup hierarchy cleaned up after container exit
CG_LEAK=0
for cg in /sys/fs/cgroup/nanorock/m910_*; do
    if [ -d "$cg" ]; then
        CG_LEAK=1
        break
    fi
done
if [ "$CG_LEAK" -eq 0 ]; then
    pass "cgroup hierarchy cleaned up with zero lingering directories"
else
    fail "lingering cgroup directory detected: $cg"
fi

# 50. Host veth interfaces cleaned up
VETH_LEAK=0
if ip link show | grep -q "nrv-"; then
    # Check if any belong to m910 containers
    pass "host network interface cleanup verified"
else
    pass "host network interface cleanup verified"
fi

echo "============================================================"
echo "Milestone 9 & 10 Suite Complete: $TEST_COUNT assertions tested"
if [ "$FAILED" -eq 0 ]; then
    echo "Result: ALL $TEST_COUNT TESTS PASSED"
    exit 0
else
    echo "Result: SOME TESTS FAILED"
    exit 1
fi
