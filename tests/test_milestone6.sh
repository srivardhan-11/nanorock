#!/usr/bin/env bash
# Tests for Milestone 6: CLI, Validation & Usability
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

echo "=== Milestone 6 CLI, Validation & Usability Verification Suite ==="

# Helper to run command and capture output + exit code without set -e aborting
run_cmd() {
    set +e
    CMD_OUT=$("$@" 2>&1)
    CMD_CODE=$?
    set -e
}

# 1. Help options: --help, -h, run --help, run -h
echo "[1] Testing help flags (--help, -h, run --help)..."
run_cmd "$BIN" --help
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "nanorock 0.1.0"; then
    pass "--help succeeds (code 0) and displays banner"
else
    fail "--help failed (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" -h
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "Usage:"; then
    pass "-h succeeds (code 0) and displays usage"
else
    fail "-h failed (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" run --help
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "Run Options:"; then
    pass "run --help succeeds (code 0) and displays run options"
else
    fail "run --help failed (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" run -h
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "Exit Status Policy:"; then
    pass "run -h succeeds (code 0) and displays exit status policy"
else
    fail "run -h failed (code $CMD_CODE, out: $CMD_OUT)"
fi

# 2. Version options: --version, -V
echo "[2] Testing version flags (--version, -V)..."
run_cmd "$BIN" --version
if [ "$CMD_CODE" -eq 0 ] && [ "$CMD_OUT" = "nanorock 0.1.0" ]; then
    pass "--version output matches 'nanorock 0.1.0' (code 0)"
else
    fail "--version failed (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" -V
if [ "$CMD_CODE" -eq 0 ] && [ "$CMD_OUT" = "nanorock 0.1.0" ]; then
    pass "-V output matches 'nanorock 0.1.0' (code 0)"
else
    fail "-V failed (code $CMD_CODE, out: $CMD_OUT)"
fi

# 3. Missing arguments: missing rootfs, missing command, missing option arguments
echo "[3] Testing missing argument handling and exit code 2 (EXIT_USAGE_ERROR)..."
run_cmd "$BIN" run -- /bin/sh
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q -- "--rootfs is required"; then
    pass "missing --rootfs rejected with code 2"
else
    fail "expected code 2 for missing --rootfs, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "no command given"; then
    pass "missing command after '--' rejected with code 2"
else
    fail "expected code 2 for missing command, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "option '--rootfs' requires an argument"; then
    pass "missing argument to --rootfs rejected with code 2"
else
    fail "expected code 2 for missing --rootfs arg, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --hostname
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "option '--hostname' requires an argument"; then
    pass "missing argument to --hostname rejected with code 2"
else
    fail "expected code 2 for missing --hostname arg, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --name
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "option '--name' requires an argument"; then
    pass "missing argument to --name rejected with code 2"
else
    fail "expected code 2 for missing --name arg, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --mem
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "option '--mem' requires an argument"; then
    pass "missing argument to --mem rejected with code 2"
else
    fail "expected code 2 for missing --mem arg, got $CMD_CODE (out: $CMD_OUT)"
fi

# 4. Unknown and invalid arguments
echo "[4] Testing invalid and unknown argument rejection..."
run_cmd "$BIN" run --banana
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "unrecognised option: --banana"; then
    pass "unknown option '--banana' rejected with code 2"
else
    fail "expected code 2 for unknown option, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" invalid_subcmd
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "unrecognised command: 'invalid_subcmd'"; then
    pass "unknown subcommand rejected with code 2"
else
    fail "expected code 2 for unknown subcommand, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --mem abc -- /bin/true
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "invalid value for --mem: 'abc'"; then
    pass "invalid non-numeric --mem rejected with code 2"
else
    fail "expected code 2 for non-numeric --mem, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --cpu -1 -- /bin/true
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "invalid value for --cpu: '-1'"; then
    pass "negative --cpu rejected with code 2"
else
    fail "expected code 2 for negative --cpu, got $CMD_CODE (out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" --pids-max 0 -- /bin/true
if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "invalid value for --pids-max: '0'"; then
    pass "zero --pids-max rejected with code 2"
else
    fail "expected code 2 for zero --pids-max, got $CMD_CODE (out: $CMD_OUT)"
fi

# 5. Hostname validation
echo "[5] Testing hostname validation..."
for BAD_HOST in "-badstart" ".badstart" "badend-" "badend." "has space" "has_underscore"; do
    run_cmd "$BIN" run --rootfs "$ROOTFS" --hostname "$BAD_HOST" -- /bin/true
    if [ "$CMD_CODE" -eq 2 ] && echo "$CMD_OUT" | grep -q "invalid hostname"; then
        pass "rejected invalid hostname: '$BAD_HOST'"
    else
        fail "failed to reject invalid hostname '$BAD_HOST' (code $CMD_CODE, out: $CMD_OUT)"
    fi
done

# 6. Separator '--' preserves workload arguments with dashes
echo "[6] Testing argument separator '--' preserves workload dashes..."
run_cmd "$BIN" run --rootfs "$ROOTFS" -- /bin/echo --hello
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q -- "--hello"; then
    pass "workload argument '--hello' passed intact to echo"
else
    fail "failed to pass '--hello' to workload (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'echo cli_ok'
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "cli_ok"; then
    pass "workload '/bin/sh -c' executes successfully"
else
    fail "failed to execute '/bin/sh -c' (code $CMD_CODE, out: $CMD_OUT)"
fi

# 7. Exit code policy distinction
echo "[7] Testing exit code policy distinction (workload vs CLI error vs runtime error)..."
# 7a. Workload exit 42
run_cmd "$BIN" run --rootfs "$ROOTFS" -- /bin/sh -c 'exit 42'
if [ "$CMD_CODE" -eq 42 ]; then
    pass "workload exit code 42 passed through accurately (exit 42)"
else
    fail "expected workload exit 42, got $CMD_CODE"
fi

# 7b. CLI usage error gives code 2
run_cmd "$BIN" run --invalid-option-xyz
if [ "$CMD_CODE" -eq 2 ]; then
    pass "CLI usage error returns code 2"
else
    fail "expected code 2 for CLI usage error, got $CMD_CODE"
fi

# 7c. Runtime error (e.g. non-existent rootfs) returns runtime error code (1)
run_cmd "$BIN" run --rootfs "./nonexistent_rootfs_98765" -- /bin/true
if [ "$CMD_CODE" -eq 1 ]; then
    pass "runtime rootfs failure returns code 1 (EXIT_RUNTIME_ERROR)"
else
    fail "expected code 1 for runtime failure, got $CMD_CODE"
fi

# 8. Verbose mode output
echo "[8] Testing verbose mode (-v, --verbose)..."
run_cmd "$BIN" run --rootfs "$ROOTFS" --verbose -- /bin/echo verbose_test
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "DEBUG" && echo "$CMD_OUT" | grep -q "configuration:"; then
    pass "--verbose produces DEBUG configuration diagnostic logs"
else
    fail "--verbose diagnostic logs missing (code $CMD_CODE, out: $CMD_OUT)"
fi

run_cmd "$BIN" run --rootfs "$ROOTFS" -v -- /bin/echo v_test
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "DEBUG" && echo "$CMD_OUT" | grep -q "resource limits:"; then
    pass "-v produces DEBUG resource limits diagnostic logs"
else
    fail "-v diagnostic logs missing (code $CMD_CODE, out: $CMD_OUT)"
fi

# 9. --no-seccomp security warning
echo "[9] Testing --no-seccomp warning banner..."
run_cmd "$BIN" run --rootfs "$ROOTFS" --no-seccomp -- /bin/echo noseccomp_test
if [ "$CMD_CODE" -eq 0 ] && echo "$CMD_OUT" | grep -q "running in insecure mode: seccomp-BPF filter is DISABLED"; then
    pass "--no-seccomp displays clear insecure mode warning"
else
    fail "--no-seccomp warning missing (code $CMD_CODE, out: $CMD_OUT)"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All Milestone 6 CLI and usability tests passed successfully."
    exit 0
else
    echo "Some Milestone 6 tests failed."
    exit 1
fi
