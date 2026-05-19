#!/usr/bin/env bash
# validate-adhoc.sh — run the round-1+round-2 regression probes against
# a freshly-provisioned adhoc lab. Used after `make pkg` + setup_adhoc.sh
# to confirm v0.1.0 doesn't regress the bugs we fixed in those rounds.
#
# Probes:
#   A1   happy path: mssh user@authorized-server -- whoami
#   A7   Bug #5: binary stdout fidelity at 1MB
#   C6   Bug #8: flip_to_per_connection round-trip
#   A12  concurrency: 3 parallel mssh sessions
#
# Exits non-zero on any probe failure with a diagnostic.

set -u

cd "$(dirname "$0")/.." || exit 99

if [ ! -f python/adhoc-env.sh ]; then
    echo "error: python/adhoc-env.sh not found — provision a lab first" >&2
    exit 2
fi
# shellcheck disable=SC1091
source python/adhoc-env.sh > /dev/null 2>&1

FAIL=0
report() {
    local name="$1" status="$2"
    if [ "$status" = "ok" ]; then
        printf '  ✓ %-40s\n' "$name"
    else
        printf '  ✗ %-40s\n' "$name"
        FAIL=1
    fi
}

echo "=== Round-1/2 regression probes ==="

# A1 — happy path
out=$(mssh_as alice acct whoami 2>&1)
if [ "$out" = "alice" ]; then report "A1 happy path (alice → acct)" ok
else report "A1 happy path (alice → acct)" "fail: got $out"; fi

# A7 — binary stdout fidelity at 1MB (Bug #5 regression)
got=$(mssh_as alice acct 'head -c 1048576 /dev/urandom' 2>/dev/null | wc -c)
if [ "$got" = "1048576" ]; then report "A7 binary stdout 1MB (Bug #5)" ok
else report "A7 binary stdout 1MB (Bug #5)" "fail: got $got bytes"; fi

# A12 — concurrency
( mssh_as alice acct hostname > /tmp/v.1 2>&1 ) &
( mssh_as alice acct hostname > /tmp/v.2 2>&1 ) &
( mssh_as alice acct hostname > /tmp/v.3 2>&1 ) &
wait
n=$(cat /tmp/v.1 /tmp/v.2 /tmp/v.3 | wc -l)
if [ "$n" = "3" ]; then report "A12 concurrency (3 parallel)" ok
else report "A12 concurrency (3 parallel)" "fail: got $n outputs"; fi
rm -f /tmp/v.[123]

# C6 — flip_to_per_connection (Bug #8 regression)
CA_CONTAINER=$(lxc list --format=csv -c n 2>/dev/null | grep -E "^.*-adhoc-ca$" | head -1)
if [ -n "$CA_CONTAINER" ]; then
    flip_out=$(lxc exec "$CA_CONTAINER" -- su - root-admin -c \
        './flip-to-per-connection.sh' 2>&1 | grep -c "OK (per-connection)")
    if [ "$flip_out" = "4" ]; then
        report "C6 flip_to_per_connection (Bug #8)" ok
        # Flip back to long-lived for cleanliness.
        lxc exec "$CA_CONTAINER" -- su - root-admin -c \
            './flip-to-enforce.sh' > /dev/null 2>&1
    else
        report "C6 flip_to_per_connection (Bug #8)" "fail: $flip_out servers OK (want 4)"
    fi
else
    report "C6 flip_to_per_connection (Bug #8)" "fail: CA container not found"
fi

# Version check — proves we're running v0.1.0 wheels, not the old code.
ver=$(lxc exec "$CA_CONTAINER" -- pip show mssh-ca 2>/dev/null \
    | awk '/^Version:/ {print $2}')
echo
echo "=== Installed version on CA: ${ver:-unknown} ==="

echo
if [ $FAIL -eq 0 ]; then
    echo "✓ all probes passed"
    exit 0
else
    echo "✗ at least one probe failed"
    exit 1
fi
