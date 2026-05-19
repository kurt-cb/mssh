#!/usr/bin/env bash
# redeploy.sh — push freshly-built wheels into a running adhoc lab.
#
# Usage:
#   scripts/redeploy.sh <lab-prefix> <dist-dir>
#
# Replaces the "lxc file push + restart" hot-patch workflow with the
# real upgrade path users will hit. For each container matching the
# lab-prefix:
#
#   1. lxc file push <dist>/*.whl into /tmp/mssh-wheels/
#   2. pip install --force-reinstall --no-deps the wheels (handles
#      PEP 668 marker conditionally — same logic as install_wheels()
#      in python/tests/lxc/lxc_helpers.py)
#   3. systemctl restart msshd (and mssh-ca on the CA host)
#
# Designed so that `make redeploy` after editing source = the user's
# upgrade path = the lab gets the fix the same way real ops would.

set -euo pipefail

PREFIX="${1:-}"
DIST_DIR="${2:-dist}"

if [ -z "$PREFIX" ]; then
    echo "usage: $0 <lab-prefix> [dist-dir]" >&2
    echo "  e.g.: $0 kurt-3xK4 dist" >&2
    exit 2
fi
if [ ! -d "$DIST_DIR" ] || [ -z "$(ls -1 "$DIST_DIR"/*.whl 2>/dev/null)" ]; then
    echo "error: no wheels in $DIST_DIR — run 'make pkg' first" >&2
    exit 3
fi

# Find containers matching the prefix.
mapfile -t CONTAINERS < <(lxc list --format=csv -c n | grep "^${PREFIX}-adhoc-" || true)
if [ "${#CONTAINERS[@]}" -eq 0 ]; then
    echo "error: no containers matching '${PREFIX}-adhoc-*' — is the lab running?" >&2
    lxc list --format=csv -c n | head -10
    exit 4
fi

WHEELS=("$DIST_DIR"/*.whl)
echo "Redeploying ${#WHEELS[@]} wheels to ${#CONTAINERS[@]} containers (prefix=$PREFIX)"
echo

start_ts=$(date +%s)
for c in "${CONTAINERS[@]}"; do
    printf '  %-40s ' "$c"
    lxc exec "$c" -- mkdir -p /tmp/mssh-wheels
    for w in "${WHEELS[@]}"; do
        lxc file push --quiet "$w" "$c/tmp/mssh-wheels/$(basename "$w")"
    done

    # PEP 668 detection — see lxc_helpers.py for the same logic.
    if lxc exec "$c" -- sh -c 'find /usr/lib -name EXTERNALLY-MANAGED 2>/dev/null | head -1' \
        | grep -q EXTERNALLY-MANAGED; then
        PIP_FLAGS='--quiet --force-reinstall --no-deps --break-system-packages'
    else
        PIP_FLAGS='--quiet --force-reinstall --no-deps'
    fi
    lxc exec "$c" -- sh -c "pip install $PIP_FLAGS /tmp/mssh-wheels/*.whl"

    # Restart services that exist (msshd on servers; mssh-ca on the CA host).
    for svc in msshd mssh-ca; do
        if lxc exec "$c" -- systemctl is-enabled "$svc" >/dev/null 2>&1; then
            lxc exec "$c" -- systemctl restart "$svc"
        fi
    done
    echo "ok"
done

elapsed=$(($(date +%s) - start_ts))
echo
echo "✓ redeployed in ${elapsed}s — version $(grep '^__version__' "$DIST_DIR"/../python/packages/mssh-common/src/mssh/_version.py 2>/dev/null | head -1 || echo unknown)"
