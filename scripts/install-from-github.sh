#!/bin/sh
# install-from-github.sh — pip-install mssh wheels from a GitHub Release.
#
# Fetches the requested wheels for the given tag and pip-installs them
# in dependency order. No PyPI dependency for mssh's own packages;
# third-party deps (cryptography, flask, pyyaml, requests, click,
# webauthn, mcp) still come from PyPI.
#
# Usage:
#   install-from-github.sh <version> [package ...]
#
#   version    Release tag (e.g. v0.5.1)
#   package    Optional list of packages to install; default = ca
#              Known aliases:
#                ca         → mssh-common + mssh-ca
#                admin      → mssh-common + mssh-admin  (pulls ca via dep)
#                msshd      → mssh-common + msshd       (server-side gateway)
#                client     → mssh-common + <client wheel>  (see note)
#                all        → all six wheels
#              Or a bare wheel-stem (e.g. mssh-ca, mssh-admin, msshd).
#
# Notes:
#   - The client wheel is currently unpublished (the `mssh` PyPI name
#     is taken by an unrelated package). The `client` alias assumes a
#     future rename lands; today it errors out.
#   - Run in an activated virtualenv or pass --user; do NOT install
#     into a distro-managed Python without knowing what you're doing.
#
# Repo:
#   https://github.com/kurt-cb/mssh

set -eu

REPO="${MSSH_REPO:-kurt-cb/mssh}"
BASE_URL="https://github.com/${REPO}/releases/download"

usage() {
    sed -n '2,/^$/p' "$0" | sed 's|^# \?||'
    exit "${1:-0}"
}

[ $# -lt 1 ] && usage 2
case "$1" in -h|--help) usage 0 ;; esac

VERSION="$1"; shift
V="${VERSION#v}"        # 'v0.5.1' → '0.5.1'
[ -z "$V" ] && { echo "empty version" >&2; usage 2; }

# Default to installing the CA if nothing else asked.
[ $# -eq 0 ] && set -- ca

# Expand aliases + collect wheel stems in dependency-safe order.
# mssh-common comes first in every set that needs it.
wheels=""
add() {
    # De-dup: don't add the same wheel twice.
    case " $wheels " in *" $1 "*) return ;; esac
    wheels="$wheels $1"
}

for pkg in "$@"; do
    case "$pkg" in
        ca)         add mssh_common; add mssh_ca ;;
        admin)      add mssh_common; add mssh_ca; add mssh_admin ;;
        msshd)      add mssh_common; add msshd ;;
        passkey)    add mssh_common; add mssh_passkey ;;
        client)
            echo "error: the client wheel is currently unpublished" >&2
            echo "       (PyPI slot 'mssh' is taken; rename pending)" >&2
            exit 3
            ;;
        all)
            add mssh_common; add mssh_ca; add mssh_admin
            add msshd; add mssh_passkey
            echo "note: skipping client wheel (unpublished)" >&2
            ;;
        mssh-ca|mssh_ca)               add mssh_common; add mssh_ca ;;
        mssh-admin|mssh_admin)         add mssh_common; add mssh_ca; add mssh_admin ;;
        mssh-common|mssh_common)       add mssh_common ;;
        mssh-passkey|mssh_passkey)     add mssh_common; add mssh_passkey ;;
        msshd|msshd_)                  add mssh_common; add msshd ;;
        *)  echo "unknown package: $pkg" >&2; exit 2 ;;
    esac
done

# Build the URL list.
urls=""
for stem in $wheels; do
    urls="$urls $BASE_URL/$VERSION/${stem}-${V}-py3-none-any.whl"
done

echo "==> installing from $REPO release $VERSION:"
for u in $urls; do echo "    $u"; done
echo

# shellcheck disable=SC2086  # word-splitting on $urls is intentional.
exec pip install $urls
