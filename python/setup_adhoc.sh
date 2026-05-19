#!/bin/bash
# Provision an adhoc ssh-rt-auth lab and drop into a shell with it.
#
# Usage:
#   ./setup_adhoc.sh              # default: msshd (Tier-1 wrap-and-proxy)
#   ./setup_adhoc.sh msshd {phase}       # explicit
#   ./setup_adhoc.sh debug {phase}       # debug_sshd (the old AsyncSSH PoC lab)
#
# phase is 0, 1 or 2 and indicates stopping point in setup of the environment.

set -u

# Activate the local venv. Must exist already and have the mssh* wheels
# installed (run `make dev-install` from the repo root first).
. ../.venv/bin/activate

# Sanity: the mssh CLI should be on PATH. If not, the venv hasn't been
# set up with the new package layout.
if ! command -v mssh >/dev/null 2>&1; then
    echo "error: 'mssh' not on PATH after venv activation." >&2
    echo "  Run: make dev-install (from repo root) to install the 5 wheels editable." >&2
    exit 1
fi

# Ensure wheels are built and current before the lab provisions
# (the test framework's install_wheels() needs dist/*.whl on disk).
echo "Building wheels (make pkg) — ensures the lab installs the current source..."
(cd .. && make PYTHON="$(command -v python)" pkg) | tail -3

TIER="${1:-msshd}"
LEVEL=INFO
case "$TIER" in
    msshd)
        TEST_FILE=tests/lxc/test_setup_only_msshd.py
        MARKER=setup_only_msshd
        ;;
    debug|debug_sshd|asyncssh)
        TEST_FILE=tests/lxc/test_setup_only.py
        MARKER=setup_only
        LEVEL=DEBUG
        ;;
    *)
        echo "Unknown tier: $TIER (expected: msshd | debug)" >&2
        exit 2
        ;;
esac
PHASE="${2:-2}"
RND=$(openssl rand -base64 10)
PREFIX=$USER-${RND:0:4}

echo "Provisioning $TIER lab via $TEST_FILE (prefix=$PREFIX)"
pytest "$TEST_FILE" -s --log-file=pytest.log --log-cli-level=$LEVEL -v \
    -m "$MARKER" --phase $PHASE --lxc-prefix $PREFIX
RC=$?

if [ "$RC" != "0" ]; then
    echo "Environment failed to generate"
    exit 1
fi

# shell out
echo "Shell-ing out with adhoc-env setup; ADHOC_TEST_ENV.md has details."
cat > adhoc-rc.sh <<EOF
source ./adhoc-env.sh
export PS1="adhoc $PREFIX> "
unset PROMPT_COMMAND
export ANSIBLE_CONFIG=$(pwd)/ansible-project/ansible.cfg
EOF

bash --rcfile ./adhoc-rc.sh -i

./cleanup_containers.sh
rm -f ADHOC_TEST_ENV.md adhoc-env.sh adhoc-rc.sh
exit 0
