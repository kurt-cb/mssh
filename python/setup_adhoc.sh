#!/bin/bash
# Provision an adhoc ssh-rt-auth lab and drop into a shell with it.
#
# Usage:
#   ./setup_adhoc.sh              # default: msshd (Tier-1 wrap-and-proxy)
#   ./setup_adhoc.sh msshd        # explicit
#   ./setup_adhoc.sh debug        # debug_sshd (the old AsyncSSH PoC lab)

. ../.venv/bin/activate

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

echo "Provisioning $TIER lab via $TEST_FILE"
pytest "$TEST_FILE" -s --log-file=pytest.log --log-cli-level=$LEVEL -v -m "$MARKER"
RC=$?

if [ "$RC" != "0" ]; then
    echo "Environment failed to generate"
    exit 1
fi

# shell out
echo "Shell-ing out with adhoc-env setup; ADHOC_TEST_ENV.md has details."
cat > adhoc-rc.sh <<EOF
source ./adhoc-env.sh
export PS1="adhoc> "
unset PROMPT_COMMAND
EOF

bash --rcfile ./adhoc-rc.sh -i

./cleanup_containers.sh
rm -f ADHOC_TEST_ENV.md adhoc-env.sh adhoc-rc.sh
exit 0
