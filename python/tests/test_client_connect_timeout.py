"""Bug #6 regression test — mssh must time out on unreachable IPs.

Today: ``mssh user@192.0.2.1:2200 -- whoami`` blocks until the kernel
TCP timeout (~2 min). Users assume the system is hung and ctrl-C.
The mssh client needs a client-side connect timeout that bounds this
to a few seconds with a clear error.

192.0.2.1/24 is the RFC 5737 "documentation prefix" — guaranteed not
to route. No real machine sits there, so connect blocks.

Bug #6 was closed in v0.1.0; mssh now bounds connect to 5s. This
test verifies the fix.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


# RFC 5737 documentation prefix — guaranteed unroutable.
UNROUTABLE_IP = '192.0.2.1'
MSSHD_PORT = 2200
TIMEOUT_BUDGET = 10.0     # seconds — what we want mssh to honor
TEST_HARNESS_KILL = 25.0  # seconds — when WE give up on mssh (sanity bound)


def _mssh_bin() -> Path:
    """Return the mssh binary path. Uses the venv's mssh, which the
    tests' Python should be running in."""
    # sys.executable: e.g. /home/kgodwin/mssh/.venv/bin/python3.12
    bindir = Path(sys.executable).parent
    cand = bindir / 'mssh'
    if not cand.exists():
        pytest.skip(f'mssh binary not found at {cand} — run `make dev-install`')
    return cand


def _stub_creds_dir() -> Path:
    """Generate a throwaway cert/key/CA in a temp dir. mssh refuses to
    run without these files, so we have to materialize them — but we
    never use the cert for anything (connect fails before the
    handshake)."""
    d = Path(tempfile.mkdtemp(prefix='mssh-timeout-test-'))
    # Generate a self-signed cert pair via openssl. Cheaper than
    # importing cryptography here.
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', str(d / 'key.pem'),
        '-out', str(d / 'cert.pem'),
        '-days', '1', '-nodes',
        '-subj', '/CN=mssh-timeout-test',
    ], check=True, capture_output=True)
    # CA = self-signed (we don't care, we never get to mTLS verify).
    (d / 'ca.pem').write_bytes((d / 'cert.pem').read_bytes())
    os.chmod(d / 'key.pem', 0o600)
    return d


def test_connect_timeout_bounded():
    """mssh against an unrouted IP must give up within TIMEOUT_BUDGET
    seconds. Currently hangs ~2 minutes for kernel TCP timeout."""
    mssh = _mssh_bin()
    creds = _stub_creds_dir()
    env = {
        **os.environ,
        'MSSH_CERT': str(creds / 'cert.pem'),
        'MSSH_KEY':  str(creds / 'key.pem'),
        'MSSH_CA':   str(creds / 'ca.pem'),
    }

    start = time.monotonic()
    try:
        proc = subprocess.run(
            [str(mssh), f'alice@{UNROUTABLE_IP}:{MSSHD_PORT}', '--', 'whoami'],
            env=env, capture_output=True, text=True,
            timeout=TEST_HARNESS_KILL,
        )
        elapsed = time.monotonic() - start
        # Must exit (not hang) AND with non-zero AND within the budget.
        assert proc.returncode != 0, (
            f'mssh returned 0 (unexpected) — stdout={proc.stdout!r}')
        assert elapsed < TIMEOUT_BUDGET, (
            f'mssh took {elapsed:.1f}s to give up on unroutable IP; '
            f'should have timed out within {TIMEOUT_BUDGET}s')
        assert ('timeout' in proc.stderr.lower()
                or 'unreachable' in proc.stderr.lower()
                or 'no route' in proc.stderr.lower()), (
            f'mssh error message lacks "timeout"/"unreachable"/"no route" '
            f'hint; got: {proc.stderr!r}')
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        pytest.fail(
            f'mssh hung for {elapsed:.1f}s on unroutable IP '
            f'(test-harness killed it at {TEST_HARNESS_KILL}s). '
            f'Bug #6 reproduction: client needs a connect timeout.')
