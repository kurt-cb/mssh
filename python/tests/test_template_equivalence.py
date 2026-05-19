"""Cross-template equivalence — catches Bug #8.

The lab has two inner-sshd_config templates that have to agree on
auth-critical directives:

  - ``config/sshd_config.template`` — used by the long-lived inner
    sshd, rendered once at msshd boot.
  - ``mssh.ca.templates.BUILTIN_OPENSSH_TEMPLATE`` — used by the
    per-connection inner sshd, rendered by the CA on every authorize
    call.

When they diverge on something like ``PubkeyAcceptedAlgorithms``,
the per-connection mode silently fails — long-lived still works, so
nobody notices until a flip test. That happened in round 2 (Bug #8).

This test asserts that the auth-critical directives are identical
between the two templates. ``Port``, ``HostKey``, and similar local
substitution markers differ legitimately (one uses ``{LOCAL_PORT}``,
the other ``{{INNER_PORT}}``) — those aren't checked.

To regenerate the auth-critical directive list after a real
template change: review the diff between the two files for any
directive that touches authentication, crypto, or trust.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from mssh.ca.templates import BUILTIN_OPENSSH_TEMPLATE


# Directives whose value MUST match exactly between the two templates.
# These all affect what credentials the inner sshd will accept.
AUTH_CRITICAL_DIRECTIVES = frozenset({
    'AuthenticationMethods',
    'PubkeyAuthentication',
    'PasswordAuthentication',
    'KbdInteractiveAuthentication',
    'ChallengeResponseAuthentication',
    'GSSAPIAuthentication',
    'HostbasedAuthentication',
    'PermitEmptyPasswords',
    'PermitRootLogin',
    'UsePAM',
    'AuthorizedKeysFile',
    'AuthorizedKeysCommand',
    'AuthorizedPrincipalsFile',
    'PubkeyAcceptedAlgorithms',
    'HostKeyAlgorithms',
    'KexAlgorithms',
    'Ciphers',
    'MACs',
})


def _config_template_path() -> Path:
    """Path to the long-lived inner sshd template at the repo root."""
    return Path(__file__).resolve().parents[2] / 'config' / 'sshd_config.template'


def _parse_directives(text: str) -> dict[str, str]:
    """Map directive name → its value (with surrounding whitespace
    collapsed). Skips comments, blank lines, and lines that look like
    section markers."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        # Split into name + value on whitespace. Skip lines without a value.
        m = re.match(r'^([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$', line)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        out[name] = _normalize_value(value)
    return out


def _normalize_value(value: str) -> str:
    """Collapse whitespace and strip surrounding quotes. Lets us compare
    ``ssh-ed25519,ssh-ed25519-cert-v01@openssh.com`` against the same
    list with different spacing."""
    # Comma-separated lists: sort to ignore ordering, normalize spaces
    # around commas.
    value = re.sub(r'\s+', ' ', value)
    if ',' in value:
        parts = [p.strip() for p in value.split(',')]
        return ','.join(sorted(parts))
    return value


def test_auth_critical_directives_agree():
    """The two templates must agree on every auth-critical directive."""
    long_lived = _parse_directives(_config_template_path().read_text())
    per_connection = _parse_directives(BUILTIN_OPENSSH_TEMPLATE)

    mismatches: list[str] = []
    for name in AUTH_CRITICAL_DIRECTIVES:
        in_long = long_lived.get(name)
        in_perconn = per_connection.get(name)
        if in_long == in_perconn:
            continue
        mismatches.append(
            f'  {name}:\n'
            f'    long-lived          = {in_long!r}\n'
            f'    per-connection      = {in_perconn!r}')

    if mismatches:
        pytest.fail(
            'Auth-critical directives diverged between the two inner-sshd\n'
            'templates. This is exactly Bug #8: per-connection mode will\n'
            'silently fail at auth (the flip script reverts, hiding the\n'
            'failure). Update both templates together:\n\n'
            + '\n\n'.join(mismatches)
            + '\n\n'
            'Long-lived template:   config/sshd_config.template\n'
            'Per-connection (CA):   python/packages/mssh-ca/src/mssh/ca/'
            'templates.py::BUILTIN_OPENSSH_TEMPLATE\n')


def test_both_templates_disable_password_auth():
    """Defensive: regardless of the equivalence above, both templates
    must explicitly disable password auth. (Belt + suspenders against
    a future refactor that drops the directive entirely.)"""
    long_lived = _parse_directives(_config_template_path().read_text())
    per_connection = _parse_directives(BUILTIN_OPENSSH_TEMPLATE)
    for name, template in (('long-lived', long_lived),
                            ('per-connection', per_connection)):
        assert template.get('PasswordAuthentication') == 'no', (
            f'{name} template must explicitly set '
            f'`PasswordAuthentication no`; got '
            f'{template.get("PasswordAuthentication")!r}')
        assert template.get('PermitRootLogin') == 'no', (
            f'{name} template must explicitly set `PermitRootLogin no`; '
            f'got {template.get("PermitRootLogin")!r}')


def test_per_connection_template_accepts_ssh_certs():
    """The specific assertion that would have caught Bug #8 directly:
    per-connection's PubkeyAcceptedAlgorithms must include
    ssh-ed25519-cert-v01@openssh.com (the algorithm name asyncssh
    negotiates for the ephemeral OpenSSH user cert msshd mints)."""
    per_connection = _parse_directives(BUILTIN_OPENSSH_TEMPLATE)
    algos = per_connection.get('PubkeyAcceptedAlgorithms', '')
    assert 'ssh-ed25519-cert-v01@openssh.com' in algos, (
        'PubkeyAcceptedAlgorithms in the per-connection template must '
        'include ssh-ed25519-cert-v01@openssh.com or per-connection '
        'mode will reject msshd-minted certs (Bug #8). Got: '
        f'{algos!r}')
