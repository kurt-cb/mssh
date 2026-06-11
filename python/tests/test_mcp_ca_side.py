"""Tests for §12.4.3 — CA-side capability enforcement when Origin: mcp.

Defense in depth: even if the MCP-side TOOL_REGISTRY is tampered with,
the CA refuses non-allow-listed admin actions when the request
carries X-MSSH-Origin: mcp.

Tests: §12.4.2, §12.4.3, §13.9.2
"""
from __future__ import annotations

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca.admin import MCP_ALLOWED_ACTIONS, _check
from mssh.ca.enrollment import Admin


def _superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


def test_mcp_allow_list_includes_read_only_actions():
    """Verifies §12.4.3 — MCP allow-list covers the read-only diagnostic surface."""
    expected = {
        'server.list', 'user.list', 'admin.list', 'audit.read',
        'intermediate.list',
    }
    assert expected.issubset(MCP_ALLOWED_ACTIONS)


def test_mcp_allow_list_excludes_mutating_actions():
    """Verifies §12.2 + §12.4.3 — bypass-cert mint, admin.add, cert.revoke,
    user.remove, intermediate.rotate, intermediate.external.mint, and
    other mutating/destructive actions MUST NOT appear in the allow-list.
    """
    forbidden = {
        'bypass_cert.mint',         # §12.2 (5)
        'admin.add', 'admin.remove',
        'cert.revoke',
        'user.add', 'user.remove',
        'user.key.add', 'user.key.remove',
        'server.add', 'server.remove',
        'policy.add', 'policy.remove',
        'intermediate.rotate', 'intermediate.external.mint',
        'external_tool.add', 'external_tool.remove',
        'template.set', 'template.unset',
        'cert.mint',
    }
    overlap = forbidden & MCP_ALLOWED_ACTIONS
    assert not overlap, f'mutating actions in MCP allow-list: {overlap}'


def test_mcp_origin_blocks_non_allowed_action():
    """Verifies §12.4.3 — CA refuses MCP-origin calls for actions
    that aren't in MCP_ALLOWED_ACTIONS, even when the admin's role
    would otherwise permit the action.
    """
    err = _check('admin.add', _superuser(), origin='mcp')
    assert err is not None
    status, body = err
    assert status == 403
    assert body['reason'] == 'mcp_capability_denied'
    assert body['denied_reason'] == 'mcp_capability_denied'
    assert '§12.4.3' in body['detail']


def test_mcp_origin_allows_listed_action():
    """Verifies §12.4.3 — read-only action with MCP origin proceeds
    to the usual role check (which a superuser passes).
    """
    err = _check('server.list', _superuser(), origin='mcp')
    assert err is None


def test_no_origin_falls_back_to_role_check():
    """Verifies §12.4.3 — empty / no origin → only the role check
    applies. MCP allow-list is not consulted.
    """
    # admin.add is NOT in MCP allow-list, but with origin='' it should
    # only fail the role check, not the MCP check.
    err = _check('admin.add', _superuser(), origin='')
    assert err is None              # superuser can admin.add


def test_bypass_cert_mint_refused_to_mcp_even_for_superuser():
    """Verifies §12.2 (5) — bypass-cert mint is NEVER reachable
    from MCP, regardless of caller's mTLS role.
    """
    err = _check('bypass_cert.mint', _superuser(), origin='mcp')
    assert err is not None
    status, body = err
    assert status == 403
    assert body['reason'] == 'mcp_capability_denied'


def test_origin_only_recognises_lowercase_mcp():
    """Verifies §12.4.2 — the origin header value 'mcp' is the only
    recognised tag in v1. Empty / other values bypass MCP enforcement.
    """
    # 'MCP' uppercase, 'other', and '' should not trigger the MCP gate.
    for origin in ('', 'MCP', 'other', 'admin', 'user'):
        err = _check('admin.add', _superuser(), origin=origin)
        # All of these pass the MCP gate (origin != 'mcp') and reach
        # the role check, which a superuser passes for admin.add.
        assert err is None, \
            f'origin={origin!r} unexpectedly triggered the MCP gate'
