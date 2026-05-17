"""Unit tests for mssh.mcp.tools.

The MCP transport layer (server.py) is exercised by the protocol
itself; the tool functions are plain wrappers over CAClient + the
state detector, which is what we test here. Faster than full
end-to-end and covers the data-marshaling that the LLM client
ultimately consumes.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssh.admin.client import CAClientError
from mssh.mcp import tools


def _client(*, servers=None, users=None, admins=None,
            audit=None, raise_on=None) -> MagicMock:
    c = MagicMock()
    c.base_url = 'https://127.0.0.1:8443'
    c.server_list.return_value = servers or []
    c.user_list.return_value = users or []
    c.admin_list.return_value = admins or []
    c.audit.return_value = {'entries': audit or []}
    if raise_on:
        getattr(c, raise_on).side_effect = CAClientError(500, 'boom')
    return c


# ---------------------------------------------------------------------------
# server_list
# ---------------------------------------------------------------------------


def test_server_list_empty():
    out = tools.server_list(client=_client())
    assert 'No servers enrolled' in out


def test_server_list_formats_groups():
    out = tools.server_list(client=_client(servers=[
        {'name': 'srv-acct', 'groups': ['accounting', 'production']},
        {'name': 'srv-eng', 'groups': ['engineering']},
    ]))
    assert 'srv-acct' in out
    assert 'accounting, production' in out
    assert '2 server(s)' in out


def test_server_list_passes_filters_to_client():
    c = _client(servers=[])
    tools.server_list(client=c, group='accounting', name_prefix='srv-')
    c.server_list.assert_called_once_with(group='accounting',
                                          name_prefix='srv-')


def test_server_list_empty_filters_are_none_not_empty_string():
    """The client API expects None for "no filter", not ''."""
    c = _client(servers=[])
    tools.server_list(client=c)
    c.server_list.assert_called_once_with(group=None, name_prefix=None)


def test_server_list_surfaces_ca_error():
    out = tools.server_list(client=_client(raise_on='server_list'))
    assert 'CA error 500' in out


# ---------------------------------------------------------------------------
# user_list
# ---------------------------------------------------------------------------


def test_user_list_counts_keys_and_policies():
    users = [{
        'username': 'alice',
        'keys': [{'fingerprint': 'aa'}, {'fingerprint': 'bb'}],
        'policies': [{'id': 'p1'}],
    }]
    out = tools.user_list(client=_client(users=users))
    assert 'alice: 2 key(s), 1 policy(ies)' in out


def test_user_list_empty():
    out = tools.user_list(client=_client())
    assert 'No users enrolled' in out


# ---------------------------------------------------------------------------
# user_inspect
# ---------------------------------------------------------------------------


def test_user_inspect_requires_username():
    out = tools.user_inspect(client=_client(), username='')
    assert 'username is required' in out


def test_user_inspect_missing_user():
    out = tools.user_inspect(client=_client(users=[]), username='ghost')
    assert "No user named 'ghost'" in out


def test_user_inspect_full_record():
    user = {
        'username': 'alice',
        'keys': [{
            'type': 'ssh-pubkey', 'fingerprint': 'AB:CD',
            'key_type': 'ssh-ed25519', 'key_id': '', 'principals': [],
        }],
        'policies': [{
            'id': 'p1', 'servers': [], 'server_groups': ['accounting'],
            'channels': ['session'], 'source_cidrs': ['10.0.0.0/16'],
            'time_window': None, 'max_cert_validity_seconds': 600,
            'environment': {}, 'force_command': None,
        }],
    }
    out = tools.user_inspect(client=_client(users=[user]), username='alice')
    assert 'User: alice' in out
    assert 'AB:CD' in out
    assert 'accounting' in out
    assert 'session' in out
    assert '10.0.0.0/16' in out


def test_user_inspect_force_command_surfaced():
    user = {
        'username': 'opbot',
        'keys': [],
        'policies': [{
            'id': 'p1', 'servers': ['srv-db'], 'server_groups': [],
            'channels': ['session'], 'source_cidrs': [],
            'time_window': None, 'max_cert_validity_seconds': 60,
            'environment': {}, 'force_command': '/usr/local/bin/dbshell',
        }],
    }
    out = tools.user_inspect(client=_client(users=[user]), username='opbot')
    assert '/usr/local/bin/dbshell' in out


def test_user_inspect_no_policies_flags_unreachable():
    user = {'username': 'alice', 'keys': [], 'policies': []}
    out = tools.user_inspect(client=_client(users=[user]), username='alice')
    assert 'reach no host' in out


# ---------------------------------------------------------------------------
# audit_search
# ---------------------------------------------------------------------------


def test_audit_search_filters_decision():
    out = tools.audit_search(client=_client(), decision='bogus')
    assert 'decision must be one of' in out


def test_audit_search_empty_returns_message():
    out = tools.audit_search(client=_client())
    assert 'No matching audit entries' in out


def test_audit_search_renders_entries():
    entries = [
        {'timestamp': '2026-05-17T10:00:00Z', 'user': 'alice',
         'server': 'srv-acct', 'decision': 'allow'},
        {'timestamp': '2026-05-17T10:01:00Z', 'user': 'bob',
         'server': 'srv-sales', 'decision': 'deny',
         'denied_reason': 'policy_mismatch'},
    ]
    out = tools.audit_search(client=_client(audit=entries))
    assert 'allow alice → srv-acct' in out
    assert ' deny bob → srv-sales (policy_mismatch)' in out


def test_audit_search_passes_filters():
    c = _client()
    tools.audit_search(client=c, user='alice', server='srv-acct',
                       decision='deny', since='1 hour ago', limit=10)
    c.audit.assert_called_once_with(
        user='alice', server='srv-acct', result='deny',
        since='1 hour ago', limit=10)


# ---------------------------------------------------------------------------
# admin_list
# ---------------------------------------------------------------------------


def test_admin_list_empty():
    assert 'No admins enrolled' in tools.admin_list(client=_client())


def test_admin_list_renders():
    admins = [{'name': 'bootstrap', 'role': 'superuser'},
              {'name': 'auditor1', 'role': 'auditor'}]
    out = tools.admin_list(client=_client(admins=admins))
    assert 'bootstrap role=superuser' in out
    assert 'auditor1 role=auditor' in out


# ---------------------------------------------------------------------------
# status (delegates to mssh.admin.state which has its own tests)
# ---------------------------------------------------------------------------


def test_status_no_client_no_ca_dir_returns_init_suggestion():
    out = tools.status(client=None)
    assert 'mssh-admin init' in out


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


def test_tool_registry_contains_expected_tools():
    names = set(tools.tool_names())
    assert names == {'status', 'server_list', 'user_list',
                     'user_inspect', 'audit_search', 'admin_list'}


def test_find_tool_known_and_unknown():
    assert tools.find_tool('status')['name'] == 'status'
    assert tools.find_tool('nonexistent') is None
