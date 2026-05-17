"""Unit tests for mssh.admin.state — the detector behind `mssh-admin status`
and `mssh-admin next`."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mssh.admin.state import (
    _CA_BOOTSTRAP_FILES,
    DeploymentState,
    StateNode,
    ca_url_from_config,
    detect_legacy_config,
    detect_state,
    render_next,
    render_status,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _seed_ca_dir(d: Path, missing: list[str] | None = None) -> None:
    """Create empty placeholder files for every bootstrap artifact except
    those in `missing`, plus a minimal ca-config.yaml."""
    skip = set(missing or [])
    for fn in _CA_BOOTSTRAP_FILES:
        if fn in skip:
            continue
        if fn == 'ca-config.yaml':
            (d / fn).write_text('listen: 127.0.0.1:8443\n')
        else:
            (d / fn).write_text('placeholder\n')


def _fake_client(*, base_url='https://127.0.0.1:8443',
                 servers=None, users=None, admins=None,
                 reachable=True) -> MagicMock:
    client = MagicMock()
    client.base_url = base_url
    if reachable:
        client.admin_list.return_value = admins or []
        client.server_list.return_value = servers or []
        client.user_list.return_value = users or []
    else:
        client.admin_list.side_effect = RuntimeError('connection refused')
    return client


# ---------------------------------------------------------------------------
# Phase A: filesystem-only checks
# ---------------------------------------------------------------------------


def test_no_ca_dir_yields_init_suggestion():
    s = detect_state(ca_dir=None, detect_legacy=False)
    assert not s.all_ok
    first = s.first_failure
    assert first is not None
    assert first.id == 'ca_dir_set'
    assert 'init' in (first.next_command or '')


def test_nonexistent_ca_dir_yields_init_suggestion(tmp_path):
    s = detect_state(ca_dir=tmp_path / 'nonexistent', detect_legacy=False)
    assert not s.all_ok
    assert s.first_failure.id == 'ca_dir_exists'
    assert 'init' in s.first_failure.next_command


def test_partial_ca_dir_reports_missing_files(tmp_path):
    _seed_ca_dir(tmp_path, missing=['signing-key.pem', 'enrollment.yaml'])
    s = detect_state(ca_dir=tmp_path, detect_legacy=False)
    assert not s.all_ok
    failure = s.first_failure
    assert failure.id == 'ca_bootstrap_files'
    assert 'signing-key.pem' in failure.message
    assert 'enrollment.yaml' in failure.message


def test_complete_ca_dir_without_client_reports_client_gap(tmp_path):
    _seed_ca_dir(tmp_path)
    s = detect_state(ca_dir=tmp_path, ca_client=None, detect_legacy=False)
    assert s.nodes[1].ok  # ca_bootstrap_files ok
    failure = s.first_failure
    assert failure.id == 'admin_client_configured'


# ---------------------------------------------------------------------------
# Phase B: API reachability
# ---------------------------------------------------------------------------


def test_unreachable_ca_surfaces_start_suggestion(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(reachable=False)
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    failure = s.first_failure
    assert failure.id == 'ca_reachable'
    assert 'mssh-ca' in failure.next_command


# ---------------------------------------------------------------------------
# Phase C: enrollment counts
# ---------------------------------------------------------------------------


def test_no_servers_yields_server_add_suggestion(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(admins=[{'name': 'bootstrap', 'role': 'superuser'}],
                          servers=[], users=[])
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    failure = s.first_failure
    assert failure.id == 'servers_enrolled'
    assert 'server add' in failure.next_command


def test_no_users_yields_user_add_suggestion(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(
        admins=[{'name': 'b', 'role': 'superuser'}],
        servers=[{'name': 'srv-1', 'groups': ['production']}],
        users=[])
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    failure = s.first_failure
    assert failure.id == 'users_enrolled'
    assert 'user add' in failure.next_command


def test_user_without_keys_is_surfaced(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(
        admins=[{'name': 'b', 'role': 'superuser'}],
        servers=[{'name': 'srv-1', 'groups': ['production']}],
        users=[{'username': 'alice', 'keys': [], 'policies': []}])
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    failure = s.first_failure
    assert failure.id == 'users_have_keys'
    assert 'alice' in failure.message


def test_user_with_key_but_no_policy_is_surfaced(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(
        admins=[{'name': 'b', 'role': 'superuser'}],
        servers=[{'name': 'srv-1', 'groups': ['production']}],
        users=[{'username': 'alice',
                'keys': [{'fingerprint': 'aa:bb', 'type': 'ssh-pubkey',
                          'key_type': 'ssh-ed25519', 'key_id': '',
                          'principals': []}],
                'policies': []}])
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    failure = s.first_failure
    assert failure.id == 'users_have_policies'
    assert 'alice' in failure.message
    assert 'reach no host' in failure.message


def test_fully_provisioned_has_no_failure(tmp_path):
    _seed_ca_dir(tmp_path)
    client = _fake_client(
        admins=[{'name': 'b', 'role': 'superuser'}],
        servers=[{'name': 'srv-1', 'groups': ['production']}],
        users=[{'username': 'alice',
                'keys': [{'fingerprint': 'aa:bb', 'type': 'ssh-pubkey',
                          'key_type': 'ssh-ed25519', 'key_id': '',
                          'principals': []}],
                'policies': [{'id': 'pol-1', 'servers': [],
                              'server_groups': ['production'],
                              'channels': ['session'],
                              'source_cidrs': [], 'time_window': None,
                              'max_cert_validity_seconds': 600,
                              'environment': {}, 'force_command': None}]}])
    s = detect_state(ca_dir=tmp_path, ca_client=client, detect_legacy=False)
    assert s.all_ok
    assert s.first_failure is None


# ---------------------------------------------------------------------------
# Legacy-config detection
# ---------------------------------------------------------------------------


def test_detect_legacy_config_skip_homes_off_runs():
    # Just check it returns a list and doesn't crash on /root.
    found = detect_legacy_config(scan_homes=False)
    assert isinstance(found, list)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_status_includes_all_nodes(tmp_path):
    s = DeploymentState(ca_dir=tmp_path, nodes=[
        StateNode(id='a', ok=True, message='a ok'),
        StateNode(id='b', ok=False, message='b not ok',
                  next_step='do thing', next_command='thing --foo'),
    ])
    out = render_status(s)
    assert 'a ok' in out
    assert 'b not ok' in out
    assert 'thing --foo' in out


def test_render_next_only_shows_first_failure(tmp_path):
    s = DeploymentState(ca_dir=tmp_path, nodes=[
        StateNode(id='a', ok=True, message='a ok'),
        StateNode(id='b', ok=False, message='b not ok',
                  next_step='do thing', next_command='thing --foo'),
        StateNode(id='c', ok=False, message='c also broken',
                  next_step='do other'),
    ])
    out = render_next(s)
    assert 'b not ok' in out
    assert 'c also broken' not in out


def test_render_next_says_all_ok_when_all_pass(tmp_path):
    s = DeploymentState(ca_dir=tmp_path, nodes=[
        StateNode(id='a', ok=True, message='a ok'),
    ])
    out = render_next(s)
    assert 'fully provisioned' in out.lower()


# ---------------------------------------------------------------------------
# ca-config helper
# ---------------------------------------------------------------------------


def test_ca_url_from_config_handles_wildcard_listen(tmp_path):
    (tmp_path / 'ca-config.yaml').write_text('listen: 0.0.0.0:8443\n')
    assert ca_url_from_config(tmp_path) == 'https://127.0.0.1:8443'


def test_ca_url_from_config_handles_specific_host(tmp_path):
    (tmp_path / 'ca-config.yaml').write_text('listen: 10.0.0.5:9000\n')
    assert ca_url_from_config(tmp_path) == 'https://10.0.0.5:9000'


def test_ca_url_from_config_returns_none_if_missing(tmp_path):
    assert ca_url_from_config(tmp_path) is None
