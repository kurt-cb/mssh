"""Unit tests for the template admin handlers (mssh.ca.admin.template_*).

Tests the handler-layer functions directly (the HTTP wiring in server.py
is exercised by the existing CA integration tests; we don't need to
spin up Flask here).

Tests: §4.3.12 (admin side)
"""
from __future__ import annotations

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment, KeyBinding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    enroll.add_server('srv-acct', 'CN=srv-acct', groups=['accounting'])
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )


@pytest.fixture
def superuser():
    return Admin(name='root-admin', role='superuser',
                 mtls_subject='CN=root-admin')


@pytest.fixture
def auditor():
    return Admin(name='reader', role='auditor', mtls_subject='CN=reader')


# Minimal valid template using only known markers.
_VALID_TPL = (
    '# v1 template\n'
    'Port {LOCAL_PORT}\n'
    'ForceCommand {FROMCA_FORCE_COMMAND:none}\n'
    'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING:no}\n'
)


# ---------------------------------------------------------------------------
# template_set
# ---------------------------------------------------------------------------


def test_set_default_template(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh', 'content': _VALID_TPL,
    })
    assert status == 200
    assert body['scope'] == 'default'
    assert ctx.enrollment.templates_default.get('openssh') == _VALID_TPL


def test_set_group_template(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'group', 'scope_name': 'accounting',
        'kind': 'openssh', 'content': _VALID_TPL,
    })
    assert status == 200
    assert ctx.enrollment.templates_groups['accounting']['openssh'] == _VALID_TPL


def test_set_server_template(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'server', 'scope_name': 'srv-acct',
        'kind': 'openssh', 'content': _VALID_TPL,
    })
    assert status == 200
    assert ctx.enrollment.templates_servers['srv-acct']['openssh'] == _VALID_TPL


def test_set_server_template_unknown_server(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'server', 'scope_name': 'nonexistent',
        'kind': 'openssh', 'content': _VALID_TPL,
    })
    assert status == 404
    assert body['reason'] == 'not_found'


def test_set_template_rejects_unknown_marker(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh',
        'content': 'Foo {FROMCA_NO_SUCH_VAR}\n',
    })
    assert status == 400
    assert body['reason'] == 'invalid_template'
    assert 'FROMCA_NO_SUCH_VAR' in body['detail']


def test_set_template_requires_group_name(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'group', 'kind': 'openssh', 'content': _VALID_TPL,
        # no scope_name
    })
    assert status == 400
    assert 'requires scope_name' in body['detail']


def test_set_template_requires_content_string(ctx, superuser):
    status, body = admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh', 'content': 12345,
    })
    assert status == 400


def test_set_template_role_check_blocks_auditor(ctx, auditor):
    status, body = admin_handlers.template_set(ctx, auditor, {
        'scope': 'default', 'kind': 'openssh', 'content': _VALID_TPL,
    })
    assert status == 403


def test_set_template_writes_audit_entry(ctx, superuser):
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh', 'content': _VALID_TPL,
    })
    entries = ctx.audit.read_all()
    admin_entries = [e for e in entries
                     if e.get('action') == 'template.set']
    assert admin_entries
    assert admin_entries[-1]['admin']['name'] == 'root-admin'


# ---------------------------------------------------------------------------
# template_unset
# ---------------------------------------------------------------------------


def test_unset_default(ctx, superuser):
    # set then unset
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh', 'content': _VALID_TPL,
    })
    status, _ = admin_handlers.template_unset(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh',
    })
    assert status == 200
    assert 'openssh' not in ctx.enrollment.templates_default


def test_unset_idempotent(ctx, superuser):
    """Unsetting a non-existent override is a successful no-op."""
    status, _ = admin_handlers.template_unset(ctx, superuser, {
        'scope': 'server', 'scope_name': 'srv-acct', 'kind': 'openssh',
    })
    assert status == 200


def test_unset_template_role_check_blocks_auditor(ctx, auditor):
    status, _ = admin_handlers.template_unset(ctx, auditor, {
        'scope': 'default', 'kind': 'openssh',
    })
    assert status == 403


# ---------------------------------------------------------------------------
# template_list
# ---------------------------------------------------------------------------


def test_list_includes_builtin_when_no_overrides(ctx, superuser):
    status, body = admin_handlers.template_list(ctx, superuser)
    assert status == 200
    assert 'openssh' in body['templates']['builtin']
    assert body['templates']['default'] == {}
    assert body['templates']['groups'] == {}
    assert body['templates']['servers'] == {}


def test_list_reflects_all_overrides(ctx, superuser):
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh', 'content': '# d\n'
        'Port {LOCAL_PORT}\n',
    })
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'group', 'scope_name': 'accounting',
        'kind': 'openssh', 'content': '# g\nPort {LOCAL_PORT}\n',
    })
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'server', 'scope_name': 'srv-acct',
        'kind': 'openssh', 'content': '# s\nPort {LOCAL_PORT}\n',
    })
    status, body = admin_handlers.template_list(ctx, superuser)
    assert status == 200
    tpls = body['templates']
    assert tpls['default']['openssh'].startswith('# d')
    assert tpls['groups']['accounting']['openssh'].startswith('# g')
    assert tpls['servers']['srv-acct']['openssh'].startswith('# s')


def test_list_allowed_for_auditor(ctx, auditor):
    """Auditors can read templates (needed to verify policy alignment)."""
    status, _ = admin_handlers.template_list(ctx, auditor)
    assert status == 200


# ---------------------------------------------------------------------------
# template_effective
# ---------------------------------------------------------------------------


def test_effective_walks_precedence_to_server(ctx, superuser):
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'default', 'kind': 'openssh',
        'content': '# default\nPort {LOCAL_PORT}\n',
    })
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'group', 'scope_name': 'accounting',
        'kind': 'openssh', 'content': '# group\nPort {LOCAL_PORT}\n',
    })
    admin_handlers.template_set(ctx, superuser, {
        'scope': 'server', 'scope_name': 'srv-acct',
        'kind': 'openssh', 'content': '# server\nPort {LOCAL_PORT}\n',
    })
    status, body = admin_handlers.template_effective(
        ctx, superuser, 'srv-acct', 'openssh')
    assert status == 200
    assert body['source'] == 'server'
    assert body['content'].startswith('# server')


def test_effective_falls_back_to_builtin_when_nothing_set(ctx, superuser):
    status, body = admin_handlers.template_effective(
        ctx, superuser, 'srv-acct', 'openssh')
    assert status == 200
    assert body['source'] == 'builtin'
    assert 'TrustedUserCAKeys' in body['content']


def test_effective_unknown_kind_400s(ctx, superuser):
    status, body = admin_handlers.template_effective(
        ctx, superuser, 'srv-acct', 'dropbear')
    assert status == 400
