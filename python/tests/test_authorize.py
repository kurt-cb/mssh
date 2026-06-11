"""Unit tests for the authorize handler (logic-only, no HTTP).

Tests: §4.3.1, §3.2
"""
from __future__ import annotations

import base64
import datetime as _dt
from pathlib import Path

import pytest

from mssh.ca import authorize, cert_minter
from mssh.ca.audit import AuditLog
from mssh.ca.authorize import AuthorizeContext, handle_authorize
from mssh.ca.enrollment import Enrollment, KeyBinding


def _b64(b): return base64.b64encode(b).decode('ascii')


def _ts_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


@pytest.fixture
def ctx(tmp_path, ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    return AuthorizeContext(
        enrollment=enroll, audit=audit,
        signing_key=signing_key, signing_cert=signing_cert,
        identity_trust_root_fingerprints=set(),
        default_max_cert_validity_seconds=3600,
        timestamp_drift_seconds=3600,
    )


def _basic_setup(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', ['prod'])
    ctx.enrollment.add_user('alice')
    ctx.enrollment.add_user_key('alice',
        KeyBinding(test_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    ctx.enrollment.add_policy('alice', {
        'servers': ['srv1'], 'channels': ['session', 'direct-tcpip'],
        'max_cert_validity_seconds': 1800,
    })


def test_unknown_server_rejected(ctx, test_key):
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=ghost', _body(test_key))
    assert status == 401
    assert body['status'] == 'denied'


def test_unknown_identity_rejected(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', [])
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 403
    assert body['reason'] == 'unknown_identity'


def test_grant_basic_flow(ctx, test_key):
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 200, body
    assert body['status'] == 'granted'
    assert body['policy_summary']['server_bind'] == 'srv1'
    assert 'session' in body['policy_summary']['channels']
    # And we got a real cert back.
    der = base64.b64decode(body['cert'])
    from cryptography import x509
    from cryptography.x509 import oid
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)
    assert cn and cn[0].value == 'alice'


def test_grant_writes_audit(ctx, test_key):
    _basic_setup(ctx, test_key)
    handle_authorize(ctx, 'CN=srv1', _body(test_key))
    entries = ctx.audit.read_all()
    assert any(e.get('decision') == 'granted' for e in entries)


# R-3 envelope normalization tests. Tests: §14.1, §14.1.1

def test_r3_granted_response_carries_envelope(ctx, test_key):
    """Verifies §14.1 — granted response carries request_id, ca_server_id,
    issued_at, result, protocol_version envelope fields."""
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 200
    # Envelope fields (R-3 additions).
    assert body['result'] == 'granted'
    assert body['request_id']
    assert len(body['request_id']) == 32      # uuid4 hex
    assert body['ca_server_id'] == 'mssh-ca'
    assert body['issued_at']
    assert body['protocol_version']
    # Legacy field still emitted for back-compat (R-3 additive).
    assert body['status'] == 'granted'


def test_r3_granted_response_wraps_credentials(ctx, test_key):
    """Verifies §14.1.1 — granted response wraps cert material in credentials:.

    Both flat keys (legacy) and credentials wrapper (canonical) emitted.
    """
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 200
    # Canonical credentials wrapper (R-3).
    cred = body['credentials']
    assert cred['cert'] == body['cert']             # both flat + wrapped
    assert cred['serial'] == body['serial']
    assert cred['not_after'] == body['not_after']
    assert cred['policy_summary'] == body['policy_summary']
    # cert_pem is operator-facing addition.
    assert cred['cert_pem']
    assert cred['cert_pem'].startswith('-----BEGIN CERTIFICATE-----')


def test_r3_denied_response_carries_envelope_and_denied_reason(ctx, test_key):
    """Verifies §14.1 — denied responses carry envelope + denied_reason.

    Both legacy `reason` and canonical `denied_reason` are emitted.
    """
    # No policy → policy_mismatch deny.
    ctx.enrollment.add_server('srv1', 'CN=srv1', ['prod'])
    ctx.enrollment.add_user('alice')
    ctx.enrollment.add_user_key('alice',
        KeyBinding(test_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 403
    # Envelope (R-3).
    assert body['result'] == 'denied'
    assert body['request_id']
    assert body['ca_server_id']
    assert body['issued_at']
    # Both legacy + canonical deny-reason keys.
    assert body['status'] == 'denied'
    assert body['reason']                            # legacy
    assert body['denied_reason'] == body['reason']   # canonical (R-3)


def test_source_cidr_deny_path(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', [])
    ctx.enrollment.add_user('alice')
    ctx.enrollment.add_user_key('alice',
        KeyBinding(test_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    ctx.enrollment.add_policy('alice', {
        'servers': ['srv1'], 'channels': ['session'],
        'source_cidrs': ['10.0.0.0/8'],
    })
    body = _body(test_key, source_ip='192.168.1.1')
    status, resp = handle_authorize(ctx, 'CN=srv1', body)
    assert status == 403
    assert resp['reason'] == 'source_denied'


def test_clock_drift_rejected(ctx, test_key):
    _basic_setup(ctx, test_key)
    # Override the per-test drift limit.
    ctx.timestamp_drift_seconds = 1
    far = (_dt.datetime.now(tz=_dt.timezone.utc)
           + _dt.timedelta(seconds=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
    body = _body(test_key, timestamp=far)
    status, resp = handle_authorize(ctx, 'CN=srv1', body)
    assert status == 403
    assert resp['reason'] == 'clock_drift'


def test_bad_request(ctx):
    status, resp = handle_authorize(ctx, 'CN=srv1', {})
    assert status in (401, 500)        # unknown server beats parse error


def _body(test_key, *, source_ip='10.0.0.1', source_port=12345,
          timestamp=None, channels=None,
          protocol_version=None, inner_sshd_kind=None,
          inner_sshd_version=None, msshd_version=None) -> dict:
    body = {
        'identity': {
            'type': 'pubkey',
            'data': _b64(test_key.public_blob),
        },
        'connection': {
            'source_ip': source_ip,
            'source_port': source_port,
            'timestamp': timestamp or _ts_now(),
        },
    }
    if channels is not None:
        body['requested_channels'] = channels
    if protocol_version is not None:
        body['protocol_version'] = protocol_version
    if inner_sshd_kind is not None:
        body['inner_sshd_kind'] = inner_sshd_kind
    if inner_sshd_version is not None:
        body['inner_sshd_version'] = inner_sshd_version
    if msshd_version is not None:
        body['msshd_version'] = msshd_version
    return body


# ---------------------------------------------------------------------------
# Phase 1c: protocol-version handshake + inner_sshd_config in the response
# ---------------------------------------------------------------------------


def test_response_always_includes_protocol_version(ctx, test_key):
    """The CA's protocol_version is always emitted, even for 1.0 clients."""
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 200
    # 1.0 client doesn't get inner_sshd_config; but always sees the CA's
    # protocol_version so it can detect upgrades.
    assert 'protocol_version' in body
    assert body['protocol_version'] == '1.1'


def test_omits_inner_sshd_config_for_pre_1_1_clients(ctx, test_key):
    """A request without protocol_version (treated as 1.0) and one
    explicitly at 1.0 both omit inner_sshd_config in the response."""
    _basic_setup(ctx, test_key)

    status1, body1 = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert 'inner_sshd_config' not in body1

    status2, body2 = handle_authorize(
        ctx, 'CN=srv1', _body(test_key, protocol_version='1.0'))
    assert 'inner_sshd_config' not in body2


def test_includes_inner_sshd_config_for_1_1_clients(ctx, test_key):
    """At protocol 1.1+, the response carries a rendered sshd_config."""
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(
        ctx, 'CN=srv1',
        _body(test_key, protocol_version='1.1',
              inner_sshd_kind='openssh',
              inner_sshd_version='9.6p1',
              msshd_version='0.1.0'))
    assert status == 200
    assert 'inner_sshd_config' in body
    rendered = body['inner_sshd_config']
    # LOCAL_ markers are left for msshd's pass.
    assert '{LOCAL_PORT}' in rendered
    assert '{LOCAL_HOST_KEY}' in rendered
    # FROMCA_ markers should be substituted from policy.
    # alice's basic-setup policy grants 'session' and 'direct-tcpip' channels;
    # the channel name we render-from is 'tcp-forwarding' — not granted by
    # this policy, so the directive should be 'no'.
    assert 'AllowTcpForwarding        no' in rendered
    # And the well-known disabled-by-default directives are present.
    assert 'PermitRootLogin                  no' in rendered


def test_per_server_template_drives_rendered_output(ctx, test_key):
    """Setting a per-server template at the CA changes what gets rendered
    for that server."""
    from mssh.ca.templates import set_server_template
    _basic_setup(ctx, test_key)
    custom = (
        '# custom for srv1\n'
        'Port {LOCAL_PORT}\n'
        'ForceCommand {FROMCA_FORCE_COMMAND:none}\n'
    )
    set_server_template(ctx.enrollment, 'srv1', 'openssh', custom)
    status, body = handle_authorize(
        ctx, 'CN=srv1', _body(test_key, protocol_version='1.1'))
    assert status == 200
    # Rendered output starts with the custom template's first line.
    rendered = body['inner_sshd_config']
    assert rendered.startswith('# custom for srv1')


def test_audit_records_client_version_fields(ctx, test_key):
    """The audit log captures client version info for fleet-version
    inventory (mssh-admin status surfaces it)."""
    _basic_setup(ctx, test_key)
    handle_authorize(
        ctx, 'CN=srv1',
        _body(test_key, protocol_version='1.1',
              inner_sshd_kind='openssh',
              inner_sshd_version='9.6p1',
              msshd_version='0.1.0'))
    entries = ctx.audit.read_all()
    granted = [e for e in entries if e.get('decision') == 'granted']
    assert granted
    client = granted[-1].get('client') or {}
    assert client['protocol_version'] == '1.1'
    assert client['inner_sshd_kind'] == 'openssh'
    assert client['inner_sshd_version'] == '9.6p1'
    assert client['msshd_version'] == '0.1.0'


def test_render_error_does_not_block_cert_issuance(ctx, test_key):
    """If the template has a bug, the CA still issues a cert (msshd will
    handle the fallback path) but records the error in audit."""
    from mssh.ca.templates import set_default_template
    _basic_setup(ctx, test_key)
    # Bogus template: unknown FROMCA marker → render raises TemplateError.
    set_default_template(ctx.enrollment, 'openssh',
                         '# bogus\nFoo {FROMCA_BOGUS_THING}\n')
    status, body = handle_authorize(
        ctx, 'CN=srv1', _body(test_key, protocol_version='1.1'))
    # Cert still issued.
    assert status == 200
    assert body['status'] == 'granted'
    assert 'cert' in body
    # No rendered config in response.
    assert 'inner_sshd_config' not in body
    # Audit captures the error.
    entries = ctx.audit.read_all()
    granted = [e for e in entries if e.get('decision') == 'granted']
    assert granted[-1].get('inner_sshd_config_error', '').startswith('render_failed')
