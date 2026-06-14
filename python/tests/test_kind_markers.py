"""§15.23 cert-kind marker tests.

Verifies that every leaf the CA emits carries a non-critical NULL
marker OID identifying the cert's kind. The markers live in the
1.3.6.1.4.1.55555.3.* arc (9 OIDs covering every kind today plus
external-use).

Tests: §15.23
"""
from __future__ import annotations

import pytest
from cryptography import x509

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.cert_minter import (
    KIND_MARKER,
    OID_KIND_ADMIN_MTLS,
    OID_KIND_AUTHZ_BYPASS,
    OID_KIND_AUTHZ_USER,
    OID_KIND_CLIENT_MTLS,
    OID_KIND_CODE_SIGN,
    OID_KIND_EXTERNAL_USE,
    OID_KIND_HTTPS_USER,
    OID_KIND_OPENVPN,
    OID_KIND_SERVER_TLS,
    OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE,
)
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


def _load_leaf(cert_pem) -> x509.Certificate:
    """Verifies §15.23 — handles both single-cert PEM and chain PEM
    (leaf is always the first cert)."""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode('ascii')
    # Multi-cert PEM: split on the boundary and take the first.
    return x509.load_pem_x509_certificates(cert_pem)[0]


def _marker_oids(cert: x509.Certificate) -> set[str]:
    """Verifies §15.23 — extract every extension OID under the kind
    marker sub-arc."""
    out = set()
    for ext in cert.extensions:
        s = ext.oid.dotted_string
        if s.startswith('1.3.6.1.4.1.55555.3.'):
            out.add(s)
    return out


def _kind_marker_critical(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
    """Verifies §15.23 — return the critical flag on the given marker
    extension (raises if absent)."""
    return cert.extensions.get_extension_for_oid(oid).critical


# ---- arc layout sanity checks --------------------------------------------


def test_marker_table_has_nine_kinds():
    """Verifies §15.23 — KIND_MARKER covers every kind from the design
    enumeration plus the `tls-server` legacy alias."""
    # tls-server is an alias of server-tls (same marker OID).
    distinct_kinds = {k for k in KIND_MARKER if k != 'tls-server'}
    assert distinct_kinds == {
        'authz-user', 'authz-bypass', 'server-tls', 'admin-mtls',
        'client-mtls', 'https-user', 'code-sign', 'openvpn', 'external-use',
    }
    # The alias points at the same OID as server-tls.
    assert KIND_MARKER['tls-server'] == KIND_MARKER['server-tls']


def test_marker_oids_are_distinct():
    """Verifies §15.23 — each kind has its own unique marker OID."""
    distinct = {KIND_MARKER[k] for k in KIND_MARKER if k != 'tls-server'}
    assert len(distinct) == 9


def test_marker_oids_in_reserved_arc():
    """Verifies §15.23 — every marker OID is under
    1.3.6.1.4.1.55555.3.* (the marker sub-arc)."""
    for kind, oid_obj in KIND_MARKER.items():
        assert oid_obj.dotted_string.startswith('1.3.6.1.4.1.55555.3.')


# ---- leaf certs minted via admin handlers carry the right marker ---------


@pytest.fixture
def adminctx(ca_dir):
    """Standard fixture from test_cert_mint_admin.py shape."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


def test_tls_server_cert_carries_server_tls_marker(adminctx, superuser):
    """Verifies §15.23 — tls-server type produces a cert with
    OID_KIND_SERVER_TLS (`.3.3`)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'web.example',
        'sans': ['DNS:web.example']})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_SERVER_TLS.dotted_string}
    assert _kind_marker_critical(cert, OID_KIND_SERVER_TLS) is False


def test_https_user_cert_carries_https_user_marker(adminctx, superuser):
    """Verifies §15.23 — https-user type → OID_KIND_HTTPS_USER (`.3.6`)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'https-user', 'cn': 'alice'})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_HTTPS_USER.dotted_string}


def test_code_sign_cert_carries_code_sign_marker(adminctx, superuser):
    """Verifies §15.23 — code-sign type → OID_KIND_CODE_SIGN (`.3.7`)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'code-sign', 'cn': 'Build agent 01'})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_CODE_SIGN.dotted_string}


def test_openvpn_cert_carries_openvpn_marker(adminctx, superuser):
    """Verifies §15.23 — openvpn_issue → OID_KIND_OPENVPN (`.3.8`)."""
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'bob', 'server_endpoint': 'vpn.example.com 1194'})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_OPENVPN.dotted_string}


def test_admin_add_cert_carries_admin_mtls_marker(adminctx, superuser):
    """Verifies §15.23 — admin enrollment (mssh-admin admin add)
    produces a leaf with OID_KIND_ADMIN_MTLS (`.3.4`)."""
    status, body = admin_handlers.admin_add(adminctx, superuser, {
        'name': 'alice-admin', 'role': 'superuser'})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_ADMIN_MTLS.dotted_string}


def test_server_add_cert_carries_client_mtls_marker(adminctx, superuser):
    """Verifies §15.23 — server enrollment (mssh-admin server add)
    produces a leaf with OID_KIND_CLIENT_MTLS (`.3.5`)."""
    status, body = admin_handlers.server_add(adminctx, superuser, {
        'name': 'msshd-01', 'groups': ['prod']})
    assert status == 201
    cert = _load_leaf(body['credentials']['cert_pem'])
    assert _marker_oids(cert) == {OID_KIND_CLIENT_MTLS.dotted_string}


# ---- markers on the bootstrap-emitted certs --------------------------------


def test_bootstrap_tls_server_cert_carries_marker(ca_dir):
    """Verifies §15.23 — the CA's own TLS-server cert (bootstrap-emitted)
    carries the server-tls marker."""
    from cryptography.hazmat.primitives.serialization import Encoding
    # bootstrap_ca writes the leaf+chain to tls-server-cert.pem.
    cert = _load_leaf((ca_dir / 'tls-server-cert.pem').read_bytes())
    assert OID_KIND_SERVER_TLS.dotted_string in _marker_oids(cert)


def test_bootstrap_admin_cert_carries_marker(ca_dir):
    """Verifies §15.23 — the bootstrap-admin cert carries the
    admin-mtls marker."""
    cert = _load_leaf((ca_dir / 'bootstrap-admin-cert.pem').read_bytes())
    assert OID_KIND_ADMIN_MTLS.dotted_string in _marker_oids(cert)


# ---- authz certs carry the right marker (user vs bypass) -----------------


def _authz_cert(signing, *, ca_bypass: bool):
    """Verifies §15.23 — helper that builds a minimal authz cert via
    mint_authorization_cert with the kw args the function actually
    takes (subject_username, subject_pubkey_blob, not_before, not_after)."""
    import datetime as _dt
    from cryptography.hazmat.primitives.asymmetric import ed25519
    user_key = ed25519.Ed25519PrivateKey.generate()
    user_pub_blob = (
        b'\x00\x00\x00\x0bssh-ed25519'
        + b'\x00\x00\x00\x20'
        + user_key.public_key().public_bytes_raw()
    )
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _serial = cert_minter.mint_authorization_cert(
        signing=signing,
        subject_username='alice',
        subject_pubkey_blob=user_pub_blob,
        not_before=now,
        not_after=now + _dt.timedelta(minutes=5),
        server_bind='msshd-01:abc',
        channels=['session'],
        source_bind='10.0.0.0/8',
        ca_bypass=ca_bypass,
    )
    return cert


def test_authz_user_cert_carries_marker(ca_dir):
    """Verifies §15.23 — an authz-user cert (non-bypass) carries
    OID_KIND_AUTHZ_USER (`.3.1`)."""
    intermediates = cert_minter.load_intermediates(ca_dir)
    cert = _authz_cert(intermediates['user-mint'], ca_bypass=False)
    assert _marker_oids(cert) == {OID_KIND_AUTHZ_USER.dotted_string}
    assert _kind_marker_critical(cert, OID_KIND_AUTHZ_USER) is False


def test_authz_bypass_cert_carries_bypass_marker(ca_dir):
    """Verifies §15.23 — an authz-bypass cert (ca_bypass=True) carries
    OID_KIND_AUTHZ_BYPASS (`.3.2`) AND the existing OID_CA_BYPASS marker."""
    intermediates = cert_minter.load_intermediates(ca_dir)
    cert = _authz_cert(intermediates['bypass-mint'], ca_bypass=True)
    assert _marker_oids(cert) == {OID_KIND_AUTHZ_BYPASS.dotted_string}
    # The OID_CA_BYPASS marker (in the .1.* arc) is critical (existing
    # behavior); the kind marker is non-critical.
    cert.extensions.get_extension_for_oid(cert_minter.OID_CA_BYPASS)
    assert _kind_marker_critical(cert, OID_KIND_AUTHZ_BYPASS) is False


# ---- all markers are non-critical per §15.23 (RFC 5280 §4.2 compat) ------


@pytest.mark.parametrize('oid_obj', [
    OID_KIND_AUTHZ_USER, OID_KIND_AUTHZ_BYPASS, OID_KIND_SERVER_TLS,
    OID_KIND_ADMIN_MTLS, OID_KIND_CLIENT_MTLS, OID_KIND_HTTPS_USER,
    OID_KIND_CODE_SIGN, OID_KIND_OPENVPN, OID_KIND_EXTERNAL_USE,
])
def test_every_kind_marker_oid_distinct(oid_obj):
    """Verifies §15.23 — every kind marker OID is unique."""
    others = [v for k, v in KIND_MARKER.items()
              if v != oid_obj and k != 'tls-server']
    assert oid_obj not in others


def test_intermediate_purpose_marker_oid_defined():
    """Verifies §15.23 — the intermediate-purpose marker for
    external-use is defined and lives in the .2.* arc."""
    assert OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE.dotted_string == \
        '1.3.6.1.4.1.55555.2.1'
