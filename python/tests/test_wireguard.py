"""Tests for the WireGuard catalog + admin handlers.

Covers the store directly (key generation, IP allocation, cascade
on server-remove) and the admin handlers (RBAC, config emission).
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import wireguard as wg
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


# ---- WireGuardStore unit tests --------------------------------------------

def test_keypair_size():
    priv, pub = wg.generate_wg_keypair()
    assert len(priv) == 32 and len(pub) == 32


def test_server_init_allocates_first_ip(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(name='wg0', network='10.20.0.0/24',
                            listen_port=51820,
                            endpoint='vpn.example.com:51820',
                            created_by='admin')
    assert srv.server_address == '10.20.0.1/24'
    assert len(base64.b64decode(srv.public_key_b64)) == 32


def test_server_init_rejects_tiny_network(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    with pytest.raises(wg.WireGuardError, match='too small'):
        store.server_init(name='wg0', network='10.20.0.0/31',
                          listen_port=51820,
                          endpoint='vpn.example.com:51820',
                          created_by='admin')


def test_server_init_duplicate_conflict(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/24',
                      listen_port=51820, endpoint='vpn.example.com:51820',
                      created_by='admin')
    with pytest.raises(wg.WireGuardConflict):
        store.server_init(name='wg0', network='10.30.0.0/24',
                          listen_port=51820,
                          endpoint='vpn.example.com:51820',
                          created_by='admin')


def test_peer_issue_assigns_sequential_ips(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/24',
                      listen_port=51820, endpoint='vpn:51820',
                      created_by='admin')
    p1, priv1 = store.peer_issue(name='alice', server_name='wg0',
                                 issued_by='admin')
    p2, priv2 = store.peer_issue(name='bob', server_name='wg0',
                                 issued_by='admin')
    # Server takes .1; peers take .2 and .3.
    assert p1.address == '10.20.0.2/32'
    assert p2.address == '10.20.0.3/32'
    assert priv1 != priv2 and len(priv1) == 32


def test_peer_issue_capacity_exhausted(tmp_path):
    """Fill a /30 — 2 usable hosts: server takes .1, one peer fits."""
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/30',
                      listen_port=51820, endpoint='vpn:51820',
                      created_by='admin')
    # /30 has 4 addresses → 2 hosts. Server takes one; one peer fits.
    store.peer_issue(name='alice', server_name='wg0', issued_by='admin')
    with pytest.raises(wg.WireGuardCapacityError):
        store.peer_issue(name='bob', server_name='wg0', issued_by='admin')


def test_peer_issue_unknown_server(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    with pytest.raises(wg.WireGuardNotFound):
        store.peer_issue(name='alice', server_name='nope', issued_by='admin')


def test_peer_issue_duplicate_conflict(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/24',
                      listen_port=51820, endpoint='vpn:51820',
                      created_by='admin')
    store.peer_issue(name='alice', server_name='wg0', issued_by='admin')
    with pytest.raises(wg.WireGuardConflict):
        store.peer_issue(name='alice', server_name='wg0', issued_by='admin')


def test_peer_revoke(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/24',
                      listen_port=51820, endpoint='vpn:51820',
                      created_by='admin')
    store.peer_issue(name='alice', server_name='wg0', issued_by='admin')
    store.peer_revoke(name='alice', server_name='wg0')
    assert store.peer_list('wg0') == []
    # Re-issuing alice should now succeed (and pick the same IP, since
    # the slot freed up).
    p, _ = store.peer_issue(name='alice', server_name='wg0',
                             issued_by='admin')
    assert p.address == '10.20.0.2/32'


def test_server_remove_cascades_peers(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(name='wg0', network='10.20.0.0/24',
                      listen_port=51820, endpoint='vpn:51820',
                      created_by='admin')
    store.peer_issue(name='alice', server_name='wg0', issued_by='admin')
    store.peer_issue(name='bob', server_name='wg0', issued_by='admin')
    store.server_remove('wg0')
    assert store.peer_list() == []
    assert store.server_list() == []


def test_persistence_round_trip(tmp_path):
    """A second store opened on the same file sees the same state."""
    path = tmp_path / 'wg.json'
    s1 = wg.WireGuardStore(path)
    s1.server_init(name='wg0', network='10.20.0.0/24',
                   listen_port=51820, endpoint='vpn:51820',
                   created_by='admin')
    s1.peer_issue(name='alice', server_name='wg0', issued_by='admin')
    # Catalog file is mode 0600.
    assert (path.stat().st_mode & 0o777) == 0o600

    s2 = wg.WireGuardStore(path)
    servers = s2.server_list()
    peers = s2.peer_list()
    assert len(servers) == 1 and servers[0].name == 'wg0'
    assert len(peers) == 1 and peers[0].name == 'alice'


def test_render_server_config_layout(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(name='wg0', network='10.20.0.0/24',
                            listen_port=51820,
                            endpoint='vpn.example.com:51820',
                            created_by='admin')
    p1, _ = store.peer_issue(name='alice', server_name='wg0',
                              issued_by='admin')
    p2, _ = store.peer_issue(name='bob', server_name='wg0',
                              issued_by='admin')
    out = wg.render_server_config(srv, [p1, p2])
    assert '[Interface]' in out
    assert 'PrivateKey = ' in out
    assert 'Address    = 10.20.0.1/24' in out
    assert out.count('[Peer]') == 2
    assert '10.20.0.2/32' in out
    assert '10.20.0.3/32' in out


def test_render_peer_config_layout(tmp_path):
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(name='wg0', network='10.20.0.0/24',
                            listen_port=51820,
                            endpoint='vpn.example.com:51820',
                            created_by='admin')
    peer, priv = store.peer_issue(name='alice', server_name='wg0',
                                   issued_by='admin',
                                   persistent_keepalive=25)
    out = wg.render_peer_config(srv, peer, priv, dns='10.20.0.1')
    assert '[Interface]' in out and '[Peer]' in out
    assert 'PrivateKey = ' in out
    assert 'Address    = 10.20.0.2/32' in out
    assert 'DNS        = 10.20.0.1' in out
    assert 'Endpoint   = vpn.example.com:51820' in out
    assert 'AllowedIPs = 10.20.0.0/24' in out
    assert 'PersistentKeepalive = 25' in out


# ---- Admin handler tests ---------------------------------------------------

@pytest.fixture
def adminctx_with_wg(ca_dir, tmp_path):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    from mssh.ca import cert_minter
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        wireguard=store,
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def auditor():
    return Admin(name='audit-bob', role='auditor',
                 mtls_subject='CN=audit-bob')


def test_handler_503_when_wireguard_not_configured(ca_dir, superuser):
    """If ctx.wireguard is None, every endpoint returns 503."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    from mssh.ca import cert_minter
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )  # wireguard left at None
    status, body = admin_handlers.wireguard_server_list(ctx, superuser)
    assert status == 503
    assert 'not configured' in body['detail']


def test_handler_server_init_ok(adminctx_with_wg, superuser):
    status, body = admin_handlers.wireguard_server_init(
        adminctx_with_wg, superuser, {
            'name': 'wg0', 'network': '10.20.0.0/24',
            'listen_port': 51820, 'endpoint': 'vpn.example.com:51820',
        })
    assert status == 201
    assert body['server']['name'] == 'wg0'
    assert body['server']['server_address'] == '10.20.0.1/24'


def test_handler_server_init_validates(adminctx_with_wg, superuser):
    status, body = admin_handlers.wireguard_server_init(
        adminctx_with_wg, superuser, {
            'name': 'wg0', 'network': '', 'endpoint': '',
        })
    assert status == 400


def test_handler_server_init_forbidden_for_auditor(adminctx_with_wg, auditor):
    status, body = admin_handlers.wireguard_server_init(
        adminctx_with_wg, auditor, {
            'name': 'wg0', 'network': '10.20.0.0/24',
            'listen_port': 51820, 'endpoint': 'vpn.example.com:51820',
        })
    assert status == 403


def test_handler_peer_issue_returns_client_config(adminctx_with_wg, superuser):
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.20.0.0/24',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    status, body = admin_handlers.wireguard_peer_issue(
        adminctx_with_wg, superuser,
        {'name': 'alice', 'server': 'wg0', 'persistent_keepalive': 25})
    assert status == 201
    config = body['client_config']
    assert '[Interface]' in config
    assert 'PrivateKey = ' in config
    assert 'PersistentKeepalive = 25' in config
    assert body['peer']['address'] == '10.20.0.2/32'


def test_handler_server_show_includes_peers(adminctx_with_wg, superuser):
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.20.0.0/24',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    admin_handlers.wireguard_peer_issue(adminctx_with_wg, superuser,
        {'name': 'alice', 'server': 'wg0'})
    admin_handlers.wireguard_peer_issue(adminctx_with_wg, superuser,
        {'name': 'bob', 'server': 'wg0'})
    status, body = admin_handlers.wireguard_server_show(
        adminctx_with_wg, superuser, 'wg0')
    assert status == 200
    assert body['server']['peer_count'] == 2
    cfg = body['server_config']
    assert cfg.count('[Peer]') == 2
    assert '10.20.0.2/32' in cfg and '10.20.0.3/32' in cfg


def test_handler_peer_revoke_then_relist(adminctx_with_wg, superuser):
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.20.0.0/24',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    admin_handlers.wireguard_peer_issue(adminctx_with_wg, superuser,
        {'name': 'alice', 'server': 'wg0'})
    status, _ = admin_handlers.wireguard_peer_revoke(
        adminctx_with_wg, superuser, 'wg0', 'alice')
    assert status == 200
    status, body = admin_handlers.wireguard_peer_list(
        adminctx_with_wg, superuser, 'wg0')
    assert body['peers'] == []


def test_handler_peer_revoke_unknown_404(adminctx_with_wg, superuser):
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.20.0.0/24',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    status, body = admin_handlers.wireguard_peer_revoke(
        adminctx_with_wg, superuser, 'wg0', 'nobody')
    assert status == 404


def test_auditor_can_read_not_write(adminctx_with_wg, superuser, auditor):
    """Auditors get list/show but not init/issue/revoke."""
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.20.0.0/24',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    # Reads OK:
    status, _ = admin_handlers.wireguard_server_list(adminctx_with_wg, auditor)
    assert status == 200
    status, _ = admin_handlers.wireguard_peer_list(adminctx_with_wg, auditor, None)
    assert status == 200
    # Mutations forbidden:
    status, _ = admin_handlers.wireguard_peer_issue(
        adminctx_with_wg, auditor,
        {'name': 'alice', 'server': 'wg0'})
    assert status == 403
