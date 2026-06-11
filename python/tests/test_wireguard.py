"""Tests for the WireGuard catalog + admin handlers.

Covers the store directly (key generation, IP allocation, cascade
on server-remove) and the admin handlers (RBAC, config emission).

Tests: §13.7, §4.3.11, §15.14
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
    """Verifies §13.7 — WireGuard keypair generator returns 32-byte X25519 keys."""
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
    """Verifies §13.7 — peer_issue allocates sequential IPs after the server."""
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
    """Verifies §13.7 — removing a server cascades to delete its peers."""
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
    """Verifies §4.3.11 — WireGuard endpoints return 503 when store unconfigured.

    If ctx.wireguard is None, every endpoint returns 503.
    """
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
    """Verifies §4.3.11 — peer_issue returns a ready-to-use client config."""
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
    """Verifies §4.3.11 — auditors get list/show but not init/issue/revoke (RBAC)."""
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


# ---- §15.14 dual-stack tests (v0.4.0+) ------------------------------------

def test_v6_dual_stack_server_address(tmp_path):
    """Verifies §15.14 — dual-stack server gets ::1 alongside .1."""
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(
        name='wg0', network='10.98.123.0/24',
        network_v6='fd00:98:123::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    assert srv.server_address == '10.98.123.1/24'
    assert srv.server_address_v6 == 'fd00:98:123::1/64'
    assert srv.network_v6 == 'fd00:98:123::/64'


def test_v6_only_server_no_v4_fields(tmp_path):
    """Verifies §15.14 — v6-only server omits v4 fields cleanly."""
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(
        name='wg6', network_v6='fd00:6::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    assert srv.network == ''
    assert srv.server_address == ''
    assert srv.server_address_v6 == 'fd00:6::1/64'


def test_server_init_requires_at_least_one_family(tmp_path):
    """Verifies §15.14 — server_init rejects empty network + network_v6."""
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    with pytest.raises(wg.WireGuardError) as exc:
        store.server_init(
            name='wg0', listen_port=51820,
            endpoint='vpn.example.com:51820',
            created_by='bootstrap-admin')
    assert 'at least one' in str(exc.value).lower()


def test_v6_dual_stack_peer_shares_host_number(tmp_path):
    """Verifies §15.14 — dual-stack peer's v6 IID parallels v4 host portion.

    Peer at .10 gets ::a (= 10). This is the load-bearing rule for the
    server-side cryptokey routing — the server's [Peer] AllowedIPs
    must contain both host addresses for the peer's v6 traffic to be
    accepted.
    """
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(
        name='wg0', network='10.98.123.0/24',
        network_v6='fd00:98:123::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    # First peer takes host 2 (server has 1).
    p1, _ = store.peer_issue(name='alice', server_name='wg0',
                             issued_by='bootstrap-admin')
    assert p1.address == '10.98.123.2/32'
    assert p1.address_v6 == 'fd00:98:123::2/128'
    # Second peer takes host 3.
    p2, _ = store.peer_issue(name='bob', server_name='wg0',
                             issued_by='bootstrap-admin')
    assert p2.address == '10.98.123.3/32'
    assert p2.address_v6 == 'fd00:98:123::3/128'


def test_v6_only_peer_uses_min_free_integer(tmp_path):
    """Verifies §15.14 — v6-only allocator scans the peer catalog,
    not the /64 address space. Picks smallest free integer ≥ 2.
    """
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    store.server_init(
        name='wg6', network_v6='fd00:6::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    p1, _ = store.peer_issue(name='alice', server_name='wg6',
                             issued_by='bootstrap-admin')
    p2, _ = store.peer_issue(name='bob', server_name='wg6',
                             issued_by='bootstrap-admin')
    p3, _ = store.peer_issue(name='carol', server_name='wg6',
                             issued_by='bootstrap-admin')
    assert p1.address == ''
    assert p1.address_v6 == 'fd00:6::2/128'
    assert p2.address_v6 == 'fd00:6::3/128'
    assert p3.address_v6 == 'fd00:6::4/128'
    # Revoke bob; carol stays; next allocation reuses bob's number.
    store.peer_revoke(name='bob', server_name='wg6')
    p4, _ = store.peer_issue(name='dave', server_name='wg6',
                             issued_by='bootstrap-admin')
    assert p4.address_v6 == 'fd00:6::3/128'   # reused gap


def test_dual_stack_render_server_config(tmp_path):
    """Verifies §15.14 — server config Address line + per-peer AllowedIPs
    are both dual-stack when network_v6 is set.
    """
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(
        name='wg0', network='10.98.123.0/24',
        network_v6='fd00:98:123::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    peer, _ = store.peer_issue(name='alice', server_name='wg0',
                                issued_by='bootstrap-admin')
    cfg = wg.render_server_config(srv, [peer])
    assert 'Address    = 10.98.123.1/24, fd00:98:123::1/64' in cfg
    # Cryptokey routing — load-bearing line per the ask.
    assert 'AllowedIPs = 10.98.123.2/32, fd00:98:123::2/128' in cfg


def test_dual_stack_render_peer_config(tmp_path):
    """Verifies §15.14 — peer config Address + AllowedIPs are both
    dual-stack when the server is dual-stack.
    """
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(
        name='wg0', network='10.98.123.0/24',
        network_v6='fd00:98:123::/64',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    peer, priv = store.peer_issue(name='alice', server_name='wg0',
                                   issued_by='bootstrap-admin')
    cfg = wg.render_peer_config(srv, peer, priv)
    assert '[Interface]' in cfg
    assert 'Address    = 10.98.123.2/32, fd00:98:123::2/128' in cfg
    # Client routes both server networks through the tunnel.
    assert 'AllowedIPs = 10.98.123.0/24, fd00:98:123::/64' in cfg


def test_v4_only_render_byte_identical_regression(tmp_path):
    """Verifies §15.14 backward compat — v4-only server output is
    byte-for-byte unchanged. Regression guard for the renderer
    refactor in v0.4.0.
    """
    store = wg.WireGuardStore(tmp_path / 'wg.json')
    srv = store.server_init(
        name='wg0', network='10.20.0.0/24',
        listen_port=51820, endpoint='vpn.example.com:51820',
        created_by='bootstrap-admin')
    # Patch the keys deterministically so the snapshot is stable.
    srv.private_key_b64 = 'PRIV_SERVER_B64=='
    srv.public_key_b64 = 'PUB_SERVER_B64=='
    peer, priv = store.peer_issue(name='alice', server_name='wg0',
                                   issued_by='bootstrap-admin')
    peer.public_key_b64 = 'PUB_ALICE_B64=='
    expected_server = (
        '# mssh-admin wireguard server show — emitted config\n'
        '[Interface]\n'
        'Address    = 10.20.0.1/24\n'
        'ListenPort = 51820\n'
        'PrivateKey = PRIV_SERVER_B64==\n'
        '\n'
        '# alice\n'
        '[Peer]\n'
        'PublicKey  = PUB_ALICE_B64==\n'
        'AllowedIPs = 10.20.0.2/32\n')
    assert wg.render_server_config(srv, [peer]) == expected_server


def test_dual_stack_catalog_roundtrip(tmp_path):
    """Verifies §15.14 — new fields survive serialize → load.

    Note: addresses are stored as canonical IPv6 (RFC 5952 compressed):
    ``fd00:0::/64`` → ``fd00::/64`` when round-tripped through
    ipaddress.IPv6Network.
    """
    p = tmp_path / 'wg.json'
    s1 = wg.WireGuardStore(p)
    s1.server_init(
        name='wg0', network='10.0.0.0/24', network_v6='fd00:0::/64',
        listen_port=51820, endpoint='vpn:51820',
        created_by='bootstrap-admin')
    peer, _ = s1.peer_issue(name='alice', server_name='wg0',
                             issued_by='bootstrap-admin')
    # Reload from disk.
    s2 = wg.WireGuardStore(p)
    srv2 = s2.server_get('wg0')
    # network_v6 was passed through verbatim (stored as the operator
    # gave it). server_address_v6 was constructed via ipaddress and
    # is canonical (RFC 5952).
    assert srv2.network_v6 == 'fd00:0::/64'
    assert srv2.server_address_v6 == 'fd00::1/64'
    peer2 = [pp for pp in s2.peer_list('wg0') if pp.name == 'alice'][0]
    assert peer2.address_v6 == 'fd00::2/128'


def test_v0_3_x_catalog_loads_without_v6_fields(tmp_path):
    """Verifies §15.14 backward compat — JSON from v0.3.x (no
    network_v6 / address_v6 keys) loads cleanly with the new fields
    defaulted to '' (i.e. byte-identical v4-only behavior).
    """
    import json
    p = tmp_path / 'wg.json'
    # Hand-craft a v0.3.x-shaped catalog (no v6 fields).
    # On-disk format: servers + peers are lists of dicts.
    p.write_text(json.dumps({
        'servers': [
            {
                'name': 'wg0', 'network': '10.0.0.0/24',
                'listen_port': 51820, 'endpoint': 'vpn:51820',
                'private_key_b64': 'X' * 44,
                'public_key_b64': 'Y' * 44,
                'server_address': '10.0.0.1/24',
                'created_at': '', 'created_by': 'init',
            },
        ],
        'peers': [
            {
                'name': 'alice', 'server_name': 'wg0',
                'address': '10.0.0.2/32',
                'public_key_b64': 'Z' * 44,
                'issued_at': '', 'issued_by': 'init',
                'persistent_keepalive': 0,
            },
        ],
    }))
    store = wg.WireGuardStore(p)
    srv = store.server_get('wg0')
    assert srv.network_v6 == ''
    assert srv.server_address_v6 == ''
    peer = store.peer_list('wg0')[0]
    assert peer.address_v6 == ''


def test_dual_stack_admin_handler_returns_v6_fields(adminctx_with_wg, superuser):
    """Verifies §15.14 — peer-issue response includes address_v6 so
    consumers (e.g. totaldns) don't have to regex it from client_config.
    """
    admin_handlers.wireguard_server_init(adminctx_with_wg, superuser, {
        'name': 'wg0', 'network': '10.0.0.0/24',
        'network_v6': 'fd00::/64',
        'listen_port': 51820, 'endpoint': 'vpn.example.com:51820'})
    status, body = admin_handlers.wireguard_peer_issue(
        adminctx_with_wg, superuser,
        {'name': 'alice', 'server': 'wg0'})
    assert status == 201
    assert body['peer']['address'] == '10.0.0.2/32'
    assert body['peer']['address_v6'] == 'fd00::2/128'
    # Server response also exposes the dual-stack server address.
    status, body = admin_handlers.wireguard_server_show(
        adminctx_with_wg, superuser, 'wg0')
    assert body['server']['network_v6'] == 'fd00::/64'
    assert body['server']['server_address_v6'] == 'fd00::1/64'


def test_admin_handler_400_when_no_family(adminctx_with_wg, superuser):
    """Verifies §15.14 — admin handler returns 400 if neither network
    nor network_v6 is supplied.
    """
    status, body = admin_handlers.wireguard_server_init(
        adminctx_with_wg, superuser,
        {'name': 'wg0', 'listen_port': 51820,
         'endpoint': 'vpn.example.com:51820'})
    assert status == 400
    assert 'network' in body['detail'].lower()
