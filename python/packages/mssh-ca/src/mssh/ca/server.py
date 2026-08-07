"""Flask app + mTLS listener.

Design: §4.3.13 (see design/mssh_design_v1.md) — server entrypoint and
Flask app wiring. Routes here delegate to authorize.py (§4.3.1),
admin.py (§4.3.6), etc.

For PoC: a single Flask app, mTLS enforced via Werkzeug's ``ssl_context``.
Client cert is extracted from the request environ (``SSL_CLIENT_CERT`` in PEM
or the raw cert from the WSGI handler) — we use the underlying ``ssl`` socket.
"""
from __future__ import annotations

import argparse
import base64
import logging
import ssl
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import oid
from flask import Flask, g, jsonify, request

from . import admin as admin_handlers
from . import authorize
from . import cert_minter
from .audit import AuditLog
from .config import CAConfig
from .enrollment import Enrollment
from ..identity import sha256_fingerprint


log = logging.getLogger('mssh-ca')


def _load_identity_trust_root_fingerprints(paths: list[str]) -> set[str]:
    """Load OpenSSH user CA pubkey files and return their SHA256 fingerprints."""
    out: set[str] = set()
    for path in paths:
        p = Path(path)
        if not p.exists():
            log.warning('identity trust root %s does not exist; skipping', path)
            continue
        text = p.read_text().strip()
        # OpenSSH "ssh-ed25519 AAAA... comment" — the middle field is the blob.
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                blob = base64.b64decode(parts[1])
            except Exception:
                continue
            out.add(sha256_fingerprint(blob))
    return out


def _extract_client_cert(req) -> 'x509.Certificate | None':
    """Return the parsed peer cert from this request, or None.

    Tries the WSGI environ first (test-injected), then the
    custom ``peercert_der`` slot our request handler populates
    from the live socket. Same lookup as the prior CN-only
    helper.
    """
    env = req.environ
    pem = env.get('SSL_CLIENT_CERT') or env.get('werkzeug.peer_cert_pem')
    if pem:
        try:
            return x509.load_pem_x509_certificate(pem.encode('ascii'))
        except Exception:
            return None
    der = env.get('peercert_der')
    if der:
        try:
            return x509.load_der_x509_certificate(der)
        except Exception:
            return None
    return None


def _extract_client_cert_subject(req) -> str | None:
    """Pull CN from the client cert presented in this request.

    Returns ``None`` if no cert. Returned as a ``"CN=..."`` string
    matching the format used in the enrollment store.
    """
    cert = _extract_client_cert(req)
    if cert is None:
        return None
    return _cn_from_cert(cert)


def _cn_from_cert(cert: x509.Certificate) -> str | None:
    try:
        cn = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)
        if cn:
            return f'CN={cn[0].value}'
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(config: CAConfig) -> Flask:
    # §4.3.13 server bootstrap; loads enrollment (§4.3.2), audit
    # (§4.3.7), CRL registry (§4.3.5), intermediates (§2.2)
    app = Flask(__name__)
    app.config['CA_CONFIG'] = config

    enrollment = Enrollment(config.enrollment_path)
    audit = AuditLog(config.audit_path or '/tmp/mssh-audit.jsonl')

    signing_key = cert_minter.load_private_key(config.signing_key)
    signing_cert = cert_minter.load_certificate(config.signing_cert)
    tls_ca_cert = cert_minter.load_certificate(
        Path(config.signing_cert).parent / 'tls-ca-cert.pem')
    tls_ca_key = cert_minter.load_private_key(
        Path(config.signing_cert).parent / 'tls-ca-key.pem')

    # Per-issuer CRL registry lives next to the enrollment file. One
    # log per intermediate (user-mint.jsonl, bypass-mint.jsonl, etc.);
    # auto-migrates the legacy single-file crl.jsonl on upgrade from
    # v0.2.1 or earlier.
    from . import crl as _crl
    crl_dir = Path(config.enrollment_path).parent / 'crl'
    _crl.migrate_legacy_crl(
        crl_dir, Path(config.enrollment_path).parent / 'crl.jsonl')
    crl_store = _crl.CRLRegistry(crl_dir)

    identity_fps = _load_identity_trust_root_fingerprints(config.identity_trust_roots)

    auth_ctx = authorize.AuthorizeContext(
        enrollment=enrollment, audit=audit,
        signing_key=signing_key, signing_cert=signing_cert,
        identity_trust_root_fingerprints=identity_fps,
        default_max_cert_validity_seconds=config.default_max_cert_validity_seconds,
        timestamp_drift_seconds=config.timestamp_drift_seconds,
        crl=crl_store,
        crl_url=(config.crl_url or None),        # R-2
    )
    # WireGuard catalog (optional). Loaded lazily; None means
    # WireGuard endpoints respond 503.
    wg_store = None
    if config.wireguard_path:
        from . import wireguard as _wg
        wg_store = _wg.WireGuardStore(config.wireguard_path)

    # mssh-passkey broker integration (optional). All of the
    # passkey_* fields must be set together or none of them.
    passkey_broker = None
    passkey_allowlist = None
    pending_regs = None
    pending_auths = None
    cache_2fa = None
    if config.passkey_broker_url:
        from . import passkey_broker as _pb
        from . import passkey as _pk
        passkey_broker = _pb.PasskeyBrokerClient(
            base_url=config.passkey_broker_url,
            client_cert=config.passkey_client_cert,
            client_key=config.passkey_client_key,
            ca_cert=config.passkey_ca_cert,
        )
        passkey_allowlist = _pk.AAGUIDAllowlist.load(
            config.passkey_aaguid_allowlist_path or None)
        pending_regs = {}
        pending_auths = {}
        cache_2fa = {}

    admin_ctx = admin_handlers.AdminContext(
        enrollment=enrollment, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=config.server_cert_validity_days,
        admin_cert_validity_days=config.admin_cert_validity_days,
        mtls_key_type=config.mtls_key_type,
        signing_key=signing_key, signing_cert=signing_cert,
        crl=crl_store,
        crl_url=(config.crl_url or None),
        wireguard=wg_store,
        passkey_broker=passkey_broker,
        passkey_rp_id=config.passkey_rp_id,
        passkey_rp_name=config.passkey_rp_name,
        passkey_expected_origin=config.passkey_expected_origin,
        passkey_callback_url=config.passkey_callback_url,
        passkey_aaguid_allowlist=passkey_allowlist,
        passkey_pending_registrations=pending_regs,
        passkey_pending_authentications=pending_auths,
        passkey_2fa_cache=cache_2fa,
        admin_2fa_protected_actions=frozenset(config.admin_2fa_protected_actions),
        admin_2fa_within_seconds=config.admin_2fa_within_seconds,
        # PKI hierarchy root dir. We derive it from signing_cert's
        # parent — bootstrap_ca writes everything next to signing-cert.pem.
        ca_dir=str(Path(config.signing_cert).parent
                    if config.signing_cert else ''),
        # §15.23 per-kind validity policy from ca-config.yaml.
        cert_kinds=config.cert_kinds,
        # §15.21 operator-allowlisted custom OIDs.
        custom_oids=config.custom_oids,
        # R-10 §14.3.6 — operator MCP capability allow-list (echoed
        # onto the context for diagnostics; the live gating uses the
        # module-level MCP_ALLOWED_ACTIONS installed below).
        mcp_allow_list=(config.mcp.capability_allow_list
                         if config.mcp.capability_allow_list is not None
                         else None),
    )

    # R-10 §14.3.6 — install operator's MCP allow-list (or restore the
    # built-in default if the operator's config has no `mcp:` section).
    admin_handlers.set_mcp_allow_list(config.mcp.capability_allow_list)

    app.config['AUTH_CTX'] = auth_ctx
    app.config['ADMIN_CTX'] = admin_ctx
    app.config['ENROLLMENT'] = enrollment
    app.config['AUDIT'] = audit

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    # §4.3.13 route table; §3.2 v1/authorize wire, §4.3.6 v1/admin/*
    @app.before_request
    def _attach_caller():
        g.client_cert = _extract_client_cert(request)
        g.client_subject = (_cn_from_cert(g.client_cert)
                             if g.client_cert is not None else None)
        # §12.4.2 origin tag: lowercased + allowlisted. Any value
        # other than the recognised set is dropped to avoid an
        # attacker setting it to something spoofy. v1 recognised:
        # 'mcp' (set by mssh-mcp's CA client per §12.4.2).
        raw_origin = (request.headers.get('X-MSSH-Origin') or '').strip().lower()
        g.client_origin = raw_origin if raw_origin in {'mcp'} else ''

    @app.errorhandler(Exception)
    def _on_error(e: Exception):
        log.exception('unhandled error')
        return jsonify(status='error', reason='internal', detail=str(e)), 500

    # ---- Authorization ----
    @app.post('/v1/authorize')
    def _authorize():
        subj = g.client_subject
        if not subj:
            return jsonify(status='error', reason='unauthorized',
                           detail='no mTLS client cert'), 401
        body = request.get_json(silent=True) or {}
        status, payload = authorize.handle_authorize(
            app.config['AUTH_CTX'], subj, body)
        return jsonify(payload), status

    # ---- Admin: helpers ----
    def _admin_or_401():
        subj = g.client_subject
        if not subj:
            return None, (jsonify(status='error', reason='unauthorized',
                                  detail='no mTLS client cert'), 401)
        enrollment: Enrollment = app.config['ENROLLMENT']
        adm = enrollment.find_admin_by_mtls_subject(subj)
        if adm is None:
            return None, (jsonify(status='error', reason='unauthorized',
                                  detail=f'admin cert {subj!r} not enrolled'),
                          401)
        return adm, None

    # ---- Servers ----
    @app.post('/v1/admin/server/add')
    def _server_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/server/<name>')
    def _server_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.put('/v1/admin/server/<name>/groups')
    def _server_groups(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_set_groups(
            app.config['ADMIN_CTX'], adm, name,
            request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.get('/v1/admin/server/list')
    def _server_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_list(
            app.config['ADMIN_CTX'], adm,
            group=request.args.get('group'),
            name_prefix=request.args.get('name'))
        return jsonify(payload), status

    # ---- Users ----
    @app.post('/v1/admin/user/add')
    def _user_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/user/<username>')
    def _user_remove(username):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_remove(
            app.config['ADMIN_CTX'], adm, username)
        return jsonify(payload), status

    @app.post('/v1/admin/user/<username>/key')
    def _user_key_add(username):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_key_add(
            app.config['ADMIN_CTX'], adm, username,
            request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/user/<username>/key/<path:fingerprint>')
    def _user_key_remove(username, fingerprint):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_key_remove(
            app.config['ADMIN_CTX'], adm, username, fingerprint)
        return jsonify(payload), status

    @app.get('/v1/admin/user/list')
    def _user_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_list(
            app.config['ADMIN_CTX'], adm,
            username=request.args.get('username'),
            fingerprint=request.args.get('fingerprint'))
        return jsonify(payload), status

    # ---- Policy ----
    @app.post('/v1/admin/policy/add')
    def _policy_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.policy_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/policy/<policy_id>')
    def _policy_remove(policy_id):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.policy_remove(
            app.config['ADMIN_CTX'], adm, policy_id)
        return jsonify(payload), status

    # ---- Admins ----
    @app.post('/v1/admin/admin/add')
    def _admin_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/admin/<name>')
    def _admin_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.get('/v1/admin/admin/list')
    def _admin_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    # ---- Audit ----
    @app.get('/v1/admin/audit')
    def _audit():
        adm, err = _admin_or_401()
        if err:
            return err
        filters = {
            'type': request.args.get('type') or 'all',
            'since': request.args.get('since'),
            'until': request.args.get('until'),
            'username': request.args.get('username'),
            'server': request.args.get('server'),
            'decision': request.args.get('decision'),
            'admin': request.args.get('admin'),
            'limit': request.args.get('limit'),
            'offset': request.args.get('offset'),
        }
        status, payload = admin_handlers.audit_read(
            app.config['ADMIN_CTX'], adm, filters)
        return jsonify(payload), status

    # ---- Templates ----
    @app.post('/v1/admin/template/set')
    def _template_set():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.template_set(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.post('/v1/admin/template/unset')
    def _template_unset():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.template_unset(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.get('/v1/admin/template/list')
    def _template_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.template_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    @app.get('/v1/admin/template/effective/<server_name>')
    def _template_effective(server_name):
        adm, err = _admin_or_401()
        if err:
            return err
        kind = request.args.get('kind') or 'openssh'
        status, payload = admin_handlers.template_effective(
            app.config['ADMIN_CTX'], adm, server_name, kind)
        return jsonify(payload), status

    # ---- CA-bypass cert mint ----
    @app.post('/v1/admin/bypass-cert/mint')
    def _bypass_cert_mint():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.bypass_cert_mint(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    # ---- §5 cert minting (TLS server / HTTPS user / code-signing) ----
    @app.post('/v1/admin/cert/mint')
    def _cert_mint():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.cert_mint(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    # §15.19 external-use cert mint — CSR-based, signed by an
    # operator-named external intermediate (must have been minted with
    # `--profile <name>` per §15.20).
    @app.post('/v1/admin/cert/external-use')
    def _cert_external_use_mint():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.external_use_cert_mint(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.post('/v1/admin/openvpn/issue')
    def _openvpn_issue():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.openvpn_issue(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    # ---- Admin-2FA passkey flow (design/admin-2fa.md) ----
    @app.post('/v1/admin/passkey/enroll-begin')
    def _passkey_admin_enroll():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.passkey_admin_enroll(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.get('/v1/admin/passkey/<admin_name>/list')
    def _passkey_admin_list(admin_name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.passkey_admin_list(
            app.config['ADMIN_CTX'], adm, admin_name)
        return jsonify(payload), status

    @app.delete('/v1/admin/passkey/<admin_name>/<path:credential_id>')
    def _passkey_admin_revoke(admin_name, credential_id):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.passkey_admin_revoke(
            app.config['ADMIN_CTX'], adm, admin_name, credential_id)
        return jsonify(payload), status

    # Broker callback. mTLS-validated upstream (the broker presents
    # its own client cert). For dev mode the in-process TLS handler
    # populates X-Client-CN; production uses Apache2.
    @app.post('/v1/admin/passkey/callback')
    def _passkey_callback():
        # The broker's CN must be in a small allowlist — same shape
        # as the other admin endpoints check, but we expect the
        # broker, not an enrolled admin. v1 trusts any incoming
        # request that passes mTLS chain validation; the Hardening
        # v2 work tightens this to a pinned-CN check.
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.passkey_admin_callback(
            app.config['ADMIN_CTX'], body)
        return jsonify(payload), status

    @app.get('/v1/admin/passkey/ceremony/<ceremony_id>')
    def _passkey_poll(ceremony_id):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.passkey_poll_outcome(
            app.config['ADMIN_CTX'], ceremony_id)
        return jsonify(payload), status

    # ---- external-tool CRUD (admin-mTLS) ----
    @app.post('/v1/admin/external-tool/add')
    def _external_tool_add():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.external_tool_add(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.delete('/v1/admin/external-tool/<name>')
    def _external_tool_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.external_tool_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.get('/v1/admin/external-tool/list')
    def _external_tool_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.external_tool_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    # ---- external-tool passkey endpoints (tool-mTLS) ----
    # These authenticate the calling TOOL's mTLS subject, not an
    # admin role. The Flask layer pulls subject from g.client_subject
    # the same way admin endpoints do.
    @app.post('/v1/external/passkey/enroll-begin')
    def _ext_enroll_begin():
        subj = g.client_subject
        if not subj:
            return jsonify({'status': 'error', 'reason': 'unauthorized',
                            'detail': 'no mTLS client cert'}), 401
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.external_tool_passkey_enroll_begin(
            app.config['ADMIN_CTX'], subj, body)
        return jsonify(payload), status

    @app.post('/v1/external/passkey/challenge')
    def _ext_challenge():
        subj = g.client_subject
        if not subj:
            return jsonify({'status': 'error', 'reason': 'unauthorized',
                            'detail': 'no mTLS client cert'}), 401
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.external_tool_passkey_challenge(
            app.config['ADMIN_CTX'], subj, body)
        return jsonify(payload), status

    @app.get('/v1/external/passkey/ceremony/<ceremony_id>')
    def _ext_status(ceremony_id):
        subj = g.client_subject
        if not subj:
            return jsonify({'status': 'error', 'reason': 'unauthorized',
                            'detail': 'no mTLS client cert'}), 401
        status, payload = admin_handlers.external_tool_passkey_status(
            app.config['ADMIN_CTX'], subj, ceremony_id)
        return jsonify(payload), status

    @app.delete('/v1/external/passkey/credential/<user_id>/<path:credential_id>')
    def _ext_revoke(user_id, credential_id):
        subj = g.client_subject
        if not subj:
            return jsonify({'status': 'error', 'reason': 'unauthorized',
                            'detail': 'no mTLS client cert'}), 401
        status, payload = admin_handlers.external_tool_passkey_revoke(
            app.config['ADMIN_CTX'], subj, user_id, credential_id)
        return jsonify(payload), status

    # R-4: ceremony cancel route per §14.1.3 + §13.6.
    @app.delete('/v1/external/passkey/ceremony/<ceremony_id>')
    def _ext_cancel(ceremony_id):
        subj = g.client_subject
        if not subj:
            return jsonify({'status': 'error', 'reason': 'unauthorized',
                            'detail': 'no mTLS client cert'}), 401
        status, payload = admin_handlers.external_tool_passkey_cancel(
            app.config['ADMIN_CTX'], subj, ceremony_id)
        return jsonify(payload), status

    # ---- §5 WireGuard catalog ----
    @app.post('/v1/admin/wireguard/server')
    def _wg_server_init():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.wireguard_server_init(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.delete('/v1/admin/wireguard/server/<name>')
    def _wg_server_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.wireguard_server_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.get('/v1/admin/wireguard/server/<name>')
    def _wg_server_show(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.wireguard_server_show(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.get('/v1/admin/wireguard/server')
    def _wg_server_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.wireguard_server_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    @app.post('/v1/admin/wireguard/peer')
    def _wg_peer_issue():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.wireguard_peer_issue(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.delete('/v1/admin/wireguard/peer/<server>/<name>')
    def _wg_peer_revoke(server, name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.wireguard_peer_revoke(
            app.config['ADMIN_CTX'], adm, server, name)
        return jsonify(payload), status

    @app.get('/v1/admin/wireguard/peer')
    def _wg_peer_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.wireguard_peer_list(
            app.config['ADMIN_CTX'], adm,
            request.args.get('server'))
        return jsonify(payload), status

    # ---- CRL ----
    # cert.revoke appends to the CRL; msshds pick up on next authorize.
    @app.post('/v1/admin/cert/revoke')
    def _cert_revoke():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.cert_revoke(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    # /v1/admin/intermediate/* — PKI hierarchy management (v0.2.4+).
    # See design/notes-pki-hierarchy.md Commit 5.
    @app.get('/v1/admin/intermediate/list')
    def _intermediate_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.intermediate_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    @app.post('/v1/admin/intermediate/rotate')
    def _intermediate_rotate():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.intermediate_rotate(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    # External Intermediate CA tier (v0.2.5+ — Commit 5b of PKI hierarchy).
    # Delegates signing to a third party; the resulting cert chains
    # to root but is intentionally NOT trusted by any mssh validator.
    @app.post('/v1/admin/intermediate/mint-external')
    def _intermediate_mint_external():
        adm, err = _admin_or_401()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.external_intermediate_mint(
            app.config['ADMIN_CTX'], adm, body)
        return jsonify(payload), status

    @app.get('/v1/admin/intermediate/list-external')
    def _intermediate_list_external():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.external_intermediate_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    # /v1/admin/crl is the operator/auditor view (RBAC: any admin role
    # except no role at all).
    @app.get('/v1/admin/crl')
    def _crl_admin_list():
        adm, err = _admin_or_401()
        if err:
            return err
        try:
            after = int(request.args.get('after') or 0)
        except ValueError:
            return jsonify({'status': 'error', 'reason': 'bad_request',
                            'detail': 'after must be an integer'}), 400
        limit_arg = request.args.get('limit')
        try:
            limit = int(limit_arg) if limit_arg is not None else None
        except ValueError:
            return jsonify({'status': 'error', 'reason': 'bad_request',
                            'detail': 'limit must be an integer'}), 400
        issuer = request.args.get('issuer') or 'user-mint'
        status, payload = admin_handlers.crl_fetch(
            app.config['ADMIN_CTX'], adm, after, limit, issuer=issuer)
        return jsonify(payload), status

    # /v1/cert/renew — auth-by-cert-being-renewed (NOT admin role).
    # The presented mTLS client cert IS the credential. CA validates
    # it chains to its own TLS hierarchy, isn't revoked, is in the
    # renewable window, and mints a fresh leaf with the same identity.
    # Design: §4.3.10 (CA endpoint) + §13.4 (auto-renewal cross-cutting).
    @app.post('/v1/cert/renew')
    def _cert_renew():
        body = request.get_json(silent=True) or {}
        status, payload = admin_handlers.cert_renew(
            app.config['ADMIN_CTX'], g.client_cert, body)
        # 304 has special HTTP semantics — Flask wants no body. We
        # still return a body so the CLI sees the not_modified
        # detail. Use 200 + status='too_early' instead.
        if status == 304:
            return jsonify(payload), 200
        return jsonify(payload), status

    # /v1/crl.pem is the X.509 CRL that consumers like OpenVPN's
    # --crl-verify and browsers fetch. Built on the fly from the
    # JSON CRL log of one issuer (default user-mint). Signed by the
    # TLS CA so anyone trusting tls-ca-cert.pem can verify the
    # signature. Public read — revocation info is not sensitive.
    @app.get('/v1/crl.pem')
    def _crl_x509_pem():
        from . import crl as crl_module
        ctx = app.config['ADMIN_CTX']
        if ctx.crl is None:
            return ('', 503)
        issuer = request.args.get('issuer') or 'user-mint'
        pem = crl_module.build_x509_crl(
            ctx.crl.for_issuer(issuer),
            signing_key=ctx.tls_ca_key,
            signing_cert=ctx.tls_ca_cert,
        )
        return (pem, 200, {'Content-Type': 'application/x-pem-file'})

    # /v1/crl is the msshd hot-path fetch. Authenticated by the same
    # mTLS chain as /v1/authorize (msshd presents its mTLS cert
    # — no admin role gate). Pure read; never mutates state.
    # ?issuer=<short_name> selects which intermediate's CRL feed.
    # Default = user-mint (matches v0.2.0 single-signer behavior).
    @app.get('/v1/crl')
    def _crl_msshd_fetch():
        try:
            after = int(request.args.get('after') or 0)
        except ValueError:
            return jsonify({'status': 'error', 'reason': 'bad_request',
                            'detail': 'after must be an integer'}), 400
        limit_arg = request.args.get('limit')
        try:
            limit = int(limit_arg) if limit_arg is not None else None
        except ValueError:
            return jsonify({'status': 'error', 'reason': 'bad_request',
                            'detail': 'limit must be an integer'}), 400
        issuer = request.args.get('issuer') or 'user-mint'
        auth_ctx = app.config['AUTH_CTX']
        if auth_ctx.crl is None:
            return jsonify({'status': 'ok', 'issuer': issuer,
                            'current_seq': 0, 'current_seqs': {},
                            'entries': []}), 200
        entries = auth_ctx.crl.fetch_after(issuer, after, limit=limit)
        return jsonify({
            'status': 'ok',
            'issuer': issuer,
            'current_seq': auth_ctx.crl.for_issuer(issuer).current_seq(),
            'current_seqs': auth_ctx.crl.current_seqs(),
            'entries': [e.to_dict() for e in entries],
        }), 200


# ---------------------------------------------------------------------------
# Werkzeug request handler that surfaces the mTLS peer cert via environ.
# ---------------------------------------------------------------------------

def _make_request_handler():
    """Return a WSGIRequestHandler subclass that exposes the peer cert.

    Werkzeug's default handler hides the SSL peer cert. We override
    ``make_environ`` to add ``peercert_der`` when present.
    """
    from werkzeug.serving import WSGIRequestHandler

    class _SSLRequestHandler(WSGIRequestHandler):
        def make_environ(self):
            env = super().make_environ()
            try:
                der = self.connection.getpeercert(binary_form=True)
                if der:
                    env['peercert_der'] = der
            except Exception:
                pass
            return env

    return _SSLRequestHandler


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    # §4.3.13 CLI entry; mTLS listener wiring per §14.3.2 config schema
    p = argparse.ArgumentParser(prog='mssh-ca')
    p.add_argument('--config', required=True, help='Path to CA config file')
    p.add_argument('--debug', action='store_true')
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    cfg = CAConfig.load(args.config)
    # R-9 §13.9.7: refuse to start when a security-critical field is
    # missing or points at a path that doesn't exist.
    cfg.validate()
    app = create_app(cfg)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cfg.tls_cert, keyfile=cfg.tls_key)
    ctx.load_verify_locations(cafile=cfg.client_ca_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED

    log.info('CA listening on https://%s:%d', cfg.listen_host, cfg.listen_port)

    # Use Werkzeug's run_simple with our custom request handler so the peer
    # cert reaches the WSGI environ.
    from werkzeug.serving import run_simple
    run_simple(
        hostname=cfg.listen_host, port=cfg.listen_port, application=app,
        ssl_context=ctx, threaded=True, use_reloader=False,
        request_handler=_make_request_handler(),
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
