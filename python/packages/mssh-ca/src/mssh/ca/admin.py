"""Admin API handlers.

Design: §4.3.6 (see design/mssh_design_v1.md) — the /v1/admin/*
surface. The role-permission table here implements the §14.1.2 RBAC
matrix; each action key maps directly to a row in that table.

Role-permission table mirrors mssh-detailed-rest-api.md. Each handler
takes a parsed request body, the admin's enrollment record, and the
``AdminContext``; returns ``(http_status, json_body)``.
"""
from __future__ import annotations

import base64
import datetime as _dt
import logging
from dataclasses import dataclass
from typing import Any, Callable

from cryptography import x509
from cryptography.x509 import oid

from . import cert_minter
from . import templates as _templates
from .audit import AuditLog
from .enrollment import (Admin, Enrollment, EnrollmentError, KeyBinding,
                          Policy)
from ..identity import (CertIdentity, IdentityParseError, PubkeyIdentity,
                              parse_identity)
from .render import TemplateError, validate_template

log = logging.getLogger('mssh.ca.admin')


# Role permissions: maps action key -> set of allowed roles.
# §14.1.2 RBAC matrix — single source of truth for admin authz
_PERMISSIONS = {
    'server.add':       {'superuser', 'server-admin'},
    'server.remove':    {'superuser', 'server-admin'},
    'server.groups':    {'superuser', 'server-admin'},
    'server.list':      {'superuser', 'server-admin', 'user-admin', 'auditor'},
    'user.add':         {'superuser', 'user-admin'},
    'user.remove':      {'superuser', 'user-admin'},
    'user.key.add':     {'superuser', 'user-admin'},
    'user.key.remove':  {'superuser', 'user-admin'},
    'policy.add':       {'superuser', 'user-admin'},
    'policy.remove':    {'superuser', 'user-admin'},
    'user.list':        {'superuser', 'server-admin', 'user-admin', 'auditor'},
    'admin.add':        {'superuser'},
    'admin.remove':     {'superuser'},
    'admin.list':       {'superuser', 'auditor'},
    'audit.read':       {'superuser', 'server-admin', 'user-admin', 'auditor'},
    # Templates: writes are server-admin scope (or superuser); reads are
    # available to user-admin + auditor too (they need to verify policy
    # ↔ template alignment).
    'template.set':     {'superuser', 'server-admin'},
    'template.unset':   {'superuser', 'server-admin'},
    'template.list':    {'superuser', 'server-admin', 'user-admin', 'auditor'},
    'template.show':    {'superuser', 'server-admin', 'user-admin', 'auditor'},
    # CA-bypass cert minting. Sensitive: a bypass cert lets the
    # holder inject directly into msshd's authz cache, sidestepping
    # the live CA. Restrict to superuser only.
    'bypass_cert.mint': {'superuser'},
    # Cert revocation: appends to the CRL, which all msshds pick up
    # on their next authorize call. Sensitive — superuser only.
    'cert.revoke':      {'superuser'},
    'crl.read':         {'superuser', 'server-admin', 'user-admin', 'auditor'},
    # §5 cert minting for other applications. Generic TLS server certs,
    # HTTPS user (browser mTLS) client certs, code-signing certs, and
    # OpenVPN client bundles all share the TLS CA hierarchy. Restrict
    # to superuser since these are operator-distributed credentials
    # outside the SSH path.
    'cert.mint':        {'superuser'},
    # §15.19 external-use cert mint (CSR-based, chains to operator's
    # external intermediate). Restricted to superuser because external
    # leaves carry operator identifiers; minting one wrong is hard
    # to undo (device-burned IDevID certs especially).
    'cert.external_use.mint': {'superuser'},
    'openvpn.issue':    {'superuser'},
    # WireGuard catalog management. Same sensitivity as openvpn —
    # the CA owns the server private key and mints per-peer
    # credentials.
    'wireguard.server.init':   {'superuser'},
    'wireguard.server.remove': {'superuser'},
    'wireguard.server.show':   {'superuser', 'auditor'},
    'wireguard.server.list':   {'superuser', 'auditor'},
    'wireguard.peer.issue':    {'superuser'},
    'wireguard.peer.revoke':   {'superuser'},
    'wireguard.peer.list':     {'superuser', 'auditor'},
}


def role_permits(role: str, action: str) -> bool:
    # §14.1.2 RBAC check; unknown action → default-deny per §13.9.7
    return role in _PERMISSIONS.get(action, set())


@dataclass
class AdminContext:
    enrollment: Enrollment
    audit: AuditLog
    tls_ca_key: Any
    tls_ca_cert: Any
    server_cert_validity_days: int
    admin_cert_validity_days: int
    mtls_key_type: str
    # Authorization signing key + cert, used for minting CA-bypass
    # authz certs from the admin endpoint (a normal authz cert with
    # the OID_CA_BYPASS critical marker; presented offline by the
    # operator and injected into msshd's authz cache).
    signing_key: Any = None
    signing_cert: Any = None
    # CRL log. Sequence-based revocation channel; msshd fleet picks
    # up entries on its next authorize call. See ca/crl.py +
    # archive/design/notes-bypass-cache.md "CRL Amendment".
    crl: Any = None             # CRLStore
    # CRL Distribution Point URL stamped into each issued leaf via
    # the X.509 CRLDistributionPoints extension. None disables the
    # extension. Consumers (OpenVPN, browsers) fetch the signed
    # X.509 CRL from this URL when checking revocation. Typically
    # served by the same CA at GET /v1/crl.pem.
    crl_url: str | None = None
    # WireGuard registry — server + peer records, server keypairs,
    # IP allocation. Lazily loaded by WireGuard endpoints; None means
    # no WireGuard configured for this CA. See ca/wireguard.py.
    wireguard: Any = None       # WireGuardStore

    # mssh-passkey broker integration. When all the passkey_*
    # fields are set, the passkey endpoints are live. Unset →
    # the passkey endpoints respond 503.
    passkey_broker: Any = None        # PasskeyBrokerClient
    passkey_rp_id: str = ''
    passkey_rp_name: str = ''
    passkey_expected_origin: str = ''
    passkey_callback_url: str = ''
    passkey_aaguid_allowlist: Any = None   # AAGUIDAllowlist
    # In-flight ceremony state keyed by ceremony_id. Holds the
    # webauthn challenge bytes + the per-flow context (admin name
    # or external-tool/user) until the broker callback arrives.
    # Two parallel maps: registration challenges + auth challenges.
    passkey_pending_registrations: Any = None   # dict[ceremony_id -> dict]
    passkey_pending_authentications: Any = None # dict[ceremony_id -> dict]
    # Per-admin 2FA cache: admin_name -> last_verified_at_iso
    passkey_2fa_cache: Any = None     # dict[str, str]

    # Admin-2FA gating: set of action names (e.g. 'cert.revoke',
    # 'admin.add') that require a fresh passkey ceremony — gates
    # configured by the operator in ca-config.yaml. Empty set = no
    # gating (default). See design/admin-2fa.md.
    admin_2fa_protected_actions: frozenset[str] = frozenset()
    admin_2fa_within_seconds: int = 300

    # Path to the CA's on-disk PKI layout (root + intermediates +
    # legacy aliases). Set in v0.2.1+ deployments; unset means
    # legacy single-signer mode. Used by intermediate.list/rotate.
    ca_dir: str = ''

    # §15.23 per-kind validity policy from ca-config.yaml. When unset
    # (default), `_validity_or_default()` falls back to the built-in
    # v0.4.x baseline dicts in config.py — preserving v0.4.x behavior
    # byte-identical for configs that lack a `cert_kinds:` section.
    cert_kinds: Any = None        # CertKindsPolicy | None

    # §15.21 operator-allowlisted custom OIDs. None = default-deny —
    # any mint request that supplies custom_oids is rejected.
    custom_oids: Any = None       # CustomOIDAllowlist | None


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _audit_admin(ctx: AdminContext, admin: Admin, action: str,
                 target: dict, result: str) -> None:
    ctx.audit.write({
        'timestamp': _now_iso(),
        'type': 'admin',
        'action': action,
        'admin': {'name': admin.name, 'role': admin.role,
                  'mtls_subject': admin.mtls_subject},
        'target': target,
        'result': result,
    })


def _forbidden(action: str, admin: Admin) -> tuple[int, dict]:
    return 403, {
        'status': 'error', 'reason': 'forbidden',
        'detail': f"admin role {admin.role!r} cannot perform {action!r}",
    }


def _check(action: str, admin: Admin,
           origin: str | None = None) -> tuple[int, dict] | None:
    # §12.4.3 CA-side defense in depth: when origin='mcp', enforce
    # the MCP capability allow-list regardless of the admin's role.
    # MCP is OFF by default (§12.2); even when on, mutating/admin
    # actions like bypass-cert mint, admin.add, cert.revoke etc.
    # remain refused by the CA even if the MCP-side allow-list is
    # tampered with. Audit tag: §12.4.2 (origin: mcp in audit records).
    if origin is None:
        # Inside a Flask request context, pull from g.client_origin
        # (set by server.py's _attach_caller before-request hook).
        # Outside a request context (tests, internal callers),
        # default to '' (no origin restriction).
        try:
            from flask import g
            origin = getattr(g, 'client_origin', '') or ''
        except (ImportError, RuntimeError):
            origin = ''
    if origin == 'mcp' and action not in MCP_ALLOWED_ACTIONS:
        return 403, {
            'status': 'error',
            'result': 'denied',
            'reason': 'mcp_capability_denied',
            'denied_reason': 'mcp_capability_denied',
            'detail': (f'action {action!r} is not in the MCP allow-list; '
                       f'CA refuses mcp-origin calls for it (§12.4.3)'),
        }
    if not role_permits(admin.role, action):
        return _forbidden(action, admin)
    return None


# §12.4.3 CA-side capability allow-list. MCP-origin calls are refused
# for any action NOT in this set, even if the admin's role would allow
# it. The MCP-side TOOL_REGISTRY (mssh-admin/mcp/tools.py) is the
# primary gate; this is defense in depth. Strict subset of mssh-admin;
# all bypass/mutating/destructive actions are excluded per §12.2.
MCP_ALLOWED_ACTIONS = frozenset({
    'server.list',
    'user.list',
    'admin.list',
    'audit.read',
    'crl.read',
    'intermediate.list',
    'intermediate.external.list',
    'external_tool.list',
    'policy.read',                  # forward-compat; not currently a separate action
    'template.list',
    'template.show',
})


def _err(status: int, reason: str, detail: str) -> tuple[int, dict]:
    return status, {'status': 'error', 'reason': reason, 'detail': detail}


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

def server_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('server.add', admin)):
        return err
    name = body.get('name')
    if not isinstance(name, str) or not name:
        return _err(400, 'bad_request', 'missing/invalid name')
    groups = body.get('groups') or []
    mtls_subject = f'CN={name}'
    try:
        cert_bundle = cert_minter.issue_client_cert(
            common_name=name, tls_ca_key=ctx.tls_ca_key,
            tls_ca_cert=ctx.tls_ca_cert,
            validity_days=ctx.server_cert_validity_days,
            key_type=ctx.mtls_key_type,
            kind='client-mtls',
        )
        srv = ctx.enrollment.add_server(name, mtls_subject, groups,
                                        enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'server.add',
                 {'server_name': srv.name, 'groups': list(srv.groups)}, 'ok')
    return 201, {
        'status': 'ok',
        'server': {
            'name': srv.name, 'groups': list(srv.groups),
            'mtls_subject': srv.mtls_subject,
        },
        'credentials': {
            'cert_pem': cert_bundle.cert_pem.decode('ascii'),
            'key_pem': cert_bundle.key_pem.decode('ascii'),
            'ca_cert_pem': cert_bundle.ca_cert_pem.decode('ascii'),
        },
    }


def server_remove(ctx: AdminContext, admin: Admin, name: str) -> tuple[int, dict]:
    if (err := _check('server.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_server(name)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'server.remove', {'server_name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def server_set_groups(ctx: AdminContext, admin: Admin, name: str,
                      body: dict) -> tuple[int, dict]:
    if (err := _check('server.groups', admin)):
        return err
    groups = body.get('groups')
    if not isinstance(groups, list):
        return _err(400, 'bad_request', 'groups must be a list')
    try:
        srv = ctx.enrollment.set_server_groups(name, groups)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'server.groups',
                 {'server_name': name, 'groups': list(srv.groups)}, 'ok')
    return 200, {
        'status': 'ok',
        'server': {'name': srv.name, 'groups': list(srv.groups)},
    }


def server_list(ctx: AdminContext, admin: Admin,
                group: str | None = None, name_prefix: str | None = None
                ) -> tuple[int, dict]:
    if (err := _check('server.list', admin)):
        return err
    items = []
    for s in ctx.enrollment.all_servers():
        if group and group not in s.groups:
            continue
        if name_prefix and not s.name.startswith(name_prefix):
            continue
        items.append({
            'name': s.name, 'groups': list(s.groups),
            'mtls_subject': s.mtls_subject, 'enrolled_at': s.enrolled_at,
        })
    return 200, {'status': 'ok', 'servers': items}


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def user_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('user.add', admin)):
        return err
    username = body.get('username')
    if not isinstance(username, str) or not username:
        return _err(400, 'bad_request', 'missing/invalid username')
    try:
        u = ctx.enrollment.add_user(username, enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'user.add', {'username': username}, 'ok')
    return 201, {
        'status': 'ok',
        'user': {'username': u.username, 'keys': [], 'policies': []},
    }


def user_remove(ctx: AdminContext, admin: Admin, username: str) -> tuple[int, dict]:
    if (err := _check('user.remove', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'user.remove')):
        return err
    try:
        ctx.enrollment.remove_user(username)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.remove', {'username': username}, 'ok')
    return 200, {'status': 'ok', 'removed': username}


def user_key_add(ctx: AdminContext, admin: Admin, username: str,
                 body: dict) -> tuple[int, dict]:
    if (err := _check('user.key.add', admin)):
        return err
    type_ = body.get('type')
    data_b64 = body.get('data')
    if type_ not in ('pubkey', 'openssh-cert'):
        return _err(400, 'bad_request', 'type must be pubkey or openssh-cert')
    if not isinstance(data_b64, str):
        return _err(400, 'bad_request', 'data must be base64 string')
    try:
        blob = base64.b64decode(data_b64, validate=True)
    except Exception as e:
        return _err(400, 'bad_request', f'invalid base64: {e}')
    try:
        parsed = parse_identity(type_, blob)
    except IdentityParseError as e:
        return _err(400, 'bad_request', f'cannot parse key: {e}')

    if isinstance(parsed, CertIdentity):
        kb = KeyBinding(
            fingerprint=parsed.fingerprint, type='openssh-cert',
            key_type=parsed.key_type, key_id=parsed.key_id,
            principals=list(parsed.principals),
        )
        extra = {
            'key_id': parsed.key_id,
            'principals': list(parsed.principals),
            'signing_ca_fingerprint': parsed.signature_key_fingerprint,
        }
    elif isinstance(parsed, PubkeyIdentity):
        kb = KeyBinding(
            fingerprint=parsed.fingerprint, type='pubkey',
            key_type=parsed.key_type,
        )
        extra = {}
    else:
        return _err(500, 'internal', 'unexpected parsed type')

    try:
        ctx.enrollment.add_user_key(username, kb, added_by=admin.name)
    except EnrollmentError as e:
        if 'already bound' in str(e):
            return _err(409, 'conflict', str(e))
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.key.add',
                 {'username': username, 'fingerprint': kb.fingerprint}, 'ok')
    return 201, {
        'status': 'ok',
        'key': {
            'type': kb.type, 'fingerprint': kb.fingerprint,
            'key_type': kb.key_type, **extra,
        },
    }


def user_key_remove(ctx: AdminContext, admin: Admin, username: str,
                    fingerprint: str) -> tuple[int, dict]:
    if (err := _check('user.key.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_user_key(username, fingerprint)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.key.remove',
                 {'username': username, 'fingerprint': fingerprint}, 'ok')
    return 200, {'status': 'ok', 'removed_fingerprint': fingerprint}


def user_list(ctx: AdminContext, admin: Admin,
              username: str | None = None,
              fingerprint: str | None = None) -> tuple[int, dict]:
    if (err := _check('user.list', admin)):
        return err
    out = []
    for u in ctx.enrollment.all_users():
        if username and u.username != username:
            continue
        if fingerprint and not any(k.fingerprint == fingerprint for k in u.keys):
            continue
        out.append({
            'username': u.username,
            'keys': [
                {'type': k.type, 'fingerprint': k.fingerprint, 'key_type': k.key_type,
                 'key_id': k.key_id, 'principals': list(k.principals)}
                for k in u.keys
            ],
            'policies': [
                {
                    'id': p.id, 'servers': list(p.servers),
                    'server_groups': list(p.server_groups),
                    'channels': list(p.channels),
                    'source_cidrs': list(p.source_cidrs),
                    'time_window': p.time_window,
                    'max_cert_validity_seconds': p.max_cert_validity_seconds,
                    'environment': dict(p.environment),
                    'force_command': p.force_command,
                }
                for p in u.policies
            ],
            'enrolled_at': u.enrolled_at,
        })
    return 200, {'status': 'ok', 'users': out}


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def policy_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('policy.add', admin)):
        return err
    username = body.get('username')
    policy = body.get('policy')
    if not isinstance(username, str) or not isinstance(policy, dict):
        return _err(400, 'bad_request', 'username and policy required')
    if not policy.get('channels'):
        return _err(400, 'bad_request', 'policy.channels required')
    try:
        p = ctx.enrollment.add_policy(username, policy, created_by=admin.name)
    except EnrollmentError as e:
        if 'user not found' in str(e):
            return _err(404, 'not_found', str(e))
        return _err(400, 'bad_request', str(e))
    _audit_admin(ctx, admin, 'policy.add',
                 {'username': username, 'policy_id': p.id}, 'ok')
    return 201, {'status': 'ok', 'policy_id': p.id, 'username': username}


def policy_remove(ctx: AdminContext, admin: Admin, policy_id: str) -> tuple[int, dict]:
    if (err := _check('policy.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_policy(policy_id)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'policy.remove', {'policy_id': policy_id}, 'ok')
    return 200, {'status': 'ok', 'removed_policy': policy_id}


# ---------------------------------------------------------------------------
# Admins
# ---------------------------------------------------------------------------

def admin_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('admin.add', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'admin.add')):
        return err
    name = body.get('name')
    role = body.get('role')
    if not isinstance(name, str) or not name:
        return _err(400, 'bad_request', 'missing/invalid name')
    if role not in {'superuser', 'server-admin', 'user-admin', 'auditor'}:
        return _err(400, 'bad_request', f'invalid role: {role!r}')
    mtls_subject = f'CN={name}'
    try:
        cert_bundle = cert_minter.issue_client_cert(
            common_name=name, tls_ca_key=ctx.tls_ca_key,
            tls_ca_cert=ctx.tls_ca_cert,
            validity_days=ctx.admin_cert_validity_days,
            key_type=ctx.mtls_key_type,
            kind='admin-mtls',
        )
        new_admin = ctx.enrollment.add_admin(
            name, role, mtls_subject, enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'admin.add', {'name': name, 'role': role}, 'ok')
    return 201, {
        'status': 'ok',
        'admin': {'name': new_admin.name, 'role': new_admin.role,
                  'mtls_subject': new_admin.mtls_subject},
        'credentials': {
            'cert_pem': cert_bundle.cert_pem.decode('ascii'),
            'key_pem': cert_bundle.key_pem.decode('ascii'),
            'ca_cert_pem': cert_bundle.ca_cert_pem.decode('ascii'),
        },
    }


def admin_remove(ctx: AdminContext, admin: Admin, name: str) -> tuple[int, dict]:
    if (err := _check('admin.remove', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'admin.remove')):
        return err
    try:
        ctx.enrollment.remove_admin(name)
    except EnrollmentError as e:
        if 'last superuser' in str(e):
            return _err(409, 'conflict', str(e))
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'admin.remove', {'name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def admin_list(ctx: AdminContext, admin: Admin) -> tuple[int, dict]:
    if (err := _check('admin.list', admin)):
        return err
    out = [
        {'name': a.name, 'role': a.role, 'mtls_subject': a.mtls_subject,
         'enrolled_at': a.enrolled_at}
        for a in ctx.enrollment.all_admins()
    ]
    return 200, {'status': 'ok', 'admins': out}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit_read(ctx: AdminContext, admin: Admin,
               filters: dict) -> tuple[int, dict]:
    if (err := _check('audit.read', admin)):
        return err
    entries = ctx.audit.read_all()

    def keep(e: dict) -> bool:
        t = filters.get('type', 'all')
        if t != 'all' and e.get('type') != t:
            return False
        since = filters.get('since')
        until = filters.get('until')
        if since and e.get('timestamp', '') < since:
            return False
        if until and e.get('timestamp', '') > until:
            return False
        if filters.get('username'):
            ident = e.get('identity') or {}
            if ident.get('username') != filters['username']:
                return False
        if filters.get('server'):
            srv = e.get('server') or {}
            if srv.get('canonical_name') != filters['server']:
                return False
        if filters.get('decision'):
            if e.get('decision') != filters['decision']:
                return False
        if filters.get('admin'):
            a = e.get('admin') or {}
            if a.get('name') != filters['admin']:
                return False
        return True

    filtered = [e for e in entries if keep(e)]
    limit = int(filters.get('limit') or 100)
    offset = int(filters.get('offset') or 0)
    return 200, {
        'status': 'ok',
        'total': len(filtered),
        'entries': filtered[offset:offset + limit],
    }


# ---------------------------------------------------------------------------
# Templates (Phase 1d of per-connection inner sshd)
# ---------------------------------------------------------------------------

_VALID_TEMPLATE_SCOPES = ('default', 'group', 'server')


def _parse_template_scope(body: dict) -> tuple[str, str | None, str] | tuple[int, dict]:
    """Pull scope / scope_name / kind out of a request body. Returns either
    a 3-tuple (scope, scope_name, kind) or an error response tuple."""
    scope = body.get('scope')
    if scope not in _VALID_TEMPLATE_SCOPES:
        return _err(400, 'bad_request',
                    f'scope must be one of {_VALID_TEMPLATE_SCOPES}')
    kind = body.get('kind') or 'openssh'
    scope_name = body.get('scope_name')
    if scope in ('group', 'server'):
        if not scope_name:
            return _err(400, 'bad_request',
                        f'scope={scope!r} requires scope_name')
    else:
        scope_name = None
    return scope, scope_name, kind


def template_set(ctx: AdminContext, admin: Admin,
                 body: dict) -> tuple[int, dict]:
    """Set or replace a template at the given scope.

    Body: {scope, scope_name?, kind, content}.
    Validates the template against the v1 marker schema before saving;
    refuses if any markers are unknown so operators don't write configs
    that will fail to render at session time.
    """
    if (err := _check('template.set', admin)):
        return err
    parsed = _parse_template_scope(body)
    if isinstance(parsed, tuple) and len(parsed) == 2:
        return parsed                                       # type: ignore[return-value]
    scope, scope_name, kind = parsed                        # type: ignore[misc]
    content = body.get('content')
    if not isinstance(content, str):
        return _err(400, 'bad_request', 'content must be a string')

    issues = validate_template(content)
    if issues:
        return _err(400, 'invalid_template',
                    f'template has unknown markers or syntax errors: '
                    + '; '.join(issues))

    try:
        if scope == 'default':
            _templates.set_default_template(ctx.enrollment, kind, content)
        elif scope == 'group':
            _templates.set_group_template(ctx.enrollment, scope_name, kind, content)
        elif scope == 'server':
            _templates.set_server_template(ctx.enrollment, scope_name, kind, content)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))

    _audit_admin(ctx, admin, 'template.set',
                 {'scope': scope, 'scope_name': scope_name, 'kind': kind,
                  'content_bytes': len(content)},
                 'ok')
    return 200, {'status': 'ok', 'scope': scope,
                 'scope_name': scope_name, 'kind': kind}


def template_unset(ctx: AdminContext, admin: Admin,
                   body: dict) -> tuple[int, dict]:
    """Remove a template override at the given scope.

    Removing the default reverts to the built-in. Removing a group or
    server override reverts to its next-level fallback. Idempotent —
    removing a non-existent override is a no-op success.
    """
    if (err := _check('template.unset', admin)):
        return err
    parsed = _parse_template_scope(body)
    if isinstance(parsed, tuple) and len(parsed) == 2:
        return parsed                                       # type: ignore[return-value]
    scope, scope_name, kind = parsed                        # type: ignore[misc]
    if scope == 'default':
        _templates.unset_default_template(ctx.enrollment, kind)
    elif scope == 'group':
        _templates.unset_group_template(ctx.enrollment, scope_name, kind)
    elif scope == 'server':
        _templates.unset_server_template(ctx.enrollment, scope_name, kind)
    _audit_admin(ctx, admin, 'template.unset',
                 {'scope': scope, 'scope_name': scope_name, 'kind': kind},
                 'ok')
    return 200, {'status': 'ok'}


def template_list(ctx: AdminContext, admin: Admin) -> tuple[int, dict]:
    """Return every template the CA knows about (built-in + stored)."""
    if (err := _check('template.list', admin)):
        return err
    return 200, {'status': 'ok',
                 'templates': _templates.list_templates(ctx.enrollment)}


def template_effective(ctx: AdminContext, admin: Admin,
                       server_name: str, kind: str) -> tuple[int, dict]:
    """Return the template that would actually be used for (server, kind),
    plus the source (server / group / default / builtin) so callers can
    compute a meaningful diff against the default."""
    if (err := _check('template.show', admin)):
        return err
    try:
        content, source, detail = _templates.get_effective_template(
            ctx.enrollment, server_name, kind=kind)
    except EnrollmentError as e:
        return _err(400, 'bad_request', str(e))
    return 200, {
        'status': 'ok',
        'server': server_name,
        'kind': kind,
        'source': source,
        'source_detail': detail,
        'content': content,
    }


# ---------------------------------------------------------------------------
# CA-bypass cert mint
# ---------------------------------------------------------------------------

def bypass_cert_mint(ctx: AdminContext, admin: Admin,
                     body: dict) -> tuple[int, dict]:
    # §4.3.6 admin surface; delegates to §4.3.4 bypass-mint path
    """Mint a CA-bypass authz cert for an enrolled user.

    The cert is a normal X.509 authz cert with the OID_CA_BYPASS
    critical extension marker. The operator stores it offline; when
    presented via the mssh client's ``--inject-bypass-cert`` flag,
    msshd validates it and injects directly into the authz cache
    without a live CA call. See archive/design/notes-bypass-cache.md for the
    full design rationale.

    Body shape:
        {
          "username":     "alice",
          "pubkey_b64":   "<base64 of raw SSH pubkey blob>",
          "validity_days": 90,
          "source_bind":  "0.0.0.0/0",     // optional, default wildcard
          "server_bind":  "*",              // optional, default wildcard
          "channels":     ["session"],      // optional
          "force_command": "...",           // optional
          "max_session_seconds": 3600,      // optional
        }
    """
    if (err := _check('bypass_cert.mint', admin)):
        return err
    if ctx.signing_key is None or ctx.signing_cert is None:
        return _err(500, 'internal',
                    'CA signing key not configured for bypass-cert mint')

    username = body.get('username')
    if not isinstance(username, str) or not username:
        return _err(400, 'bad_request', 'username required')
    if username not in ctx.enrollment.users:
        return _err(404, 'not_found', f'user {username!r} not enrolled')

    pubkey_b64 = body.get('pubkey_b64')
    if not isinstance(pubkey_b64, str) or not pubkey_b64:
        return _err(400, 'bad_request',
                    'pubkey_b64 required (base64 of the raw SSH pubkey blob)')
    try:
        pubkey_blob = base64.b64decode(pubkey_b64, validate=True)
    except Exception as e:
        return _err(400, 'bad_request', f'invalid pubkey_b64: {e}')

    # `or 90` would coerce 0 to the default; use explicit None check so
    # validity_days=0 hits the range validator below.
    raw_days = body.get('validity_days')
    if raw_days is None:
        validity_days = 90
    else:
        try:
            validity_days = int(raw_days)
        except (TypeError, ValueError):
            return _err(400, 'bad_request',
                        'validity_days must be an integer')
    if not (1 <= validity_days <= 3650):
        return _err(400, 'bad_request',
                    'validity_days must be 1..3650')

    source_bind = str(body.get('source_bind') or '0.0.0.0/0')
    server_bind = str(body.get('server_bind') or '*')
    channels = list(body.get('channels') or ['session'])
    force_command = body.get('force_command')
    max_session_seconds = body.get('max_session_seconds')
    if max_session_seconds is not None:
        try:
            max_session_seconds = int(max_session_seconds)
        except (TypeError, ValueError):
            return _err(400, 'bad_request',
                        'max_session_seconds must be an integer')

    not_before = _dt.datetime.now(_dt.timezone.utc)
    not_after = not_before + _dt.timedelta(days=validity_days)

    try:
        cert, serial_hex = cert_minter.mint_authorization_cert(
            subject_username=username,
            subject_pubkey_blob=pubkey_blob,
            signing_key=ctx.signing_key,
            signing_cert=ctx.signing_cert,
            not_before=not_before,
            not_after=not_after,
            source_bind=source_bind,
            server_bind=server_bind,
            channels=channels,
            force_command=force_command if isinstance(force_command, str)
                          and force_command else None,
            max_session_seconds=max_session_seconds,
            ca_bypass=True,
            crl_url=ctx.crl_url,                # R-2
        )
    except Exception as e:                                      # noqa: BLE001
        return _err(500, 'internal', f'mint failed: {e}')

    # Serialize as PEM for operator storage.
    from cryptography.hazmat.primitives import serialization
    cert_pem = cert.public_bytes(
        serialization.Encoding.PEM).decode('ascii')

    _audit_admin(ctx, admin, 'bypass_cert.mint',
                 {'username': username, 'serial': serial_hex,
                  'validity_days': validity_days,
                  'force_command': force_command,
                  'source_bind': source_bind},
                 'ok')

    return 201, {
        'status': 'ok',
        'username': username,
        'serial': serial_hex,
        'not_before': not_before.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'not_after': not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'cert_pem': cert_pem,
    }


# ---------------------------------------------------------------------------
# CRL — cert revocation list
# ---------------------------------------------------------------------------

def cert_revoke(ctx: AdminContext, admin: Admin,
                body: dict) -> tuple[int, dict]:
    # §4.3.6 admin endpoint; appends to §4.3.5 CRL; drives §13.3
    # revocation propagation
    """Append a CRL entry revoking the given cert serial(s).

    Body:
        {
          "serials": ["abc123", "def456"],    // required, lowercase hex
          "issuer":  "user-mint",              // optional; default user-mint
          "reason":  "operator decision"       // optional
        }

    ``issuer`` is the intermediate's short_name. Defaults to user-mint
    (matches v0.2.0 single-signer behavior). Per-issuer CRL logs since
    v0.2.2 — serials are issuer-scoped, so the operator picks which
    intermediate's log to append to.

    Every msshd in the fleet picks this up on its next authorize call
    (the response's ``current_crl_seqs`` map advances; msshd fetches
    the missing entries per-issuer and applies them to its authz cache).
    """
    if (err := _check('cert.revoke', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'cert.revoke')):
        return err
    if ctx.crl is None:
        return _err(500, 'internal', 'CRL store not configured')
    serials = body.get('serials')
    if not isinstance(serials, list) or not serials:
        return _err(400, 'bad_request',
                    'serials must be a non-empty list of hex serials')
    cleaned: list[str] = []
    for s in serials:
        if not isinstance(s, str) or not s.strip():
            return _err(400, 'bad_request', f'invalid serial: {s!r}')
        cleaned.append(s.strip().lower())
    reason = str(body.get('reason') or '')
    issuer = str(body.get('issuer') or 'user-mint').strip()

    try:
        entry = ctx.crl.append(issuer, cleaned,
                                revoked_by=admin.name, reason=reason)
    except OSError as e:
        return _err(500, 'internal', f'CRL append failed: {e}')

    _audit_admin(ctx, admin, 'cert.revoke',
                 {'serials': cleaned, 'seq': entry.seq,
                  'issuer': issuer, 'reason': reason},
                 'ok')

    return 201, {
        'status': 'ok',
        'seq': entry.seq,
        'issuer': issuer,
        'revoked_at': entry.revoked_at,
        'serials': cleaned,
    }


# ---------------------------------------------------------------------------
# Intermediates (v0.2.4+ — Commit 5 of PKI hierarchy work)
# ---------------------------------------------------------------------------

_PERMISSIONS['intermediate.list'] = {
    'superuser', 'server-admin', 'user-admin', 'auditor',
}                                                  # R-4: broadened per §14.1.2
_PERMISSIONS['intermediate.rotate'] = {'superuser'}
_PERMISSIONS['intermediate.external.mint'] = {'superuser'}
_PERMISSIONS['intermediate.external.list'] = {
    'superuser', 'server-admin', 'user-admin', 'auditor',
}                                                  # R-4: broadened per §14.1.2


def intermediate_list(ctx: AdminContext, admin: Admin
                      ) -> tuple[int, dict]:
    """Return metadata about each named intermediate. Read-only;
    superuser + auditor both allowed."""
    if (err := _check('intermediate.list', admin)):
        return err
    from . import cert_minter
    if not ctx.ca_dir:
        return _err(503, 'unavailable',
                    'CA running in legacy single-signer mode; no '
                    'intermediates to list. Re-run mssh-admin init to '
                    'bootstrap the multi-intermediate layout.')
    try:
        intermediates = cert_minter.load_intermediates(ctx.ca_dir)
    except FileNotFoundError as e:
        return _err(503, 'unavailable',
                    f'intermediates not on disk: {e}')
    out = []
    for role, inter in intermediates.items():
        out.append({
            'role': role,
            'issuer_id': inter.issuer_id,
            'pubkey_fp16': inter.pubkey_fp16,
            'subject': inter.cert.subject.rfc4514_string(),
            'not_before': inter.cert.not_valid_before_utc.strftime(
                '%Y-%m-%dT%H:%M:%SZ'),
            'not_after': inter.cert.not_valid_after_utc.strftime(
                '%Y-%m-%dT%H:%M:%SZ'),
        })
    return 200, {'status': 'ok', 'intermediates': out}


def intermediate_rotate(ctx: AdminContext, admin: Admin,
                         body: dict) -> tuple[int, dict]:
    """Replace the named intermediate's keypair + cert. The new cert
    is signed by root; the old key/cert files are archived with a
    timestamp suffix.

    Operators must distribute the new cert to validators that pin
    to it (msshd's bypass_trust_root, auth_trust_root, user_ca_pubkey,
    or ca.ca_pubkey depending on the role) before existing leaves
    expire. Until distributed, validators rejecting the new cert
    means freshly-minted leaves fail validation.
    """
    if (err := _check('intermediate.rotate', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'intermediate.rotate')):
        return err
    role = (body.get('role') or '').strip()
    from . import cert_minter
    if role not in cert_minter.INTERMEDIATE_ROLES:
        return _err(400, 'bad_request',
                    f'role must be one of '
                    f'{list(cert_minter.INTERMEDIATE_ROLES)}, got {role!r}')
    if not ctx.ca_dir:
        return _err(503, 'unavailable',
                    'CA running in legacy single-signer mode; nothing '
                    'to rotate. Bootstrap with the multi-intermediate '
                    'layout first.')

    from pathlib import Path
    ca_dir = Path(ctx.ca_dir)
    role_dir = ca_dir / 'intermediates' / role
    if not role_dir.exists():
        return _err(503, 'unavailable',
                    f'intermediate {role} not on disk at {role_dir}')

    # Load root + generate new keypair + sign new cert.
    root_cert = cert_minter.load_root_cert(ca_dir)
    root_key = cert_minter.load_private_key(ca_dir / 'root-key.pem')
    new_key = cert_minter.generate_signing_key('ec')
    new_cert = cert_minter._issue_intermediate(role, new_key, root_key, root_cert)

    # Archive old, write new. Archive is timestamp-suffixed in the role
    # dir itself so an operator can audit the rotation later.
    ts = _now_iso().replace(':', '').replace('-', '')
    (role_dir / f'cert.pem.archive.{ts}').write_bytes(
        (role_dir / 'cert.pem').read_bytes())
    (role_dir / f'key.pem.archive.{ts}').write_bytes(
        (role_dir / 'key.pem').read_bytes())
    new_cert_pem = cert_minter.serialize_certificate(new_cert)
    new_key_pem = cert_minter.serialize_private_key(new_key)
    (role_dir / 'cert.pem').write_bytes(new_cert_pem)
    (role_dir / 'key.pem').write_bytes(new_key_pem)
    import os as _os
    _os.chmod(role_dir / 'key.pem', 0o600)

    # Keep legacy aliases in sync for user-mint + auth roles.
    if role == 'user-mint':
        (ca_dir / 'signing-cert.pem').write_bytes(new_cert_pem)
        (ca_dir / 'signing-key.pem').write_bytes(new_key_pem)
        _os.chmod(ca_dir / 'signing-key.pem', 0o600)
    elif role == 'auth':
        root_pem = cert_minter.serialize_certificate(root_cert)
        (ca_dir / 'tls-ca-cert.pem').write_bytes(new_cert_pem + root_pem)
        (ca_dir / 'tls-ca-key.pem').write_bytes(new_key_pem)
        _os.chmod(ca_dir / 'tls-ca-key.pem', 0o600)

    new_fp = cert_minter.compute_pubkey_fp16(new_key.public_key())
    _audit_admin(ctx, admin, 'intermediate.rotate',
                 {'role': role, 'new_pubkey_fp16': new_fp,
                  'archive_suffix': ts}, 'ok')

    return 200, {
        'status': 'ok',
        'role': role,
        'new_issuer_id': f'{role}:{new_fp}',
        'new_cert_pem': new_cert_pem.decode('ascii'),
        'archive_suffix': ts,
        'warning': ('Distribute the new cert to validators that pin '
                    'this intermediate (msshd bypass_trust_root, '
                    'auth_trust_root, user_ca_pubkey, ca.ca_pubkey) '
                    'before existing leaves expire.'),
    }


def external_intermediate_mint(ctx: AdminContext, admin: Admin,
                                body: dict) -> tuple[int, dict]:
    """Mint an external Intermediate CA cert per the trust-model
    amendment (design/notes-pki-hierarchy.md § External Intermediate
    CA tier).

    Body: {name, path_length?, validity_days?}

    The external entity gets the (cert, key) pair to operate their
    own signing infrastructure. The CA keeps the cert on disk for
    audit + revocation; the private key is NOT retained — it's
    returned exactly once and the operator hands it off out-of-band.
    """
    if (err := _check('intermediate.external.mint', admin)):
        return err
    if (err := admin_check_2fa(ctx, admin, 'intermediate.external.mint')):
        return err
    name = (body.get('name') or '').strip()
    if not name or '/' in name or name.startswith('.'):
        return _err(400, 'bad_request',
                    'name required: short alphanumeric (no /, no leading .)')
    try:
        path_length = int(body.get('path_length') or 0)
    except (TypeError, ValueError):
        return _err(400, 'bad_request', 'path_length must be int')
    if path_length < 0 or path_length > 5:
        return _err(400, 'bad_request',
                    'path_length must be in [0, 5]')
    # §15.20 profile flag. `generic` (default) preserves v0.4.x
    # behavior byte-identical; named profiles (e.g. `device-identity`)
    # bump default validity to 30yr and stamp the §15.23
    # intermediate-purpose marker so external-use leaves can pin to it.
    _BUILTIN_PROFILES = {
        'generic':         {'default_validity_days': 3650},
        'device-identity': {'default_validity_days': 10950},
    }
    profile = (body.get('profile') or 'generic').strip()
    if profile not in _BUILTIN_PROFILES:
        return _err(400, 'bad_request',
                    f'unknown profile {profile!r}; built-ins are '
                    f'{sorted(_BUILTIN_PROFILES)}')
    profile_defaults = _BUILTIN_PROFILES[profile]
    validity_days = int(
        body.get('validity_days') or profile_defaults['default_validity_days'])

    if not ctx.ca_dir:
        return _err(503, 'unavailable',
                    'CA in legacy single-signer mode; multi-intermediate '
                    'layout required for external CAs.')

    from pathlib import Path
    from . import cert_minter
    ca_dir = Path(ctx.ca_dir)
    target = ca_dir / 'external' / name
    if target.exists():
        return _err(409, 'conflict',
                    f'external intermediate {name!r} already exists at '
                    f'{target}; rotate or pick a different name')

    # §15.22 — optional `new_root: true` opts into a separate Root.
    # The named Root is created (or re-used if it already exists) under
    # <ca_dir>/roots/<root_name>/, and the new intermediate is signed
    # by that Root instead of the primary one. Operator's deployment
    # process trusts the right Root in the device's trust store.
    new_root = bool(body.get('new_root', False))
    root_name = (body.get('root_name') or '').strip()
    if new_root or root_name:
        if not root_name:
            root_name = name   # default to intermediate's name
        from . import roots as roots_mod
        all_roots = roots_mod.load_all_roots(ca_dir)
        if root_name in all_roots and root_name != 'primary':
            root_entry = all_roots[root_name]
        else:
            try:
                root_entry = roots_mod.create_new_root(
                    ca_dir, name=root_name)
            except ValueError as e:
                return _err(400, 'bad_request', str(e))
        root_cert = root_entry.cert
        root_key = root_entry.key
    else:
        root_cert = cert_minter.load_root_cert(ca_dir)
        root_key = cert_minter.load_private_key(ca_dir / 'root-key.pem')
        root_name = 'primary'

    new_key, new_cert = cert_minter.issue_external_intermediate(
        name, root_key=root_key, root_cert=root_cert,
        path_length=path_length, validity_days=validity_days,
        profile=profile)

    target.mkdir(parents=True, exist_ok=True)
    cert_pem = cert_minter.serialize_certificate(new_cert)
    (target / 'cert.pem').write_bytes(cert_pem)
    # §15.20 — persist the profile alongside the cert so the CA knows
    # on future loads which leaves this intermediate is allowed to sign.
    import json as _json
    (target / 'profile.json').write_text(_json.dumps({
        'profile': profile,
        'path_length': path_length,
        'validity_days': validity_days,
    }))
    # NOTE: we do NOT persist the private key. The external entity
    # gets it once in this response; the CA retains only the public
    # cert. This is the whole point of delegating signing authority.
    key_pem = cert_minter.serialize_private_key(new_key)
    fp16 = cert_minter.compute_pubkey_fp16(new_key.public_key())

    _audit_admin(ctx, admin, 'intermediate.external.mint',
                 {'name': name, 'path_length': path_length,
                  'profile': profile,
                  'root_name': root_name,
                  'pubkey_fp16': fp16,
                  'serial': format(new_cert.serial_number, 'x')},
                 'ok')

    return 201, {
        'status': 'ok',
        'name': name,
        'path_length': path_length,
        'profile': profile,
        'root_name': root_name,
        'issuer_id': f'external-{name}:{fp16}',
        'cert_pem': cert_pem.decode('ascii'),
        'key_pem': key_pem.decode('ascii'),
        'serial': format(new_cert.serial_number, 'x'),
        'warning': ('Private key is returned in this response ONLY. The '
                    'CA does NOT retain it. Deliver to the external '
                    'entity over a secure channel and store offline.'),
    }


def external_intermediate_list(ctx: AdminContext, admin: Admin
                                ) -> tuple[int, dict]:
    """List all external Intermediate CAs minted by this CA. CAs
    are identified by their on-disk cert under <ca_dir>/external/<name>/."""
    if (err := _check('intermediate.external.list', admin)):
        return err
    if not ctx.ca_dir:
        return 200, {'status': 'ok', 'external_intermediates': []}
    from . import cert_minter
    externals = cert_minter.load_external_intermediates(ctx.ca_dir)
    out = []
    for name, cert in externals.items():
        try:
            bc = cert.extensions.get_extension_for_class(
                __import__('cryptography.x509', fromlist=['BasicConstraints']
                            ).BasicConstraints).value
            path_length = bc.path_length
        except Exception:
            path_length = None
        out.append({
            'name': name,
            'serial': format(cert.serial_number, 'x'),
            'subject': cert.subject.rfc4514_string(),
            'path_length': path_length,
            'not_before': cert.not_valid_before_utc.strftime(
                '%Y-%m-%dT%H:%M:%SZ'),
            'not_after': cert.not_valid_after_utc.strftime(
                '%Y-%m-%dT%H:%M:%SZ'),
        })
    return 200, {'status': 'ok', 'external_intermediates': out}


def crl_fetch(ctx: AdminContext, admin: Admin,
              after: int, limit: int | None,
              issuer: str = 'user-mint') -> tuple[int, dict]:
    """Return CRL entries with seq > ``after`` for ``issuer``, optionally
    bounded by ``limit``. Operator-callable for diagnostic visibility;
    the msshd hot path uses the un-authenticated ``GET /v1/crl`` mirror.
    """
    if (err := _check('crl.read', admin)):
        return err
    if ctx.crl is None:
        return _err(500, 'internal', 'CRL store not configured')
    entries = ctx.crl.fetch_after(issuer, int(after or 0), limit=limit)
    return 200, {
        'status': 'ok',
        'issuer': issuer,
        'current_seq': ctx.crl.for_issuer(issuer).current_seq(),
        'current_seqs': ctx.crl.current_seqs(),
        'entries': [e.to_dict() for e in entries],
    }


# ---------------------------------------------------------------------------
# §5: cert minting for other applications
# ---------------------------------------------------------------------------

_CERT_TYPES = ('tls-server', 'https-user', 'code-sign')

# §15.23: per-type validity resolution is now operator-configurable
# via ca-config.yaml's `cert_kinds:` section (parsed into
# `CertKindsPolicy` and threaded through `AdminContext.cert_kinds`).
# When the operator's config has no `cert_kinds:` section, these
# fall back to the built-in baseline in config.py — which mirrors
# v0.4.x behavior byte-identical. The constants below are retained
# only as a v0.4.x-compatible fallback path when callers pass a
# raw AdminContext without `cert_kinds` (older tests; legacy entry
# points). The authoritative source is `ctx.cert_kinds`.
_CERT_DEFAULT_VALIDITY = {
    'tls-server': 90,
    'https-user': 90,
    'code-sign':  365,
    'openvpn':    90,
}
_CERT_MAX_VALIDITY = 825   # CAB-forum-style max; v0.4.x global cap.


def _validate_san(s: str) -> str:
    """Normalize and validate a single SAN string.

    Accepts ``DNS:<name>``, ``IP:<addr>``, or a bare DNS name (no
    prefix → treated as DNS). Raises ValueError on malformed input.
    Returns the normalized form (always with a ``DNS:`` / ``IP:``
    prefix) for downstream consumers.
    """
    s = s.strip()
    if not s:
        raise ValueError('empty SAN')
    if s.startswith('IP:'):
        import ipaddress
        ipaddress.ip_address(s[3:])  # raises ValueError if bad
        return s
    if s.startswith('DNS:'):
        host = s[4:]
        if not host or any(c in host for c in ' \t\n\r"\''):
            raise ValueError(f'invalid DNS SAN {host!r}')
        return s
    # bare hostname
    host = s
    if any(c in host for c in ' \t\n\r"\''):
        raise ValueError(f'invalid DNS SAN {host!r}')
    return f'DNS:{host}'


def _validity_or_default(ctx: AdminContext | None, body: dict,
                         kind: str) -> tuple[int, dict | None]:
    """Resolve validity_days from body with operator-configured default
    + cap (§15.23). Returns ``(days, err_payload)`` — err_payload is
    None on success.

    Looks up `ctx.cert_kinds.default_for(kind)` / `cap_for(kind)` when
    `ctx.cert_kinds` is set. Otherwise (legacy tests, no ctx) falls
    back to the v0.4.x baseline dicts.
    """
    if ctx is not None and getattr(ctx, 'cert_kinds', None) is not None:
        default = ctx.cert_kinds.default_for(kind)
        cap = ctx.cert_kinds.cap_for(kind)
    else:
        default = _CERT_DEFAULT_VALIDITY.get(kind, 90)
        cap = _CERT_MAX_VALIDITY
    raw = body.get('validity_days')
    if raw is None:
        return default, None
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return 0, _err(400, 'bad_request',
                       f'validity_days must be an integer, got {raw!r}')[1]
    if days < 1:
        return 0, _err(400, 'bad_request',
                       f'validity_days must be >= 1, got {days}')[1]
    if days > cap:
        return 0, _err(400, 'bad_request',
                       f'validity_days={days} exceeds cap {cap}')[1]
    return days, None


def cert_mint(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    """Mint an X.509 leaf cert against the TLS CA hierarchy.

    Body schema::

      {
        "type":          "tls-server" | "https-user" | "code-sign",
        "cn":            "common-name",
        "sans":          ["DNS:foo.example.com", "IP:10.0.0.1"]   # tls-server only
        "validity_days": 90                                       # optional
      }

    Returns ``{cert_pem, key_pem, ca_cert_pem, subject_cn}`` shaped
    like server / admin add. The CLI handles output formatting (PEM
    files for tls-server / code-sign; PKCS#12 wrap for https-user).
    """
    if (err := _check('cert.mint', admin)):
        return err

    cert_type = body.get('type')
    if cert_type not in _CERT_TYPES:
        return _err(400, 'bad_request',
                    f'type must be one of {_CERT_TYPES}, got {cert_type!r}')

    cn = body.get('cn')
    if not isinstance(cn, str) or not cn.strip():
        return _err(400, 'bad_request', 'missing/invalid cn')
    cn = cn.strip()

    days, err = _validity_or_default(ctx, body, cert_type)
    if err:
        return 400, err

    sans_raw = body.get('sans') or []
    if cert_type != 'tls-server' and sans_raw:
        return _err(400, 'bad_request',
                    f'sans are only valid for type=tls-server (got {cert_type})')
    if not isinstance(sans_raw, list):
        return _err(400, 'bad_request', 'sans must be a list')
    try:
        sans = [_validate_san(s) for s in sans_raw]
    except ValueError as e:
        return _err(400, 'bad_request', f'invalid SAN: {e}')

    try:
        if cert_type == 'tls-server':
            bundle = cert_minter.issue_server_cert(
                cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=days, key_type=ctx.mtls_key_type,
                sans=sans or None,
                crl_url=ctx.crl_url)
        elif cert_type == 'https-user':
            bundle = cert_minter.issue_client_cert(
                cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=days, key_type=ctx.mtls_key_type,
                crl_url=ctx.crl_url, kind='https-user')
        else:  # code-sign
            # Code-signing certs intentionally skip CRLDP — long-lived
            # build identities + downstream timestamping authorities
            # typically handle revocation differently.
            bundle = cert_minter.issue_codesign_cert(
                cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=days, key_type=ctx.mtls_key_type)
    except Exception as e:
        return _err(500, 'internal', f'cert issuance failed: {e}')

    _audit_admin(ctx, admin, f'cert.mint.{cert_type}',
                 {'cn': cn, 'validity_days': days,
                  'sans': sans}, 'ok')

    return 201, {
        'status': 'ok',
        'cert': {
            'type': cert_type,
            'subject_cn': cn,
            'validity_days': days,
        },
        'credentials': {
            'cert_pem': bundle.cert_pem.decode('ascii'),
            'key_pem': bundle.key_pem.decode('ascii'),
            'ca_cert_pem': bundle.ca_cert_pem.decode('ascii'),
        },
    }


def external_use_cert_mint(ctx: AdminContext, admin: Admin,
                            body: dict) -> tuple[int, dict]:
    """§15.19 — mint a CSR-based external-use leaf signed by an
    operator-named external intermediate (one minted via §15.20
    `--profile <name>`).

    Body schema::

      {
        "cn":                  "device-001",
        "csr":                 "-----BEGIN CERTIFICATE REQUEST-----...",
        "issuer_intermediate": "device-mfg",
        "validity_days":       7305,                  # optional
        "never_expires":       false,                 # optional (§15.19)
        "custom_oids":         [{"oid": ..., "value": ...}],  # optional (§15.21)
      }

    Returns the issued leaf PEM (no private key — operator's CSR-supplied
    key stays on-device).
    """
    if (err := _check('cert.external_use.mint', admin)):
        return err

    cn = (body.get('cn') or '').strip()
    if not cn:
        return _err(400, 'bad_request', 'missing/invalid cn')

    csr_pem = body.get('csr')
    if not csr_pem:
        return _err(400, 'bad_request',
                    'external-use mint requires a csr (PEM); the CA does '
                    'not generate keys for external-use certs (§15.19)')

    issuer_name = (body.get('issuer_intermediate') or '').strip()
    if not issuer_name:
        return _err(400, 'bad_request',
                    'external-use mint requires issuer_intermediate '
                    '(the name of a §15.20-minted external intermediate)')

    never_expires = bool(body.get('never_expires', False))
    custom_oids = body.get('custom_oids') or []

    if not never_expires:
        days, err = _validity_or_default(ctx, body, 'external-use')
        if err:
            return 400, err
    else:
        days = 0

    if not ctx.ca_dir:
        return _err(503, 'unavailable',
                    'CA in legacy single-signer mode; multi-intermediate '
                    'layout required for external-use (§15.19)')

    # Load the named external intermediate from disk.
    from pathlib import Path
    from . import cert_minter
    from . import csr as csr_mod
    ca_dir = Path(ctx.ca_dir)
    issuer_dir = ca_dir / 'external' / issuer_name
    issuer_cert_path = issuer_dir / 'cert.pem'
    if not issuer_cert_path.exists():
        return _err(404, 'not_found',
                    f'external intermediate {issuer_name!r} not found '
                    f'(mint it first via `mssh-admin intermediate mint-external`)')
    issuer_cert = cert_minter.load_certificate(issuer_cert_path)

    # External intermediates don't persist their key CA-side per §2.6.
    # For external-use leaves we need the operator to have provided the
    # intermediate's key back — typically by writing it into the
    # intermediate's directory after minting. v0.5.0 keeps this simple:
    # if `key.pem` is present in the intermediate's dir, use it.
    issuer_key_path = issuer_dir / 'key.pem'
    if not issuer_key_path.exists():
        return _err(409, 'conflict',
                    f'external intermediate {issuer_name!r} has no key.pem '
                    f'on disk; this CA cannot sign external-use leaves '
                    f'under it. (The key was returned at mint time and '
                    f'must be placed at {issuer_key_path} to enable CA-side '
                    f'leaf issuance.)')
    issuer_key = cert_minter.load_private_key(issuer_key_path)

    # Verify + parse the CSR.
    try:
        csr_obj = csr_mod.load_and_verify_csr(csr_pem)
    except csr_mod.CSRValidationError as e:
        return _err(400, 'bad_request', f'CSR rejected: {e}')

    try:
        issued = cert_minter.issue_external_use_cert(
            csr_obj,
            issuer_key=issuer_key, issuer_cert=issuer_cert,
            cn=cn,
            validity_days=days if not never_expires else 1,
            never_expires=never_expires,
            custom_oids=custom_oids,
            allowlist=ctx.custom_oids,
            crl_url=ctx.crl_url,
        )
    except ValueError as e:
        return _err(400, 'bad_request', str(e))
    except Exception as e:
        return _err(500, 'internal', f'cert issuance failed: {e}')

    _audit_admin(ctx, admin, 'cert.external_use.mint',
                 {'cn': cn,
                  'issuer_intermediate': issuer_name,
                  'never_expires': never_expires,
                  'validity_days': days,
                  'custom_oids': [
                      r.get('oid') or r.get('name')
                      for r in custom_oids if isinstance(r, dict)
                  ]}, 'ok')

    return 201, {
        'status': 'ok',
        'cert': {
            'type': 'external-use',
            'subject_cn': cn,
            'issuer_intermediate': issuer_name,
            'never_expires': never_expires,
            'validity_days': (None if never_expires else days),
            'not_valid_after': issued.not_valid_after.isoformat(),
        },
        'credentials': {
            'cert_pem': issued.cert_pem.decode('ascii'),
            'leaf_only_pem': issued.leaf_only_pem.decode('ascii'),
            'ca_cert_pem': issued.ca_cert_pem.decode('ascii'),
        },
    }


def openvpn_issue(ctx: AdminContext, admin: Admin,
                  body: dict) -> tuple[int, dict]:
    """Issue an OpenVPN client cert + key + CA bundle.

    Body schema::

      {
        "cn":              "alice",                       # client cert CN
        "server_endpoint": "vpn.example.com 1194",        # for `remote ` directive
        "proto":           "udp" | "tcp"                  # optional, default udp
        "dev":             "tun" | "tap"                  # optional, default tun
        "validity_days":   90                             # optional
      }

    Returns PEMs + the connection metadata; the CLI assembles the
    final ``.ovpn`` config file (which inlines the cert/key/ca).
    """
    if (err := _check('openvpn.issue', admin)):
        return err

    cn = body.get('cn')
    if not isinstance(cn, str) or not cn.strip():
        return _err(400, 'bad_request', 'missing/invalid cn')
    cn = cn.strip()

    server_endpoint = body.get('server_endpoint')
    if not isinstance(server_endpoint, str) or not server_endpoint.strip():
        return _err(400, 'bad_request',
                    'missing/invalid server_endpoint (e.g. "vpn.example.com 1194")')
    server_endpoint = server_endpoint.strip()
    # Basic shape check: should contain a space (host then port).
    if len(server_endpoint.split()) != 2:
        return _err(400, 'bad_request',
                    f'server_endpoint must be "host port" form, got {server_endpoint!r}')

    proto = (body.get('proto') or 'udp').strip().lower()
    if proto not in ('udp', 'tcp'):
        return _err(400, 'bad_request',
                    f'proto must be udp or tcp, got {proto!r}')
    dev = (body.get('dev') or 'tun').strip().lower()
    if dev not in ('tun', 'tap'):
        return _err(400, 'bad_request', f'dev must be tun or tap, got {dev!r}')

    days, err = _validity_or_default(ctx, body, 'openvpn')
    if err:
        return 400, err

    try:
        bundle = cert_minter.issue_client_cert(
            cn, ctx.tls_ca_key, ctx.tls_ca_cert,
            validity_days=days, key_type=ctx.mtls_key_type,
            crl_url=ctx.crl_url, kind='openvpn')
    except Exception as e:
        return _err(500, 'internal', f'cert issuance failed: {e}')

    _audit_admin(ctx, admin, 'openvpn.issue',
                 {'cn': cn, 'server_endpoint': server_endpoint,
                  'proto': proto, 'dev': dev,
                  'validity_days': days}, 'ok')

    return 201, {
        'status': 'ok',
        'openvpn': {
            'subject_cn': cn,
            'server_endpoint': server_endpoint,
            'proto': proto, 'dev': dev,
            'validity_days': days,
        },
        'credentials': {
            'cert_pem': bundle.cert_pem.decode('ascii'),
            'key_pem': bundle.key_pem.decode('ascii'),
            'ca_cert_pem': bundle.ca_cert_pem.decode('ascii'),
        },
    }


# ---------------------------------------------------------------------------
# §5 WireGuard catalog
# ---------------------------------------------------------------------------

def _wg_or_503(ctx: AdminContext):
    """Return ctx.wireguard or a 503 payload if WireGuard isn't
    configured on this CA (no `wireguard.path` in ca-config.yaml)."""
    if ctx.wireguard is None:
        return None, _err(503, 'unavailable',
                          'WireGuard not configured on this CA '
                          '(set wireguard.path in ca-config.yaml)')
    return ctx.wireguard, None


def wireguard_server_init(ctx: AdminContext, admin: Admin,
                          body: dict) -> tuple[int, dict]:
    """POST /v1/admin/wireguard/server  — create a WireGuard interface.

    Body: {name, network? (CIDR), network_v6? (CIDR), listen_port,
    endpoint ("host:port")}.

    ``network`` and ``network_v6`` are independently optional; at
    least one is required (v0.4.0+). When both are set the server
    runs dual-stack.
    """
    if (err := _check('wireguard.server.init', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    from . import wireguard as _wg

    name = (body.get('name') or '').strip()
    network = (body.get('network') or '').strip()
    network_v6 = (body.get('network_v6') or '').strip()
    endpoint = (body.get('endpoint') or '').strip()
    if not name or not endpoint:
        return _err(400, 'bad_request', 'name and endpoint are required')
    if not network and not network_v6:
        return _err(400, 'bad_request',
                    'at least one of network or network_v6 is required')
    try:
        listen_port = int(body.get('listen_port') or 51820)
    except (TypeError, ValueError):
        return _err(400, 'bad_request', 'listen_port must be an integer')

    try:
        srv = wg.server_init(name=name, network=network,
                             network_v6=network_v6,
                             listen_port=listen_port, endpoint=endpoint,
                             created_by=admin.name)
    except _wg.WireGuardConflict as e:
        return _err(409, 'conflict', str(e))
    except _wg.WireGuardError as e:
        return _err(400, 'bad_request', str(e))

    _audit_admin(ctx, admin, 'wireguard.server.init',
                 {'name': name, 'network': network,
                  'network_v6': network_v6,
                  'listen_port': listen_port, 'endpoint': endpoint}, 'ok')
    return 201, {'status': 'ok',
                 'server': {
                     'name': srv.name, 'network': srv.network,
                     'network_v6': srv.network_v6,
                     'listen_port': srv.listen_port,
                     'endpoint': srv.endpoint,
                     'public_key_b64': srv.public_key_b64,
                     'server_address': srv.server_address,
                     'server_address_v6': srv.server_address_v6,
                     'created_at': srv.created_at,
                 }}


def wireguard_server_remove(ctx: AdminContext, admin: Admin,
                            name: str) -> tuple[int, dict]:
    """DELETE /v1/admin/wireguard/server/<name>."""
    if (err := _check('wireguard.server.remove', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    from . import wireguard as _wg
    try:
        wg.server_remove(name)
    except _wg.WireGuardNotFound as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'wireguard.server.remove',
                 {'name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def wireguard_server_show(ctx: AdminContext, admin: Admin,
                          name: str) -> tuple[int, dict]:
    """GET /v1/admin/wireguard/server/<name>  — emits server config.

    Returns ``server`` metadata + ``server_config`` (the
    /etc/wireguard/<name>.conf text the operator writes on the
    WireGuard host). NB: ``server_config`` contains the server's
    private key — superuser-only.
    """
    if (err := _check('wireguard.server.show', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    from . import wireguard as _wg
    try:
        srv = wg.server_get(name)
    except _wg.WireGuardNotFound as e:
        return _err(404, 'not_found', str(e))
    peers = wg.peer_list(server_name=name)
    _audit_admin(ctx, admin, 'wireguard.server.show',
                 {'name': name, 'peer_count': len(peers)}, 'ok')
    return 200, {
        'status': 'ok',
        'server': {
            'name': srv.name, 'network': srv.network,
            'network_v6': srv.network_v6,
            'listen_port': srv.listen_port, 'endpoint': srv.endpoint,
            'public_key_b64': srv.public_key_b64,
            'server_address': srv.server_address,
            'server_address_v6': srv.server_address_v6,
            'created_at': srv.created_at, 'created_by': srv.created_by,
            'peer_count': len(peers),
        },
        'server_config': _wg.render_server_config(srv, peers),
    }


def wireguard_server_list(ctx: AdminContext, admin: Admin
                          ) -> tuple[int, dict]:
    """GET /v1/admin/wireguard/server  — list registered servers."""
    if (err := _check('wireguard.server.list', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    servers = wg.server_list()
    return 200, {'status': 'ok',
                 'servers': [{
                     'name': s.name, 'network': s.network,
                     'network_v6': s.network_v6,
                     'listen_port': s.listen_port, 'endpoint': s.endpoint,
                     'public_key_b64': s.public_key_b64,
                     'server_address': s.server_address,
                     'server_address_v6': s.server_address_v6,
                     'created_at': s.created_at,
                 } for s in servers]}


def wireguard_peer_issue(ctx: AdminContext, admin: Admin,
                         body: dict) -> tuple[int, dict]:
    """POST /v1/admin/wireguard/peer  — mint a peer keypair + config.

    Body: {name, server, persistent_keepalive?, dns?}.
    The peer's freshly-minted private key is returned exactly once;
    the CA only retains the public half.
    """
    if (err := _check('wireguard.peer.issue', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    from . import wireguard as _wg

    name = (body.get('name') or '').strip()
    server_name = (body.get('server') or '').strip()
    if not name or not server_name:
        return _err(400, 'bad_request', 'name and server are required')

    try:
        keepalive = int(body.get('persistent_keepalive') or 0)
    except (TypeError, ValueError):
        return _err(400, 'bad_request',
                    'persistent_keepalive must be an integer')
    dns = body.get('dns') or None

    try:
        peer, priv = wg.peer_issue(
            name=name, server_name=server_name,
            issued_by=admin.name,
            persistent_keepalive=keepalive)
    except _wg.WireGuardNotFound as e:
        return _err(404, 'not_found', str(e))
    except _wg.WireGuardConflict as e:
        return _err(409, 'conflict', str(e))
    except _wg.WireGuardCapacityError as e:
        return _err(507, 'capacity', str(e))

    srv = wg.server_get(server_name)
    client_config = _wg.render_peer_config(srv, peer, priv, dns=dns)

    _audit_admin(ctx, admin, 'wireguard.peer.issue',
                 {'name': name, 'server': server_name,
                  'address': peer.address,
                  'address_v6': peer.address_v6}, 'ok')

    return 201, {
        'status': 'ok',
        'peer': {
            'name': peer.name, 'server': peer.server_name,
            'address': peer.address,
            'address_v6': peer.address_v6,
            'public_key_b64': peer.public_key_b64,
            'issued_at': peer.issued_at,
        },
        'client_config': client_config,
    }


def wireguard_peer_revoke(ctx: AdminContext, admin: Admin,
                          server_name: str, name: str
                          ) -> tuple[int, dict]:
    """DELETE /v1/admin/wireguard/peer/<server>/<name>."""
    if (err := _check('wireguard.peer.revoke', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    from . import wireguard as _wg
    try:
        wg.peer_revoke(name=name, server_name=server_name)
    except _wg.WireGuardNotFound as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'wireguard.peer.revoke',
                 {'name': name, 'server': server_name}, 'ok')
    return 200, {'status': 'ok',
                 'revoked': {'name': name, 'server': server_name}}


def wireguard_peer_list(ctx: AdminContext, admin: Admin,
                        server_name: str | None) -> tuple[int, dict]:
    """GET /v1/admin/wireguard/peer  — list peers (optionally filtered)."""
    if (err := _check('wireguard.peer.list', admin)):
        return err
    wg, err = _wg_or_503(ctx)
    if err:
        return err
    peers = wg.peer_list(server_name=server_name)
    return 200, {'status': 'ok',
                 'peers': [{
                     'name': p.name, 'server': p.server_name,
                     'address': p.address,
                     'public_key_b64': p.public_key_b64,
                     'issued_at': p.issued_at,
                     'persistent_keepalive': p.persistent_keepalive,
                 } for p in peers]}


# ---------------------------------------------------------------------------
# Admin-2FA passkey flow (design/admin-2fa.md)
# ---------------------------------------------------------------------------

def _passkey_or_503(ctx: AdminContext):
    """Return broker or a 503 if passkey isn't configured."""
    if ctx.passkey_broker is None:
        return None, _err(503, 'unavailable',
                          'mssh-passkey not configured on this CA '
                          '(set passkey.broker_url in ca-config.yaml)')
    return ctx.passkey_broker, None


def passkey_admin_enroll(ctx: AdminContext, admin: Admin,
                          body: dict) -> tuple[int, dict]:
    """POST /v1/admin/user/<admin_name>/passkey/enroll-begin

    Generate WebAuthn registration options for the named admin,
    push them to the broker, return the resulting URL the operator
    sends to the admin's phone.

    Restricted to superuser — passkey enrollment is sensitive (it
    binds a hardware token to a privileged identity)."""
    if (err := _check('admin.add', admin)):
        return err
    broker, err = _passkey_or_503(ctx)
    if err:
        return err

    target = (body.get('admin_name') or '').strip()
    if not target:
        return _err(400, 'bad_request', 'admin_name required')
    if target not in ctx.enrollment.admins:
        return _err(404, 'not_found', f'admin not found: {target}')

    label = body.get('label') or ''
    display_name = body.get('display_name') or target

    from . import passkey as _pk
    target_rec = ctx.enrollment.admins[target]
    exclude = [c.credential_id for c in target_rec.passkey_credentials
               if not c.revoked_at]
    options_json, challenge = _pk.generate_registration_options(
        rp_id=ctx.passkey_rp_id,
        rp_name=ctx.passkey_rp_name,
        user_id=f'admin:{target}',
        display_name=display_name,
        exclude_credential_ids=exclude or None,
    )

    try:
        ceremony = broker.create_ceremony(
            ceremony_type='register',
            options_json=options_json,
            description=f'Enroll a new passkey for admin {target!r}',
            display_name=display_name,
            callback_url=ctx.passkey_callback_url,
            ttl_seconds=300,
        )
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')

    # Stash the per-ceremony state until the callback arrives.
    ctx.passkey_pending_registrations[ceremony.ceremony_id] = {
        'flow': 'admin',
        'admin_name': target,
        'challenge': challenge,
        'label': label,
        'allowlist': ctx.passkey_aaguid_allowlist,
        'rp_id': ctx.passkey_rp_id,
        'expected_origin': ctx.passkey_expected_origin,
    }
    _audit_admin(ctx, admin, 'admin.passkey.enroll-begin',
                 {'target': target, 'ceremony_id': ceremony.ceremony_id}, 'ok')
    return 201, {
        'status': 'ok',
        'ceremony_id': ceremony.ceremony_id,
        'url': ceremony.url,
        'expires_at': ceremony.expires_at,
    }


def passkey_admin_list(ctx: AdminContext, admin: Admin,
                       admin_name: str) -> tuple[int, dict]:
    if (err := _check('admin.list', admin)):
        return err
    if admin_name not in ctx.enrollment.admins:
        return _err(404, 'not_found', f'admin not found: {admin_name}')
    creds = ctx.enrollment.admins[admin_name].passkey_credentials
    return 200, {
        'status': 'ok',
        'admin_name': admin_name,
        'credentials': [
            {
                'credential_id': c.credential_id,
                'aaguid': c.aaguid,
                'sign_count': c.sign_count,
                'label': c.label,
                'enrolled_at': c.enrolled_at,
                'revoked_at': c.revoked_at or None,
                'transports': list(c.transports),
            }
            for c in creds
        ],
    }


def passkey_admin_revoke(ctx: AdminContext, admin: Admin,
                          admin_name: str,
                          credential_id: str) -> tuple[int, dict]:
    if (err := _check('admin.add', admin)):
        return err
    try:
        ctx.enrollment.revoke_admin_passkey(admin_name, credential_id)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    # Invalidate any 2FA cache for this admin since their credential
    # set just changed.
    if ctx.passkey_2fa_cache is not None:
        ctx.passkey_2fa_cache.pop(admin_name, None)
    _audit_admin(ctx, admin, 'admin.passkey.revoke',
                 {'admin_name': admin_name,
                  'credential_id': credential_id}, 'ok')
    return 200, {'status': 'ok',
                 'admin_name': admin_name,
                 'revoked': credential_id}


def passkey_admin_callback(ctx: AdminContext,
                            body: dict) -> tuple[int, dict]:
    """POST /v1/admin/passkey/callback — broker delivers a ceremony
    outcome. Validates origin via mTLS upstream (Apache2 or the
    Flask server's TLS handler). Body shape comes from
    mssh_passkey/callback.py."""
    # §4.3.6 admin endpoint; §4.3.8 admin-2FA ceremony complete;
    # consumes §3.6 broker outcome, persists evidence per §13.5
    ceremony_id = body.get('ceremony_id') or ''
    outcome = body.get('outcome') or ''
    response_json = body.get('response_json')

    if not ceremony_id or outcome not in ('approved', 'denied', 'expired', 'cancelled'):
        return _err(400, 'bad_request', 'bad callback body')

    # Registration?
    if (pending := ctx.passkey_pending_registrations.pop(ceremony_id, None)):
        flow = pending.get('flow', 'admin')
        target_str = (pending.get('admin_name')
                      if flow == 'admin'
                      else f'{pending.get("tool_name")}/{pending.get("user_id")}')
        if outcome != 'approved':
            ctx.audit.write({
                'timestamp': _now_iso(),
                'type': 'admin',
                'action': f'{flow}.passkey.register-failed',
                'admin': {'name': '<broker>',
                          'role': 'broker',
                          'mtls_subject': '<broker>'},
                'target': {'target': target_str,
                           'ceremony_id': ceremony_id,
                           'outcome': outcome},
                'result': 'failed',
            })
            _maybe_post_external_outcome(ctx, pending, outcome, None)
            return 200, {'status': 'ok', 'outcome': outcome}
        from . import passkey as _pk
        challenge = _pk.RegistrationChallenge(
            challenge_bytes=pending['challenge'],
            rp_id=pending['rp_id'],
            expected_origin=pending['expected_origin'],
            user_id=target_str,
            aaguid_allowlist=pending['allowlist'],
        )
        try:
            cred = _pk.verify_registration(
                response_json=response_json or '',
                challenge=challenge,
            )
        except ValueError as e:
            ctx.audit.write({
                'timestamp': _now_iso(),
                'type': 'admin',
                'action': f'{flow}.passkey.register-rejected',
                'admin': {'name': '<broker>', 'role': 'broker',
                          'mtls_subject': '<broker>'},
                'target': {'target': target_str,
                           'ceremony_id': ceremony_id,
                           'error': str(e)},
                'result': 'rejected',
            })
            return _err(400, 'verification_failed', str(e))

        cred.label = pending.get('label') or ''
        cred.enrolled_by = '<broker callback>'

        if flow == 'admin':
            try:
                ctx.enrollment.add_admin_passkey(pending['admin_name'], cred)
            except EnrollmentError as e:
                return _err(409, 'conflict', str(e))
        else:  # external-tool
            try:
                ctx.enrollment.add_external_tool_user_passkey(
                    pending['tool_name'], pending['user_id'], cred)
            except EnrollmentError as e:
                return _err(409, 'conflict', str(e))

        ctx.audit.write({
            'timestamp': _now_iso(),
            'type': 'admin',
            'action': f'{flow}.passkey.register-complete',
            'admin': {'name': '<broker>', 'role': 'broker',
                      'mtls_subject': '<broker>'},
            'target': {'target': target_str,
                       'credential_id': cred.credential_id,
                       'aaguid': cred.aaguid},
            'result': 'ok',
        })
        _maybe_post_external_outcome(ctx, pending, 'approved',
                                       {'credential_id': cred.credential_id})
        return 200, {'status': 'ok',
                     'target': target_str,
                     'credential_id': cred.credential_id}

    # Authentication?
    if (pending := ctx.passkey_pending_authentications.pop(ceremony_id, None)):
        flow = pending.get('flow', 'admin')
        target_str = (pending.get('admin_name')
                      if flow == 'admin'
                      else f'{pending.get("tool_name")}/{pending.get("user_id")}')
        if outcome != 'approved':
            ctx.audit.write({
                'timestamp': _now_iso(),
                'type': 'admin',
                'action': f'{flow}.passkey.2fa-failed',
                'admin': {'name': '<broker>', 'role': 'broker',
                          'mtls_subject': '<broker>'},
                'target': {'target': target_str,
                           'ceremony_id': ceremony_id,
                           'outcome': outcome},
                'result': 'failed',
            })
            _maybe_post_external_outcome(ctx, pending, outcome, None)
            return 200, {'status': 'ok', 'outcome': outcome}
        from . import passkey as _pk

        # Look up the credential set + sign-count-updater function
        # based on which flow this is.
        if flow == 'admin':
            target_rec = ctx.enrollment.admins.get(pending['admin_name'])
            if not target_rec:
                return _err(404, 'not_found',
                            f'admin {pending["admin_name"]} no longer enrolled')
            creds = target_rec.passkey_credentials
            def update_count(cid, new_count):
                ctx.enrollment.update_admin_passkey_sign_count(
                    pending['admin_name'], cid, new_count)
        else:  # external-tool
            tool = ctx.enrollment.external_tools.get(pending['tool_name'])
            if not tool:
                return _err(404, 'not_found',
                            f'tool {pending["tool_name"]} no longer enrolled')
            creds = tool.user_credentials.get(pending['user_id'], [])
            def update_count(cid, new_count):
                ctx.enrollment.update_external_tool_user_passkey_sign_count(
                    pending['tool_name'], pending['user_id'], cid, new_count)

        creds_by_id = {c.credential_id: c for c in creds if not c.revoked_at}
        challenge = _pk.AuthenticationChallenge(
            challenge_bytes=pending['challenge'],
            rp_id=pending['rp_id'],
            expected_origin=pending['expected_origin'],
            user_id=target_str,
            credentials_by_id=creds_by_id,
        )
        try:
            res = _pk.verify_authentication(
                response_json=response_json or '',
                challenge=challenge,
            )
        except ValueError as e:
            return _err(400, 'verification_failed', str(e))

        update_count(res.credential_id, res.new_sign_count)

        if flow == 'admin':
            ctx.passkey_2fa_cache[pending['admin_name']] = _now_iso()

        ctx.audit.write({
            'timestamp': _now_iso(),
            'type': 'admin',
            'action': f'{flow}.passkey.2fa-success',
            'admin': {'name': '<broker>', 'role': 'broker',
                      'mtls_subject': '<broker>'},
            'target': {'target': target_str,
                       'credential_id': res.credential_id},
            'result': 'ok',
        })
        _maybe_post_external_outcome(ctx, pending, 'approved',
                                       {'credential_id': res.credential_id})
        return 200, {'status': 'ok',
                     'target': target_str,
                     'credential_id': res.credential_id}

    return _err(404, 'not_found',
                f'no pending ceremony {ceremony_id}')


def _maybe_post_external_outcome(ctx: AdminContext, pending: dict,
                                   outcome: str,
                                   extra: dict | None) -> None:
    """Second-hop callback delivery to the external tool's outcome_url.

    Best-effort; failures are logged but not raised. The tool can
    also poll /v1/external/passkey/status/<ceremony_id> as a backup.
    Only fires for flow='external-tool'.
    """
    if pending.get('flow') != 'external-tool':
        return
    outcome_url = pending.get('outcome_url') or ''
    if not outcome_url:
        return

    import requests
    payload = {
        'ceremony_id': '<unknown>',     # not present in pending; filled by caller if needed
        'tool': pending.get('tool_name'),
        'user_id': pending.get('user_id'),
        'outcome': outcome,
        'verified': outcome == 'approved',
        **(extra or {}),
    }
    try:
        requests.post(
            outcome_url,
            json=payload,
            # Use the same callback-client cert/key/CA the broker uses
            # to talk to mssh-ca; reuse the connection pool.
            cert=((ctx.passkey_broker.client_cert,
                   ctx.passkey_broker.client_key)
                  if ctx.passkey_broker and ctx.passkey_broker.client_cert
                  else None),
            verify=(ctx.passkey_broker.ca_cert
                    if ctx.passkey_broker else True),
            timeout=10.0,
        )
    except Exception as e:
        ctx.audit.write({
            'timestamp': _now_iso(),
            'type': 'admin',
            'action': 'external-tool.outcome-delivery-failed',
            'admin': {'name': '<ca>', 'role': 'broker',
                      'mtls_subject': '<ca>'},
            'target': {'tool': pending.get('tool_name'),
                       'user_id': pending.get('user_id'),
                       'outcome_url': outcome_url,
                       'error': str(e)},
            'result': 'failed',
        })


def passkey_admin_challenge(ctx: AdminContext, admin: Admin) -> tuple[int, dict]:
    """Internal helper called from the policy-enforcement layer when an
    admin needs to satisfy a 2FA requirement. Builds an
    authentication ceremony for ``admin`` against their registered
    credentials and returns the qr_url + ceremony_id.

    Surfaced as a 202 Accepted from the admin endpoint that triggered
    it (see passkey_2fa_interrupt below)."""
    broker, err = _passkey_or_503(ctx)
    if err:
        return err

    target_rec = ctx.enrollment.admins.get(admin.name)
    if not target_rec or not [c for c in target_rec.passkey_credentials
                              if not c.revoked_at]:
        return _err(403, 'forbidden',
                    f'admin {admin.name!r} has no active passkey '
                    f'credentials; cannot satisfy 2FA')

    from . import passkey as _pk
    cred_ids = [c.credential_id for c in target_rec.passkey_credentials
                if not c.revoked_at]
    options_json, challenge = _pk.generate_authentication_options(
        rp_id=ctx.passkey_rp_id,
        allow_credential_ids=cred_ids,
    )

    try:
        ceremony = broker.create_ceremony(
            ceremony_type='approve',
            options_json=options_json,
            description=f'2FA approval for admin {admin.name!r}',
            callback_url=ctx.passkey_callback_url,
            ttl_seconds=300,
        )
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')

    ctx.passkey_pending_authentications[ceremony.ceremony_id] = {
        'flow': 'admin',
        'admin_name': admin.name,
        'challenge': challenge,
        'rp_id': ctx.passkey_rp_id,
        'expected_origin': ctx.passkey_expected_origin,
    }
    return 202, {
        'status': 'pending_2fa',
        'reason': 'passkey_required',
        'ceremony_id': ceremony.ceremony_id,
        'url': ceremony.url,
        'expires_at': ceremony.expires_at,
    }


def passkey_check_2fa(ctx: AdminContext, admin: Admin,
                      policy: 'Policy') -> tuple[int, dict] | None:
    """Returns (status, body) — typically a 202 challenge — if the
    admin must complete a 2FA ceremony before the operation can
    proceed. Returns None if the cache is fresh or no 2FA required.

    Callers chain this in front of the actual operation."""
    if policy is None or policy.require_2fa == 'none':
        return None
    if policy.require_2fa != 'passkey':
        return _err(500, 'internal',
                    f'unknown require_2fa: {policy.require_2fa!r}')
    if ctx.passkey_broker is None:
        return _err(503, 'unavailable',
                    'policy requires passkey 2FA but the broker is not '
                    'configured on this CA')
    last = ctx.passkey_2fa_cache.get(admin.name)
    if last:
        try:
            last_dt = _dt.datetime.strptime(
                last, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            last_dt = None
        if last_dt:
            age = (_dt.datetime.now(_dt.timezone.utc) - last_dt).total_seconds()
            if age <= policy.twofa_within_seconds:
                return None
    # Cache miss → issue a challenge.
    return passkey_admin_challenge(ctx, admin)


def admin_check_2fa(ctx: AdminContext, admin: Admin,
                    action: str) -> tuple[int, dict] | None:
    """Gate `action` per the CA-config protected-action list.

    Returns the same shape as `passkey_check_2fa`: a (status, body) tuple
    when 2FA is required (typically 202 with a ceremony URL, or 403/503),
    or None when the admin may proceed.

    Callers chain this in front of the actual operation after role-check:

        if (err := _check('cert.revoke', admin)): return err
        if (err := admin_check_2fa(ctx, admin, 'cert.revoke')): return err
        # ... actual work ...
    """
    if action not in ctx.admin_2fa_protected_actions:
        return None
    pseudo_policy = Policy(
        id=f'admin-2fa:{action}',
        require_2fa='passkey',
        twofa_within_seconds=ctx.admin_2fa_within_seconds,
    )
    return passkey_check_2fa(ctx, admin, pseudo_policy)


def passkey_poll_outcome(ctx: AdminContext,
                          ceremony_id: str) -> tuple[int, dict]:
    """GET /v1/admin/passkey/ceremony/<id> — clients poll while
    waiting for the user to approve. Returns 202 while pending,
    200 with terminal outcome when resolved."""
    broker, err = _passkey_or_503(ctx)
    if err:
        return err
    # Fast path: have we recorded a verified success in the cache or
    # rejected the ceremony? Walk our local pending maps + we either
    # popped the entry (terminal) or it's still pending.
    if ceremony_id in ctx.passkey_pending_authentications:
        # Still pending — poll the broker for latest status.
        pass
    if ceremony_id in ctx.passkey_pending_registrations:
        pass
    try:
        status = broker.get_ceremony(ceremony_id)
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')
    if status.outcome is None:
        return 202, {'status': 'pending', 'ceremony_id': ceremony_id}
    return 200, {
        'status': 'ok',
        'ceremony_id': ceremony_id,
        'outcome': status.outcome,
        'consumed_at': status.consumed_at,
    }


# ---------------------------------------------------------------------------
# External-tool RP service (design/ca-integration.md § Passkey RP service)
# ---------------------------------------------------------------------------

# Permission entries for external-tool admin CRUD. Tool-side endpoints
# (challenge, status, revoke) authenticate by the tool's own mTLS CN
# rather than by admin role.
_PERMISSIONS['external_tool.add'] = {'superuser'}
_PERMISSIONS['external_tool.remove'] = {'superuser'}
_PERMISSIONS['external_tool.list'] = {'superuser', 'auditor'}


def external_tool_add(ctx: AdminContext, admin: Admin,
                       body: dict) -> tuple[int, dict]:
    """POST /v1/admin/external-tool/add — enroll a new external tool.

    Body: {name, rp_id, outcome_url_prefix}. Mints an mTLS client
    cert (signed by the CA's existing TLS hierarchy, same as admin
    enrollment) for the tool to present when calling /v1/external/
    endpoints.
    """
    if (err := _check('external_tool.add', admin)):
        return err

    name = (body.get('name') or '').strip()
    rp_id = (body.get('rp_id') or '').strip()
    prefix = (body.get('outcome_url_prefix') or '').strip()
    if not name or not rp_id or not prefix:
        return _err(400, 'bad_request',
                    'name, rp_id, and outcome_url_prefix all required')
    if not prefix.startswith('https://'):
        return _err(400, 'bad_request',
                    'outcome_url_prefix must be https://')

    mtls_subject = f'CN=external-tool:{name}'
    try:
        cert_bundle = cert_minter.issue_client_cert(
            common_name=f'external-tool:{name}',
            tls_ca_key=ctx.tls_ca_key,
            tls_ca_cert=ctx.tls_ca_cert,
            validity_days=ctx.admin_cert_validity_days,
            key_type=ctx.mtls_key_type,
            crl_url=ctx.crl_url,
            kind='client-mtls',
        )
        tool = ctx.enrollment.add_external_tool(
            name=name, mtls_subject=mtls_subject,
            rp_id=rp_id, outcome_url_prefix=prefix,
            enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    except Exception as e:
        return _err(500, 'internal', f'cert issuance failed: {e}')

    _audit_admin(ctx, admin, 'external_tool.add',
                 {'name': name, 'rp_id': rp_id,
                  'outcome_url_prefix': prefix}, 'ok')
    return 201, {
        'status': 'ok',
        'tool': {
            'name': tool.name, 'rp_id': tool.rp_id,
            'outcome_url_prefix': tool.outcome_url_prefix,
            'mtls_subject': tool.mtls_subject,
            'enrolled_at': tool.enrolled_at,
        },
        'credentials': {
            'cert_pem': cert_bundle.cert_pem.decode('ascii'),
            'key_pem': cert_bundle.key_pem.decode('ascii'),
            'ca_cert_pem': cert_bundle.ca_cert_pem.decode('ascii'),
        },
    }


def external_tool_remove(ctx: AdminContext, admin: Admin,
                          name: str) -> tuple[int, dict]:
    if (err := _check('external_tool.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_external_tool(name)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'external_tool.remove', {'name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def external_tool_list(ctx: AdminContext, admin: Admin) -> tuple[int, dict]:
    if (err := _check('external_tool.list', admin)):
        return err
    return 200, {
        'status': 'ok',
        'tools': [
            {'name': t.name, 'rp_id': t.rp_id,
             'outcome_url_prefix': t.outcome_url_prefix,
             'mtls_subject': t.mtls_subject,
             'enrolled_at': t.enrolled_at,
             'user_count': len(t.user_credentials)}
            for t in ctx.enrollment.external_tools.values()
        ],
    }


# ---- Tool-side endpoints (authenticated by tool's mTLS CN, not admin) -----

def _tool_or_401(ctx: AdminContext, mtls_subject: str):
    """Resolve the calling tool from its mTLS subject. Returns
    (tool, None) on success or (None, err) on 401."""
    tool = ctx.enrollment.find_external_tool_by_mtls_subject(mtls_subject)
    if tool is None:
        return None, _err(401, 'unauthorized',
                           f'external tool not enrolled '
                           f'(subject {mtls_subject!r})')
    return tool, None


def external_tool_passkey_enroll_begin(ctx: AdminContext,
                                         calling_subject: str,
                                         body: dict) -> tuple[int, dict]:
    """POST /v1/external/passkey/enroll-begin — tool requests a
    registration ceremony for one of its users.

    Body: {user_id, display_name?, ttl_seconds?}.
    """
    tool, err = _tool_or_401(ctx, calling_subject)
    if err:
        return err
    broker, err = _passkey_or_503(ctx)
    if err:
        return err

    user_id = (body.get('user_id') or '').strip()
    if not user_id:
        return _err(400, 'bad_request', 'user_id required')
    display_name = body.get('display_name') or user_id

    from . import passkey as _pk
    exclude_creds = [c.credential_id
                     for c in tool.user_credentials.get(user_id, [])
                     if not c.revoked_at]
    options_json, challenge = _pk.generate_registration_options(
        rp_id=tool.rp_id,
        rp_name=f'mssh-ca external tool: {tool.name}',
        user_id=f'{tool.name}:{user_id}',
        display_name=display_name,
        exclude_credential_ids=exclude_creds or None,
    )

    try:
        ceremony = broker.create_ceremony(
            ceremony_type='register',
            options_json=options_json,
            description=f'Register a new passkey for {tool.name}/{user_id}',
            display_name=display_name,
            callback_url=ctx.passkey_callback_url,
            ttl_seconds=int(body.get('ttl_seconds') or 300),
        )
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')

    ctx.passkey_pending_registrations[ceremony.ceremony_id] = {
        'flow': 'external-tool',
        'tool_name': tool.name,
        'user_id': user_id,
        'rp_id': tool.rp_id,
        'expected_origin': ctx.passkey_expected_origin,
        'challenge': challenge,
        'allowlist': ctx.passkey_aaguid_allowlist,
        'outcome_url': body.get('outcome_url') or '',
    }
    return 201, {
        'status': 'ok',
        'ceremony_id': ceremony.ceremony_id,
        'url': ceremony.url,
        'expires_at': ceremony.expires_at,
    }


def external_tool_passkey_challenge(ctx: AdminContext,
                                      calling_subject: str,
                                      body: dict) -> tuple[int, dict]:
    """POST /v1/external/passkey/challenge — tool requests an approval
    ceremony for one of its users.

    Body: {user_id, description, outcome_url, ttl_seconds?}.

    outcome_url must start with the tool's enrolled outcome_url_prefix
    — guards against a compromised tool cert delivering outcomes to
    arbitrary URLs.
    """
    tool, err = _tool_or_401(ctx, calling_subject)
    if err:
        return err
    broker, err = _passkey_or_503(ctx)
    if err:
        return err

    user_id = (body.get('user_id') or '').strip()
    description = (body.get('description') or '').strip()
    outcome_url = (body.get('outcome_url') or '').strip()
    if not user_id or not description or not outcome_url:
        return _err(400, 'bad_request',
                    'user_id, description, outcome_url required')
    if not outcome_url.startswith(tool.outcome_url_prefix):
        return _err(400, 'bad_request',
                    f'outcome_url must start with '
                    f'{tool.outcome_url_prefix!r}')

    creds = [c for c in tool.user_credentials.get(user_id, [])
             if not c.revoked_at]
    if not creds:
        return _err(404, 'not_found',
                     f'no active passkey credentials for '
                     f'{tool.name}/{user_id}')

    from . import passkey as _pk
    options_json, challenge = _pk.generate_authentication_options(
        rp_id=tool.rp_id,
        allow_credential_ids=[c.credential_id for c in creds],
    )

    try:
        ceremony = broker.create_ceremony(
            ceremony_type='approve',
            options_json=options_json,
            description=description,
            display_name=user_id,
            callback_url=ctx.passkey_callback_url,
            ttl_seconds=int(body.get('ttl_seconds') or 300),
        )
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')

    ctx.passkey_pending_authentications[ceremony.ceremony_id] = {
        'flow': 'external-tool',
        'tool_name': tool.name,
        'user_id': user_id,
        'rp_id': tool.rp_id,
        'expected_origin': ctx.passkey_expected_origin,
        'challenge': challenge,
        'outcome_url': outcome_url,
    }
    return 201, {
        'status': 'ok',
        'ceremony_id': ceremony.ceremony_id,
        'url': ceremony.url,
        'expires_at': ceremony.expires_at,
    }


def external_tool_passkey_revoke(ctx: AdminContext,
                                   calling_subject: str,
                                   user_id: str,
                                   credential_id: str) -> tuple[int, dict]:
    tool, err = _tool_or_401(ctx, calling_subject)
    if err:
        return err
    try:
        ctx.enrollment.revoke_external_tool_user_passkey(
            tool.name, user_id, credential_id)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    return 200, {'status': 'ok',
                  'tool': tool.name,
                  'user_id': user_id,
                  'revoked': credential_id}


def external_tool_passkey_status(ctx: AdminContext,
                                   calling_subject: str,
                                   ceremony_id: str) -> tuple[int, dict]:
    """Tool polls for ceremony status. Auth-checked against the
    tool's mTLS subject; restricted to ceremonies the tool started."""
    tool, err = _tool_or_401(ctx, calling_subject)
    if err:
        return err
    broker, err = _passkey_or_503(ctx)
    if err:
        return err
    # Sanity-check the ceremony belongs to the calling tool. We look
    # in both pending maps + the completed-but-cached one isn't tracked
    # here — but if the ceremony has been consumed, we err on the side
    # of "not found" to avoid disclosure across tools.
    pending = (ctx.passkey_pending_registrations.get(ceremony_id)
               or ctx.passkey_pending_authentications.get(ceremony_id))
    if pending and pending.get('tool_name') != tool.name:
        return _err(404, 'not_found',
                    f'no ceremony {ceremony_id}')
    try:
        status = broker.get_ceremony(ceremony_id)
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')
    return 200, {
        'status': 'ok',
        'ceremony_id': ceremony_id,
        'outcome': status.outcome,
        'consumed_at': status.consumed_at,
    }


# R-4: external-tool ceremony cancel route (§14.1.3). Tool cancels its
# own pending ceremony — used when the operator/user backs out before
# completing the WebAuthn flow. Implemented as a DELETE on the broker
# (which then sends an outcome callback to the tool's outcome_url).
def external_tool_passkey_cancel(ctx: AdminContext,
                                   calling_subject: str,
                                   ceremony_id: str) -> tuple[int, dict]:
    """Tool cancels a pending ceremony it owns.

    Per-tool isolation: ceremonies owned by another tool return 404,
    not 403, to keep ceremony existence opaque across tools.
    """
    # §4.3.9 / §3.5 — external-tool passkey cancel
    tool, err = _tool_or_401(ctx, calling_subject)
    if err:
        return err
    broker, err = _passkey_or_503(ctx)
    if err:
        return err
    pending = (ctx.passkey_pending_registrations.get(ceremony_id)
               or ctx.passkey_pending_authentications.get(ceremony_id))
    if pending is None or pending.get('tool_name') != tool.name:
        return _err(404, 'not_found',
                    f'no ceremony {ceremony_id}')
    try:
        broker.cancel_ceremony(ceremony_id)
    except Exception as e:
        return _err(502, 'broker_error', f'mssh-passkey: {e}')
    # Drop the pending record so a re-poll returns 404 immediately.
    ctx.passkey_pending_registrations.pop(ceremony_id, None)
    ctx.passkey_pending_authentications.pop(ceremony_id, None)
    return 200, {
        'status': 'ok',
        'result': 'ok',                                # R-3 canonical
        'ceremony_id': ceremony_id,
        'outcome': 'cancelled',
    }


# Callback fan-out for external-tool flow.
# When the broker callback arrives at passkey_admin_callback() and
# the pending entry has flow='external-tool', we still verify the
# WebAuthn response (mssh-ca holds the credential) — and then deliver
# a SECOND callback to the external tool's outcome_url. That second
# delivery is done by the existing mssh_passkey.callback worker on
# the broker side... wait no, the broker doesn't know about the
# external tool. The two-hop is mssh-ca's responsibility.
#
# Architecturally: when callback arrives, if flow='external-tool',
# instead of verifying-and-storing-locally, we verify, store the
# credential (for register) or update sign_count (for authenticate),
# THEN POST to the tool's outcome_url with the verified outcome.
# That outbound POST uses the same callback client cert mssh-ca
# already configured.
#
# Implementing that fan-out happens in the next phase to keep this
# commit focused. For now, an external-tool callback verifies and
# stores correctly; the tool polls via /v1/external/passkey/status
# until the outcome arrives.


# ---------------------------------------------------------------------------
# §4.3.10 + §13.4: cert renewal (auto-renew for any CA-issued cert)
# ---------------------------------------------------------------------------
#
# Wire shape: POST /v1/cert/renew. The caller authenticates with the
# CERT BEING RENEWED as the mTLS client cert; the CA validates the
# chain at the TLS layer (so we already issued it), checks the CRL,
# enforces the renewable window, and re-mints with the same CN/SAN/
# EKU.
#
# The endpoint is NOT under /v1/admin/ because the auth model is
# "cert is its own credential", not "admin role check". A separate
# handler entry point + a separate Flask route.

# Default renewal-window knobs. Operators override via ca-config.yaml's
# cert_renewal section. Sensible defaults match the per-type cert
# validity choices: 90-day TLS leafs let services renew within the
# last month.
_DEFAULT_RENEWAL_WINDOW_DAYS = 30   # how far before expiry we accept
_DEFAULT_GRACE_PERIOD_DAYS    = 7   # how far past expiry we accept


def cert_renew(ctx: AdminContext, presented_cert,
               body: dict) -> tuple[int, dict]:
    """Renew a cert that's authenticating this request.

    ``presented_cert`` is the x509.Certificate the caller offered as
    its mTLS client cert. ``body`` carries optional knobs:
      - revoke_predecessor: bool (default False) — also append the
        old cert's serial to the CRL.

    The renewable predicate is evaluated against the presented
    cert's not_after — independent of what body asks for.

    Returns 200 with the new cert+key bundle, or 410 if the cert
    is outside the renewable window, 403 if it's revoked, 502 if
    the underlying mint fails.
    """
    if presented_cert is None:
        return _err(401, 'unauthorized',
                    'no mTLS client cert presented; cert is its own credential')

    # 1. Revocation check. If the cert's serial is in ANY issuer's
    # CRL, refuse. Per-issuer CRLs since v0.2.2 — we don't know which
    # intermediate signed this leaf yet (chain validation lands in
    # Commit 4), so check all of them.
    serial_hex = format(presented_cert.serial_number, 'x')
    if ctx.crl is not None:
        revoked_match = False
        for issuer in ctx.crl.known_issuers() or ['user-mint']:
            for entry in ctx.crl.fetch_after(issuer, 0):
                if serial_hex in (s.lower() for s in entry.serials):
                    revoked_match = True
                    break
            if revoked_match:
                break
        if revoked_match:
            ctx.audit.write({
                'timestamp': _now_iso(),
                'type': 'admin',
                'action': 'cert.renew.refused',
                'admin': {'name': '<cert>', 'role': 'cert',
                          'mtls_subject': '<presented>'},
                'target': {'serial': serial_hex,
                           'reason': 'revoked'},
                'result': 'refused',
            })
            return _err(403, 'revoked',
                         f'cert {serial_hex} is revoked')

    # 2. Window check.
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    not_after = presented_cert.not_valid_after_utc
    # Some cryptography versions don't have not_valid_after_utc; fall back.
    if getattr(not_after, 'tzinfo', None) is None:
        not_after = not_after.replace(tzinfo=_dt.timezone.utc)

    seconds_to_expiry = (not_after - now).total_seconds()
    window_days = _DEFAULT_RENEWAL_WINDOW_DAYS
    grace_days = _DEFAULT_GRACE_PERIOD_DAYS

    if seconds_to_expiry > window_days * 86400:
        # Too early to renew. Not an error — 304 Not Modified so the
        # CLI can exit 0 (nothing to do).
        return 304, {
            'status': 'too_early',
            'detail': (f'cert not_after is {not_after.isoformat()}; '
                       f'{int(seconds_to_expiry / 86400)} days from now '
                       f'(threshold {window_days})'),
            'seconds_to_expiry': int(seconds_to_expiry),
        }
    if seconds_to_expiry < -(grace_days * 86400):
        # Too late — past grace period.
        ctx.audit.write({
            'timestamp': _now_iso(),
            'type': 'admin',
            'action': 'cert.renew.refused',
            'admin': {'name': '<cert>', 'role': 'cert',
                      'mtls_subject': '<presented>'},
            'target': {'serial': serial_hex,
                       'not_after': not_after.isoformat(),
                       'reason': 'past_grace_period'},
            'result': 'refused',
        })
        return _err(410, 'past_grace',
                     f'cert expired more than {grace_days} days ago '
                     f'(not_after={not_after.isoformat()}); operator '
                     f'must re-mint via mssh-admin cert mint')

    # 3. Extract identity bits from the presented cert.
    subject_cn = None
    for attr in presented_cert.subject:
        if attr.oid == oid.NameOID.COMMON_NAME:
            subject_cn = attr.value
            break
    if not subject_cn:
        return _err(400, 'bad_cert', 'presented cert has no CN')

    # SANs (DNS + IP), preserved verbatim on renewal.
    sans: list[str] = []
    try:
        san_ext = presented_cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for entry in san_ext:
            if isinstance(entry, x509.DNSName):
                sans.append(f'DNS:{entry.value}')
            elif isinstance(entry, x509.IPAddress):
                sans.append(f'IP:{entry.value}')
    except x509.ExtensionNotFound:
        pass

    # EKU determines which cert_minter helper to call.
    eku_usages = set()
    try:
        eku_ext = presented_cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        for usage in eku_ext:
            eku_usages.add(usage.dotted_string)
    except x509.ExtensionNotFound:
        pass

    is_server = oid.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in eku_usages
    is_client = oid.ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string in eku_usages
    is_codesign = oid.ExtendedKeyUsageOID.CODE_SIGNING.dotted_string in eku_usages

    # Validity: the new cert gets the same lifetime the original was
    # minted with. Compute from the original cert's not_before.
    not_before = presented_cert.not_valid_before_utc
    if getattr(not_before, 'tzinfo', None) is None:
        not_before = not_before.replace(tzinfo=_dt.timezone.utc)
    original_validity = (not_after - not_before).total_seconds()
    validity_days = max(1, int(round(original_validity / 86400)))

    # 4. Mint the new leaf via the same helper that issued it.
    # §15.23 — the kind is inferred from the inbound cert's EKU so
    # the renewed cert carries the same kind marker as the original.
    # An explicit kind-drift check (rejecting renewal that would
    # change kind) is a v0.6 follow-up — left out here so v0.4.x
    # certs without markers don't break renewal.
    try:
        if is_server:
            bundle = cert_minter.issue_server_cert(
                subject_cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=validity_days,
                key_type=ctx.mtls_key_type,
                sans=sans or None,
                crl_url=ctx.crl_url)
        elif is_codesign:
            bundle = cert_minter.issue_codesign_cert(
                subject_cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=validity_days,
                key_type=ctx.mtls_key_type)
        elif is_client or not eku_usages:
            # Default-and-fallback: a cert with clientAuth or with no
            # EKU is treated as client (matches admin / server-mTLS /
            # https-user shape).
            bundle = cert_minter.issue_client_cert(
                subject_cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=validity_days,
                key_type=ctx.mtls_key_type,
                crl_url=ctx.crl_url,
                kind='client-mtls')
        else:
            return _err(400, 'unsupported_eku',
                         f'cannot renew cert with EKUs {sorted(eku_usages)}; '
                         f'use mssh-admin cert mint instead')
    except Exception as e:
        return _err(502, 'mint_failed', f'cert issuance failed: {e}')

    # 5. Optionally revoke the predecessor.
    revoked_old = False
    if body and body.get('revoke_predecessor'):
        if ctx.crl is None:
            return _err(503, 'unavailable',
                         'revoke_predecessor requested but CRL not configured')
        try:
            # TODO: resolve issuer from cert chain. Defaults to
            # user-mint matching v0.2.0 single-signer behavior;
            # proper resolution waits on Commit 4's chain validation.
            ctx.crl.append('user-mint', [serial_hex],
                            revoked_by='<cert.renew>',
                            reason='renewed')
            revoked_old = True
        except Exception as e:
            log.warning('cert.renew: revoke_predecessor failed: %s', e)

    ctx.audit.write({
        'timestamp': _now_iso(),
        'type': 'admin',
        'action': 'cert.renew.complete',
        'admin': {'name': '<cert>', 'role': 'cert',
                  'mtls_subject': f'CN={subject_cn}'},
        'target': {'old_serial': serial_hex,
                   'cn': subject_cn,
                   'sans': sans,
                   'validity_days': validity_days,
                   'revoked_predecessor': revoked_old},
        'result': 'ok',
    })

    return 200, {
        'status': 'ok',
        'cert': {
            'subject_cn': subject_cn,
            'sans': sans,
            'validity_days': validity_days,
            'old_serial': serial_hex,
            'revoked_predecessor': revoked_old,
        },
        'credentials': {
            'cert_pem': bundle.cert_pem.decode('ascii'),
            'key_pem': bundle.key_pem.decode('ascii'),
            'ca_cert_pem': bundle.ca_cert_pem.decode('ascii'),
        },
    }
