"""Admin API handlers.

Role-permission table mirrors mssh-detailed-rest-api.md. Each handler
takes a parsed request body, the admin's enrollment record, and the
``AdminContext``; returns ``(http_status, json_body)``.
"""
from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass
from typing import Any, Callable

from . import cert_minter
from . import templates as _templates
from .audit import AuditLog
from .enrollment import Admin, Enrollment, EnrollmentError, KeyBinding
from ..identity import (CertIdentity, IdentityParseError, PubkeyIdentity,
                              parse_identity)
from .render import TemplateError, validate_template


# Role permissions: maps action key -> set of allowed roles.
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
    'openvpn.issue':    {'superuser'},
}


def role_permits(role: str, action: str) -> bool:
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


def _check(action: str, admin: Admin) -> tuple[int, dict] | None:
    if not role_permits(admin.role, action):
        return _forbidden(action, admin)
    return None


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
    """Append a CRL entry revoking the given cert serial(s).

    Body:
        {
          "serials": ["abc123", "def456"],   // required, lowercase hex
          "reason":  "operator decision"      // optional
        }

    Every msshd in the fleet picks this up on its next authorize call
    (the response carries the new ``current_crl_seq``; msshd fetches
    the missing CRLs and applies them to its authz cache).
    """
    if (err := _check('cert.revoke', admin)):
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

    try:
        entry = ctx.crl.append(cleaned, revoked_by=admin.name, reason=reason)
    except OSError as e:
        return _err(500, 'internal', f'CRL append failed: {e}')

    _audit_admin(ctx, admin, 'cert.revoke',
                 {'serials': cleaned, 'seq': entry.seq, 'reason': reason},
                 'ok')

    return 201, {
        'status': 'ok',
        'seq': entry.seq,
        'revoked_at': entry.revoked_at,
        'serials': cleaned,
    }


def crl_fetch(ctx: AdminContext, admin: Admin,
              after: int, limit: int | None) -> tuple[int, dict]:
    """Return CRL entries with seq > ``after``, optionally bounded
    by ``limit``. Operator-callable for diagnostic visibility; the
    msshd hot path uses the un-authenticated ``GET /v1/crl`` mirror.
    """
    if (err := _check('crl.read', admin)):
        return err
    if ctx.crl is None:
        return _err(500, 'internal', 'CRL store not configured')
    entries = ctx.crl.fetch_after(int(after or 0), limit=limit)
    return 200, {
        'status': 'ok',
        'current_seq': ctx.crl.current_seq(),
        'entries': [e.to_dict() for e in entries],
    }


# ---------------------------------------------------------------------------
# §5: cert minting for other applications
# ---------------------------------------------------------------------------

_CERT_TYPES = ('tls-server', 'https-user', 'code-sign')

# Default per-type validity (days). Operators can override per-call via
# body['validity_days']; the validity cap below is the hard upper bound.
_CERT_DEFAULT_VALIDITY = {
    'tls-server': 90,
    'https-user': 90,
    'code-sign':  365,
    'openvpn':    90,
}
_CERT_MAX_VALIDITY = 825   # CAB-forum-style max for TLS server certs;
                            # we apply it uniformly for simplicity.


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


def _validity_or_default(body: dict, kind: str) -> tuple[int, dict | None]:
    """Resolve validity_days from body with default + cap. Returns
    ``(days, err_payload)`` — err_payload is None on success."""
    raw = body.get('validity_days')
    if raw is None:
        return _CERT_DEFAULT_VALIDITY[kind], None
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return 0, _err(400, 'bad_request',
                       f'validity_days must be an integer, got {raw!r}')[1]
    if days < 1:
        return 0, _err(400, 'bad_request',
                       f'validity_days must be >= 1, got {days}')[1]
    if days > _CERT_MAX_VALIDITY:
        return 0, _err(400, 'bad_request',
                       f'validity_days={days} exceeds cap {_CERT_MAX_VALIDITY}')[1]
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

    days, err = _validity_or_default(body, cert_type)
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
                sans=sans or None)
        elif cert_type == 'https-user':
            bundle = cert_minter.issue_client_cert(
                cn, ctx.tls_ca_key, ctx.tls_ca_cert,
                validity_days=days, key_type=ctx.mtls_key_type)
        else:  # code-sign
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

    days, err = _validity_or_default(body, 'openvpn')
    if err:
        return 400, err

    try:
        bundle = cert_minter.issue_client_cert(
            cn, ctx.tls_ca_key, ctx.tls_ca_cert,
            validity_days=days, key_type=ctx.mtls_key_type)
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
