"""POST /v1/authorize handler.

Pulls together identity parsing, policy evaluation, cert minting, audit logging.
The Flask layer in ``server.py`` wires this to HTTP; this module is pure logic.
"""
from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization

from .. import PROTOCOL_VERSION
from . import render as _render
from . import templates as _templates
from .audit import AuditLog
from .cert_minter import mint_authorization_cert
from .enrollment import Enrollment
from .identity_parser import (CertIdentity, IdentityParseError, PubkeyIdentity,
                              parse_identity)
from .policy import evaluate


@dataclass
class AuthorizeContext:
    enrollment: Enrollment
    audit: AuditLog
    signing_key: Any
    signing_cert: Any
    identity_trust_root_fingerprints: set[str]   # SHA256 of trusted user-CA pubkey blobs
    default_max_cert_validity_seconds: int = 3600
    timestamp_drift_seconds: int = 60


def _now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _parse_iso8601(ts: str) -> _dt.datetime:
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    return _dt.datetime.fromisoformat(ts)


def _deny(audit: AuditLog, reason: str, detail: str, *,
          status: int = 403, extra_audit: dict | None = None) -> tuple[int, dict]:
    audit_entry = {
        'timestamp': _now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'type': 'authorization',
        'decision': 'denied',
        'reason': reason,
        'detail': detail,
    }
    if extra_audit:
        audit_entry.update(extra_audit)
    audit.write(audit_entry)
    return status, {'status': 'denied', 'reason': reason, 'detail': detail}


def _protocol_supports_inner_config(client_proto: str) -> bool:
    """True if ``client_proto`` (the version the msshd client claims) is at
    least 1.1 — the version that introduced ``inner_sshd_config`` in the
    authz response. Older clients ignore the field, so for backward
    compatibility we don't emit it for them (smaller responses, less audit
    noise)."""
    try:
        major_s, minor_s = client_proto.split('.', 1)
        major = int(major_s)
        minor = int(minor_s.split('.')[0])  # drop any patch suffix
    except (ValueError, AttributeError):
        return False
    return (major, minor) >= (1, 1)


def _error(audit: AuditLog, reason: str, detail: str) -> tuple[int, dict]:
    audit.write({
        'timestamp': _now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'type': 'authorization',
        'decision': 'error',
        'reason': reason,
        'detail': detail,
    })
    return 500, {'status': 'error', 'reason': reason, 'detail': detail}


def handle_authorize(ctx: AuthorizeContext, server_subject: str,
                     body: dict) -> tuple[int, dict]:
    """Process one authorization request body.

    ``server_subject`` is the CN from the caller's mTLS cert. Returns (http_status, json).
    """
    # 1. Server identification.
    server = ctx.enrollment.find_server_by_mtls_subject(server_subject)
    if server is None:
        return _deny(
            ctx.audit, 'unknown_server',
            f'mtls subject {server_subject!r} not enrolled',
            status=401)

    # 2. Parse the request body.
    try:
        identity = body['identity']
        identity_type = str(identity['type'])
        identity_b64 = str(identity['data'])
        connection = body['connection']
        source_ip = str(connection['source_ip'])
        source_port = int(connection['source_port'])
        timestamp_str = str(connection['timestamp'])
    except (KeyError, ValueError, TypeError) as e:
        return _error(ctx.audit, 'bad_request', f'missing/invalid field: {e}')
    requested_channels = body.get('requested_channels')
    if requested_channels is not None and not isinstance(requested_channels, list):
        return _error(ctx.audit, 'bad_request', 'requested_channels must be a list')

    # Wire-protocol negotiation. Older msshd / shim clients don't send these
    # fields; we treat absence as protocol 1.0 and emit a 1.0-shaped response
    # (no inner_sshd_config). Clients at >=1.1 also send the inner-sshd kind
    # + version so the CA can pick the right template and refuse to emit
    # directives the host's sshd can't handle.
    client_proto = str(body.get('protocol_version') or '1.0')
    inner_sshd_kind = body.get('inner_sshd_kind') or 'openssh'
    inner_sshd_version = body.get('inner_sshd_version') or ''
    msshd_version = body.get('msshd_version') or ''

    try:
        identity_blob = base64.b64decode(identity_b64, validate=True)
    except Exception as e:
        return _error(ctx.audit, 'bad_request', f'identity.data not base64: {e}')

    try:
        ts = _parse_iso8601(timestamp_str)
    except Exception as e:
        return _error(ctx.audit, 'bad_request', f'bad timestamp: {e}')
    drift = abs((_now() - ts).total_seconds())
    if drift > ctx.timestamp_drift_seconds:
        return _deny(
            ctx.audit, 'clock_drift',
            f'timestamp drift {drift:.1f}s exceeds limit '
            f'{ctx.timestamp_drift_seconds}s')

    # 3. Parse the identity.
    try:
        parsed = parse_identity(identity_type, identity_blob)
    except IdentityParseError as e:
        return _error(ctx.audit, 'bad_request', f'identity parse: {e}')

    if isinstance(parsed, CertIdentity):
        # Validate trust chain.
        if parsed.signature_key_fingerprint not in ctx.identity_trust_root_fingerprints:
            return _deny(ctx.audit, 'invalid_identity_cert',
                         'signing CA not in identity trust roots')
        now_s = int(_now().timestamp())
        if parsed.valid_after and now_s < parsed.valid_after:
            return _deny(ctx.audit, 'invalid_identity_cert',
                         'identity cert not yet valid')
        if parsed.valid_before and now_s > parsed.valid_before:
            return _deny(ctx.audit, 'invalid_identity_cert',
                         'identity cert expired')
        fingerprint = parsed.fingerprint
        subject_pubkey_blob = parsed.public_key_blob
    elif isinstance(parsed, PubkeyIdentity):
        fingerprint = parsed.fingerprint
        subject_pubkey_blob = parsed.raw_blob
    else:
        return _error(ctx.audit, 'internal', 'unexpected identity type')

    # 4. Identity lookup.
    user = ctx.enrollment.find_user_by_fingerprint(fingerprint)
    if user is None and isinstance(parsed, CertIdentity) and parsed.key_id:
        user = ctx.enrollment.find_user_by_key_id(parsed.key_id)
    if user is None:
        return _deny(
            ctx.audit, 'unknown_identity',
            f'fingerprint {fingerprint} not enrolled',
            extra_audit={'identity': {'fingerprint': fingerprint}})

    # 5. Policy evaluation.
    result = evaluate(user, server, source_ip, ts, requested_channels,
                      ctx.default_max_cert_validity_seconds)
    if not result.ok:
        return _deny(
            ctx.audit, result.deny_reason, result.detail,
            extra_audit={
                'identity': {'fingerprint': fingerprint, 'username': user.username},
                'server': {'canonical_name': server.name},
                'connection': {'source_ip': source_ip, 'source_port': source_port},
            })

    # 6. Mint cert.
    not_before = _now()
    not_after = not_before + _dt.timedelta(seconds=result.merged_max_validity)
    cert, serial_hex = mint_authorization_cert(
        subject_username=user.username,
        subject_pubkey_blob=subject_pubkey_blob,
        signing_key=ctx.signing_key,
        signing_cert=ctx.signing_cert,
        not_before=not_before,
        not_after=not_after,
        source_bind=source_ip,
        server_bind=server.name,
        channels=result.merged_channels,
        force_command=result.merged_force_command,
        environment=result.merged_environment or None,
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode('ascii')

    # 7. Render the per-session inner sshd_config (protocol >= 1.1 only).
    inner_sshd_config: str | None = None
    inner_sshd_config_error: str | None = None
    if _protocol_supports_inner_config(client_proto):
        try:
            template, _src, _detail = _templates.get_effective_template(
                ctx.enrollment, server.name, kind=inner_sshd_kind)
            fromca_values = _render.fromca_values_from_evaluation(result)
            # Render FROMCA_ markers now; leave LOCAL_ markers for msshd.
            inner_sshd_config = _render.render(
                template,
                fromca_values=fromca_values,
                leave_unsubstituted={'LOCAL'},
            )
        except _render.TemplateError as e:
            # Don't deny the session over a template bug — emit the cert
            # without an inner_sshd_config and record the error in audit.
            # msshd will refuse the session at its own validation step
            # (sshd -t) and the operator will see the audit entry.
            inner_sshd_config_error = f'render_failed: {e}'
        except Exception as e:                              # noqa: BLE001
            inner_sshd_config_error = f'render_failed: {type(e).__name__}: {e}'

    # 8. Audit + respond.
    audit_entry: dict[str, Any] = {
        'timestamp': _now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'type': 'authorization',
        'decision': 'granted',
        'serial': serial_hex,
        'identity': {
            'type': identity_type,
            'fingerprint': fingerprint,
            'username': user.username,
        },
        'server': {
            'canonical_name': server.name,
            'groups': list(server.groups),
            'mtls_subject': server.mtls_subject,
        },
        'connection': {
            'source_ip': source_ip,
            'source_port': source_port,
        },
        'cert_validity': {
            'not_before': not_before.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'not_after': not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
        'policy_applied': {
            'policy_ids': [p.id for p in result.matching_policies],
            'channels': result.merged_channels,
            'source_bound': True,
            'force_command': result.merged_force_command,
        },
        'client': {
            'protocol_version': client_proto,
            'msshd_version': msshd_version,
            'inner_sshd_kind': inner_sshd_kind,
            'inner_sshd_version': inner_sshd_version,
        },
    }
    if inner_sshd_config_error:
        audit_entry['inner_sshd_config_error'] = inner_sshd_config_error
    ctx.audit.write(audit_entry)

    response: dict[str, Any] = {
        'status': 'granted',
        'cert': cert_b64,
        'serial': serial_hex,
        'not_after': not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'protocol_version': PROTOCOL_VERSION,
        'policy_summary': {
            'channels': result.merged_channels,
            'source_bound': True,
            'server_bind': server.name,
            'force_command': result.merged_force_command,
            'environment': result.merged_environment,
        },
    }
    if inner_sshd_config is not None:
        response['inner_sshd_config'] = inner_sshd_config
    return 200, response
