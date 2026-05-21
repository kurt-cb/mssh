"""CA client adapter for msshd.

Thin adapter around ``shim.ca_client.CAClient`` that:

  - Builds the ``POST /v1/authorize`` request body in v1 schema
    (the v2 enrichments from
    [design/mssh-v2-enhancements.md](../../design/mssh-v2-enhancements.md)
    are deferred to Phase 1B+).
  - Calls the CA in an executor (CAClient uses blocking ``requests``).
  - Returns a typed result with the cert (DER), serial, and notAfter,
    or the deny reason.

The actual mTLS / failover / proxy-handling logic lives in
``shim.ca_client.CAClient`` — no point duplicating it.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import logging
from dataclasses import dataclass
from typing import Any, Union

from mssh.shim.ca_client import (AuthorizeResult, CAClient, CAClientFailedOver)

from .config import MsshdConfig


log = logging.getLogger('msshd.ca')


@dataclass
class AuthorizationGrant:
    cert_der: bytes
    serial: str
    not_after: _dt.datetime
    # Protocol-1.1+ fields. Empty / None on older CAs.
    inner_sshd_config: str = ''
    protocol_version: str = ''
    # CA's current CRL sequence at response time. 0 = CA has no CRL
    # (legacy CA or empty log). msshd uses this to decide whether to
    # fetch missing CRL entries via GET /v1/crl?after=N. See
    # archive/design/notes-bypass-cache.md "CRL Amendment".
    current_crl_seq: int = 0


@dataclass
class AuthorizationDeny:
    reason: str
    detail: str = ''
    http_status: int = 0
    # CA's current CRL sequence at the time it denied. Carried so msshd's
    # CRL sync can advance even when only denials happen — otherwise
    # revocations stall indefinitely on small fleets where the cache
    # mostly hits.
    current_crl_seq: int = 0


@dataclass
class AuthorizationError:
    """All CA endpoints unreachable, or a malformed response."""
    message: str


AuthorizationResult = Union[AuthorizationGrant, AuthorizationDeny, AuthorizationError]


class MsshdCAClient:
    """Async-friendly CA-call adapter.

    Builds on top of the blocking ``shim.ca_client.CAClient`` (which is
    deliberately ``requests``-based — see issue 2.1 in
    [tests/issues.md](../../tests/issues.md)). We run the blocking call
    in the default executor so msshd's asyncio loop stays
    responsive.
    """

    def __init__(self, cfg: MsshdConfig):
        if not cfg.ca.endpoints:
            raise ValueError('MsshdCAClient requires cfg.ca.endpoints')
        self._client = CAClient(
            endpoints=cfg.ca.endpoints,
            mtls_cert=cfg.ca.client_cert,
            mtls_key=cfg.ca.client_key,
            ca_trust_root=cfg.ca.ca_pubkey,
            connect_timeout=cfg.ca.timeout_seconds,
            read_timeout=cfg.ca.timeout_seconds * 2,
        )
        self._cfg = cfg

    async def authorize(
        self,
        *,
        identity_blob: bytes,
        identity_type: str,
        source_ip: str,
        source_port: int,
        requested_channels: list[str] | None = None,
        protocol_version: str = '',
        inner_sshd_kind: str = '',
        inner_sshd_version: str = '',
        msshd_version: str = '',
        last_crl_seq: int = 0,
    ) -> AuthorizationResult:
        """Call POST /v1/authorize. ``identity_blob`` is the raw SSH
        wire-format pubkey or OpenSSH cert bytes.

        protocol_version / inner_sshd_kind / inner_sshd_version /
        msshd_version are forwarded to the CA so it can render the
        right inner_sshd_config + record fleet-version data in audit
        (Phase 1.1+). Empty strings are dropped from the wire body so
        a 1.0 CA never sees fields it doesn't know."""
        body: dict[str, Any] = {
            'identity': {
                'type': identity_type,
                'data': base64.b64encode(identity_blob).decode('ascii'),
            },
            'connection': {
                'source_ip': source_ip,
                'source_port': source_port,
                'timestamp': _now_iso8601(),
            },
        }
        if requested_channels is not None:
            body['requested_channels'] = list(requested_channels)
        # Protocol 1.1+ optional fields. Send only if populated so the
        # body is a strict subset of 1.0 when caller doesn't supply them.
        if protocol_version:
            body['protocol_version'] = protocol_version
        if inner_sshd_kind:
            body['inner_sshd_kind'] = inner_sshd_kind
        if inner_sshd_version:
            body['inner_sshd_version'] = inner_sshd_version
        if msshd_version:
            body['msshd_version'] = msshd_version
        # Always send the CRL sequence — 0 is meaningful (msshd has
        # never synced). CA includes its current_crl_seq in the
        # response so msshd can fetch missing CRLs.
        body['last_crl_seq'] = int(last_crl_seq)

        loop = asyncio.get_running_loop()
        try:
            result: AuthorizeResult = await loop.run_in_executor(
                None, self._client.authorize, body)
        except CAClientFailedOver as e:
            return AuthorizationError(message=f'all CA endpoints failed: {e}')
        except Exception as e:
            log.exception('CA call raised unexpectedly')
            return AuthorizationError(message=f'unexpected CA error: {e}')

        return _parse_result(result)

    async def fetch_crl(self, *, after: int, limit: int) -> dict:
        """GET /v1/crl?after=N&limit=K against the same CA endpoint
        list. Returns the parsed JSON body: {status, current_seq,
        entries: [...]}.

        Raises an exception on transport / parse failure. Callers
        (the CRL sync loop) treat exceptions as "skip this round,
        retry later"."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._client.crl_fetch, after, limit)


def _parse_result(result: AuthorizeResult) -> AuthorizationResult:
    status = result.status
    body = result.body
    if status == 'granted':
        cert_b64 = body.get('cert')
        if not isinstance(cert_b64, str):
            return AuthorizationError(message='granted response missing cert')
        try:
            cert_der = base64.b64decode(cert_b64)
        except Exception as e:
            return AuthorizationError(message=f'cert base64 decode failed: {e}')
        serial = str(body.get('serial', ''))
        not_after_s = str(body.get('not_after', ''))
        try:
            not_after = _parse_iso8601(not_after_s)
        except Exception:
            return AuthorizationError(
                message=f'unparseable not_after {not_after_s!r}')
        try:
            current_crl_seq = int(body.get('current_crl_seq') or 0)
        except (TypeError, ValueError):
            current_crl_seq = 0
        return AuthorizationGrant(
            cert_der=cert_der, serial=serial, not_after=not_after,
            inner_sshd_config=str(body.get('inner_sshd_config') or ''),
            protocol_version=str(body.get('protocol_version') or ''),
            current_crl_seq=current_crl_seq)

    if status == 'denied':
        try:
            deny_crl_seq = int(body.get('current_crl_seq') or 0)
        except (TypeError, ValueError):
            deny_crl_seq = 0
        return AuthorizationDeny(
            reason=str(body.get('reason', 'unspecified')),
            detail=str(body.get('detail', '')),
            http_status=result.http_status,
            current_crl_seq=deny_crl_seq,
        )

    return AuthorizationError(
        message=f'CA returned status={status} body={body!r}')


def _now_iso8601() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_iso8601(s: str) -> _dt.datetime:
    # Accept both Z-suffix and +00:00 forms.
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return _dt.datetime.fromisoformat(s)
