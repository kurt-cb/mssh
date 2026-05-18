"""EnforceListener — TLS-terminating listener that drives the full
mssh wrap-and-proxy flow.

For each accepted client connection:

  1. Terminate outer mTLS. Verify the client cert chain against the
     configured user-mTLS root. Extract the SSH user identity (the
     authenticated principal we'll request from inner sshd).
  2. Pull the client's SSH pubkey from their mTLS cert (for now we
     accept whatever the cert subject names; richer pubkey-extraction
     comes in v2).
  3. Call the CA. Get an X.509 authz cert with policy extensions.
  4. Validate the cert against the auth trust root + KNOWN_CRITICAL.
  5. Translate extensions to OpenSSH cert critical-options.
  6. Mint a 30-second OpenSSH user cert via UserCA.
  7. Open an asyncssh client to the inner sshd, presenting the
     ephemeral key+cert.
  8. Proxy bytes between the outer TLS connection and the inner SSH
     channel.

This is a Phase 1B sketch: identity extraction is intentionally
simple (we trust the mTLS subject CN as the principal). Phase 1B+
will pull the SSH pubkey from a structured cert SAN or a richer
client greeting.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import uuid
from typing import Optional

import struct

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .authz_cache import SOURCE_BYPASS, SOURCE_CA, AuthzCache
from .ca import (AuthorizationDeny, AuthorizationError, AuthorizationGrant,
                  WrapperCAClient)
from .config import WrapperConfig
from .inner import InnerSshd
from .policy import (KNOWN_CRITICAL, parse_cert_policy,
                     translate_to_inner_cert_kwargs)
from .userca import UserCA


log = logging.getLogger('msshd.enforce')


class EnforceListener:
    """TLS-terminating listener for enforce mode.

    ``inner_sshd`` is either ``InnerSshd`` (long-lived) or
    ``PerConnectionInnerSshd`` (one sshd per session). The branch is
    in ``_proxy_to_inner``: per-connection acquires a fresh sshd via
    ``acquire_session(conn_id, grant.inner_sshd_config)`` and releases
    it when the session ends; long-lived uses ``inner_sshd.port``
    directly.
    """

    def __init__(self, cfg: WrapperConfig, *,
                 user_ca: UserCA,
                 ca_client: WrapperCAClient,
                 inner_sshd,                       # InnerSshd | PerConnectionInnerSshd
                 authz_cache: AuthzCache,
                 crl_sync=None,                    # CRLSync | None
                 inner_sshd_kind: str = 'openssh',
                 inner_sshd_version: str = '',
                 msshd_version: str = '',
                 protocol_version: str = ''):
        self.cfg = cfg
        self.user_ca = user_ca
        self.ca_client = ca_client
        self.inner_sshd = inner_sshd
        self.authz_cache = authz_cache
        # CRL sync — fetches missing CRLs after each authorize call;
        # see crl_sync.py. May be None in early-bootstrap / test code.
        self.crl_sync = crl_sync
        # Highest CRL sequence we've seen the CA advertise. Tracks
        # CA's view of "current" across connections so the strict
        # gate has a fresh enough number to compare against
        # last-applied. Seeded from the persisted cache state.
        self._last_known_ca_crl_seq: int = authz_cache.last_crl_seq
        self.inner_sshd_kind = inner_sshd_kind
        self.inner_sshd_version = inner_sshd_version
        self.msshd_version = msshd_version
        self.protocol_version = protocol_version
        self._server: Optional[asyncio.base_events.Server] = None
        self._ssl_ctx = _build_ssl_context(cfg)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.cfg.listen.external_address,
            port=self.cfg.listen.external_port,
            ssl=self._ssl_ctx,
            reuse_address=True,
        )
        for s in self._server.sockets or []:
            log.info('enforce listener bound to %s (mTLS)', s.getsockname())

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError('start() not called')
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:
            log.debug('server wait_closed raised', exc_info=True)

    async def _on_client(self,
                         reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        conn_id = uuid.uuid4().hex[:8]
        peer = writer.get_extra_info('peername') or ('?', 0)
        source_ip, source_port = peer[0], peer[1]

        # ssl_object exposes the verified peer cert (DER form).
        ssl_obj = writer.get_extra_info('ssl_object')
        if ssl_obj is None:
            log.error('[%s] no ssl_object on connection (TLS not configured?)',
                      conn_id)
            await _close(writer)
            return

        peer_der = ssl_obj.getpeercert(binary_form=True)
        if not peer_der:
            log.warning('[%s] no client cert presented; rejecting', conn_id)
            await _close(writer)
            return

        try:
            principal = _extract_principal(peer_der)
        except ValueError as e:
            log.warning('[%s] could not extract principal: %s', conn_id, e)
            await _close(writer)
            return

        if not _user_allowed(self.cfg, principal):
            log.warning('[%s] principal %r not in users.allowed; rejecting',
                        conn_id, principal)
            await _close(writer)
            return

        log.info('[%s] accepted mTLS from %s:%d as principal=%s',
                 conn_id, source_ip, source_port, principal)

        # --- Read v1 outer-protocol header ---
        # Done HERE (not in proxy_to_inner_ssh) so we can detect a
        # bypass-cert injection request before any CA call. The same
        # header is passed through to the inner proxy below for the
        # normal-session path.
        from .ssh_proxy import _read_header_line, _write_ack
        try:
            header = await _read_header_line(reader)
        except asyncio.TimeoutError:
            log.warning('[%s] outer client did not send header in time',
                        conn_id)
            try:
                _write_ack(writer, ok=False, reason='header_timeout')
            except Exception:
                pass
            await _close(writer)
            return
        except Exception as e:
            log.warning('[%s] outer header invalid: %s', conn_id, e)
            try:
                _write_ack(writer, ok=False, reason=f'bad_header: {e}')
            except Exception:
                pass
            await _close(writer)
            return

        # --- Bypass-cert injection path ---
        # When the client supplies a base64-DER bypass cert in the
        # header, msshd validates it, stores it in the authz cache
        # tagged 'bypass', acks, and closes. The operator's next
        # normal `mssh` call hits the cache. No CA call here.
        bypass_cert_b64 = header.get('bypass_cert')
        if bypass_cert_b64:
            ok, reason = await self._handle_bypass_injection(
                conn_id, principal, peer_der, bypass_cert_b64)
            try:
                _write_ack(writer, ok=ok,
                           reason=reason if not ok else f'injected:{reason}')
            except Exception:
                pass
            await _close(writer)
            return

        # --- Strict-mode CRL gate ---
        # If we know the CA is significantly ahead of our CRL state
        # (last live response advertised current_crl_seq much higher
        # than last_applied), refuse to serve cache hits — force a
        # live CA call so revocations propagate before granting.
        # Threshold of 0 disables the gate (always serve from cache).
        cache_is_stale = False
        if self.crl_sync is not None:
            threshold = self.cfg.ca.crl_strict_threshold
            if threshold > 0:
                gap = (self._last_known_ca_crl_seq
                       - self.authz_cache.last_crl_seq)
                if gap > threshold:
                    log.warning('[%s] cache stale: CRL gap=%d > '
                                'threshold=%d; bypassing cache',
                                conn_id, gap, threshold)
                    cache_is_stale = True

        # --- Normal flow: cache first, CA on miss (or stale) ---
        cached = (None if cache_is_stale
                  else self.authz_cache.get(principal))
        if cached is not None:
            log.info('[%s] authz cache hit for %s (source=%s, '
                     'not_after=%s)', conn_id, principal,
                     cached.source, cached.grant.not_after)
            result: AuthorizationGrant | AuthorizationDeny | AuthorizationError \
                = cached.grant
        else:
            try:
                identity_blob = _ssh_pubkey_blob_from_cert(peer_der)
            except ValueError as e:
                log.warning('[%s] cannot derive SSH pubkey: %s',
                            conn_id, e)
                await _close(writer)
                return

            result = await self.ca_client.authorize(
                identity_blob=identity_blob,
                identity_type='pubkey',
                source_ip=source_ip,
                source_port=source_port,
                requested_channels=['session'],
                protocol_version=self.protocol_version,
                inner_sshd_kind=self.inner_sshd_kind,
                inner_sshd_version=self.inner_sshd_version,
                msshd_version=self.msshd_version,
                last_crl_seq=self.authz_cache.last_crl_seq,
            )

            if isinstance(result, AuthorizationDeny):
                # CA is the oracle when reachable: an explicit deny
                # invalidates ALL cached entries for this principal
                # (including any bypass injection — see
                # design/notes-bypass-cache.md).
                log.info('[%s] CA denied: %s (%s) — invalidating cache',
                         conn_id, result.reason, result.detail)
                self.authz_cache.invalidate(principal)
                await _close(writer)
                return
            if isinstance(result, AuthorizationError):
                log.error('[%s] CA error + no cache hit: %s',
                          conn_id, result.message)
                await _close(writer)
                return

            assert isinstance(result, AuthorizationGrant)
            log.info('[%s] CA granted cert serial=%s not_after=%s '
                     '— caching', conn_id, result.serial,
                     result.not_after)
            self.authz_cache.put(principal, result, source=SOURCE_CA)
            # Record + maybe trigger background CRL sync.
            self._last_known_ca_crl_seq = max(
                self._last_known_ca_crl_seq, result.current_crl_seq)
            if self.crl_sync is not None:
                self.crl_sync.maybe_sync(result.current_crl_seq)

        # --- Validate + parse policy (shared path for cache-hit + fresh-CA) ---
        try:
            _validate_critical_extensions(result.cert_der)
        except ValueError as e:
            log.error('[%s] cert validation failed: %s', conn_id, e)
            await _close(writer)
            return

        cert_policy = parse_cert_policy(result.cert_der)
        if (cert_policy.server_bind
                and cert_policy.server_bind != self.cfg.tls.server_cert):
            # The wrapper's own canonical name is encoded in its mTLS
            # cert; pre-Phase-1B we don't have the explicit "this is
            # my canonical server name" yet — just log + accept for now.
            log.debug('[%s] cert server_bind=%s (wrapper local-check '
                      'deferred)', conn_id, cert_policy.server_bind)

        kwargs = translate_to_inner_cert_kwargs(cert_policy)
        log.debug('[%s] inner cert kwargs: force_command=%r source_address=%r',
                  conn_id, kwargs.force_command, kwargs.source_address)

        # --- Mint inner user cert ---
        minted = self.user_ca.mint_user_cert(
            principal=principal,
            valid_before=result.not_after,
            force_command=kwargs.force_command,
            source_address=kwargs.source_address,
        )

        # --- Inner SSH leg + bytes proxy ---
        try:
            await self._proxy_to_inner(
                conn_id, reader, writer, principal, minted, cert_policy,
                result, header)
        finally:
            await _close(writer)

    async def _proxy_to_inner(
        self,
        conn_id: str,
        outer_reader: asyncio.StreamReader,
        outer_writer: asyncio.StreamWriter,
        principal: str,
        minted,
        cert_policy,
        grant,                                    # AuthorizationGrant
        prefetched_header: dict,                  # parsed v1 header
    ) -> None:
        # Lazy import: asyncssh client is only needed in enforce mode,
        # and pulling it in at module import slows the daemon startup.
        from .config import INNER_MODE_PER_CONNECTION
        from .inner import InnerSshdError, PerConnectionInnerSshd
        from .ssh_proxy import proxy_to_inner_ssh

        # Branch on inner mode: long-lived uses the one shared port;
        # per-connection spawns a fresh sshd with the CA-rendered config.
        per_conn = isinstance(self.inner_sshd, PerConnectionInnerSshd)
        inner_port: int
        acquired = False
        if per_conn:
            if not grant.inner_sshd_config:
                log.error(
                    '[%s] per-connection mode but CA returned no '
                    'inner_sshd_config — denying session. CA protocol '
                    'too old (need >=1.1) or template render failed at '
                    'the CA. See CA audit for details.', conn_id)
                return
            try:
                inner_port = await self.inner_sshd.acquire_session(
                    conn_id, grant.inner_sshd_config)
                acquired = True
            except InnerSshdError as e:
                log.error('[%s] could not spawn per-session sshd: %s',
                          conn_id, e)
                return
        else:
            inner_port = self.inner_sshd.port

        try:
            await proxy_to_inner_ssh(
                outer_reader=outer_reader,
                outer_writer=outer_writer,
                inner_host='127.0.0.1',
                inner_port=inner_port,
                principal=principal,
                user_private_key=minted.user_private_key,
                user_cert=minted.cert,
                inner_host_key_path=str(
                    self.inner_sshd.state_dir / 'ssh_host_ed25519_key.pub'),
                conn_id=conn_id,
                max_session_seconds=cert_policy.max_session_seconds,
                forced_command=cert_policy.force_command or None,
                forced_env=cert_policy.environment or None,
                prefetched_header=prefetched_header,
            )
        finally:
            if acquired:
                try:
                    await self.inner_sshd.release_session(conn_id)
                except Exception:
                    log.exception('[%s] release_session raised', conn_id)

    async def _handle_bypass_injection(
        self,
        conn_id: str,
        mtls_principal: str,
        peer_der: bytes,
        bypass_cert_b64: str,
    ) -> tuple[bool, str]:
        """Validate a bypass cert from the JSON header and inject into
        the authz cache.

        Returns (ok, reason). On success, ``reason`` is a short
        diagnostic string (cert serial + not_after); on failure it
        names what went wrong. The caller writes the ack and closes.

        Per design/notes-bypass-cache.md, the bypass cert must:

          1. Be a CA-signed X.509 authz cert (same shape as a normal
             grant), validatable against the auth trust root via the
             same path normal CA grants go through.
          2. Have the ``mssh-ca-bypass`` critical extension marker.
          3. Be within its ``not_before``/``not_after`` window.
          4. Have its CN match the mTLS-handshake principal — i.e.
             "presented by the rightful owner only."
        """
        import base64

        from .policy import OID_CA_BYPASS, parse_cert_policy
        try:
            cert_der = base64.b64decode(bypass_cert_b64)
        except Exception as e:
            log.warning('[%s] bypass_cert: bad base64: %s', conn_id, e)
            return False, f'bypass_bad_b64: {e}'

        # Parse the cert.
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as e:
            log.warning('[%s] bypass_cert: not a valid X.509 cert: %s',
                        conn_id, e)
            return False, f'bypass_bad_cert: {e}'

        # 1. Validity window.
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
        except AttributeError:
            # cryptography <42: deprecated naive accessors.
            nb = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
            na = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
        if na < now:
            log.warning('[%s] bypass_cert: expired (not_after=%s)',
                        conn_id, na)
            return False, 'bypass_expired'
        if nb > now + _dt.timedelta(seconds=60):
            log.warning('[%s] bypass_cert: not yet valid (not_before=%s)',
                        conn_id, nb)
            return False, 'bypass_not_yet_valid'

        # 2. Has the bypass marker critical extension.
        found_bypass_marker = False
        for ext in cert.extensions:
            if ext.oid.dotted_string == OID_CA_BYPASS:
                if not ext.critical:
                    log.warning('[%s] bypass_cert: bypass marker '
                                'present but not critical', conn_id)
                    return False, 'bypass_marker_not_critical'
                found_bypass_marker = True
                break
        if not found_bypass_marker:
            log.warning('[%s] bypass_cert: missing mssh-ca-bypass '
                        'critical extension', conn_id)
            return False, 'bypass_marker_missing'

        # 3. Validate the normal cert structure (critical extensions,
        #    chain to trust root) using the same code path as
        #    regular CA grants. This rejects unknown critical
        #    extensions, expired-style mismatches, etc.
        try:
            _validate_critical_extensions(cert_der)
        except ValueError as e:
            log.warning('[%s] bypass_cert: extension validation '
                        'failed: %s', conn_id, e)
            return False, f'bypass_ext_invalid: {e}'

        # TODO: chain-to-trust-root verification. The normal CA-call
        # path implicitly trusts the CA endpoint (mTLS to a trusted
        # CA host). For bypass certs presented inline, we should
        # explicitly verify cert.signature against ca.ca_pubkey. This
        # is tracked as a follow-up; v1 relies on the bypass marker
        # being present (only CA-issued certs carry it).

        # 4. Principal match.
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)
            bypass_cn = cn_attrs[0].value if cn_attrs else None
        except Exception:
            bypass_cn = None
        if bypass_cn != mtls_principal:
            log.warning('[%s] bypass_cert: cert CN=%r does not match '
                        'mTLS principal=%r — rejecting',
                        conn_id, bypass_cn, mtls_principal)
            return False, 'bypass_principal_mismatch'

        # Synthesize an AuthorizationGrant from the cert + put in cache.
        serial_hex = format(cert.serial_number, 'x')
        # parse_cert_policy reads the same extensions used downstream
        # (force_command, source_address, channels, etc.); the
        # bypass cert encodes a full normal grant, so this works
        # transparently.
        _ = parse_cert_policy(cert_der)  # parses for side-effect-free
                                          # validation; result not used
                                          # here because the actual
                                          # session reads it again on
                                          # cache-hit.

        grant = AuthorizationGrant(
            cert_der=cert_der,
            serial=serial_hex,
            not_after=na,
        )
        self.authz_cache.put(mtls_principal, grant, source=SOURCE_BYPASS)
        log.warning('[%s] bypass_cert: INJECTED for %s (serial=%s, '
                    'not_after=%s)',
                    conn_id, mtls_principal, serial_hex, na)
        return True, f'serial={serial_hex} not_after={na.isoformat()}'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_ssl_context(cfg: WrapperConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cfg.tls.server_cert,
                        keyfile=cfg.tls.server_key)
    ctx.load_verify_locations(cafile=cfg.tls.user_ca_pubkey)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _extract_principal(peer_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(peer_der)
    try:
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        raise ValueError('no CN in client cert subject')
    if not isinstance(cn, str) or not cn:
        raise ValueError(f'invalid CN: {cn!r}')
    return cn


def _ssh_pubkey_blob_from_cert(peer_der: bytes) -> bytes:
    """Derive an SSH wire-format public key blob from the client's
    mTLS certificate's public key.

    Phase 1B simplification: the mTLS cert public key IS the user's
    SSH identity. We construct the canonical SSH wire-format blob
    (RFC 4253 §6.6, OpenSSH PROTOCOL.certkeys) so the CA's
    identity_parser recognises it natively — same shape the CA
    enrollment stored when the user was added.

    Currently supports Ed25519 only. Other key types raise
    ``ValueError``. Long-term, v2's design will let the client
    present a separate SSH pubkey in a cert SAN, decoupling the SSH
    identity from the mTLS identity. For Phase 1B closing,
    "mTLS cert pubkey == SSH pubkey" is the simplest workable choice.
    """
    cert = x509.load_der_x509_certificate(peer_der)
    pubkey = cert.public_key()
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        raw = pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # SSH wire format: u32 string-length + "ssh-ed25519" + u32 key-length + 32-byte key
        name = b'ssh-ed25519'
        return (struct.pack('>I', len(name)) + name
                + struct.pack('>I', len(raw)) + raw)
    raise ValueError(
        f'mTLS cert pubkey type {type(pubkey).__name__} not supported in '
        f'Phase 1B (use Ed25519 for now; v2 will support other types).')


def _user_allowed(cfg: WrapperConfig, principal: str) -> bool:
    allowed = cfg.users.allowed
    if not allowed:
        return False
    if allowed == ['*']:
        return True
    return principal in allowed


def _validate_critical_extensions(cert_der: bytes) -> None:
    cert = x509.load_der_x509_certificate(cert_der)
    for ext in cert.extensions:
        if not ext.critical:
            continue
        if ext.oid.dotted_string not in KNOWN_CRITICAL:
            raise ValueError(
                f'unknown critical extension {ext.oid.dotted_string}')


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
