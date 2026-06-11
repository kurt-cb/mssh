"""Gated-mode listener — mTLS + CA approval at the outer hop;
proxy to the operator's existing sshd at the inner hop.

Design: §5.3.3 + §1.4.2 (see design/mssh_design_v1.md).

The middle rung of the adoption journey (§13.8):

  fallback (TCP proxy, no CA) ─▶ gated (mTLS + CA + proxy to operator's
  sshd) ─▶ enforce (mTLS + CA + hermetic inner sshd).

Gated mode shares enforce mode's outer mTLS termination + CA authorize
call but does NOT mint an ephemeral OpenSSH cert and does NOT use a
hermetic inner sshd. After the CA approves, msshd opens a plain TCP
connection to ``fallback.host:fallback.port`` (typically the operator's
existing sshd, moved off port 22) and proxies bytes. The operator's
own SSH authentication infrastructure (sshd_config, authorized_keys,
PAM, AllowGroups, etc.) is what actually authenticates the session.

Use case: operators with years of accumulated sshd_config policy who
want CA-mediated access gating BEFORE moving to full CA-mediated
authentication.

Reuses helper functions from ``enforce_listener``:
  - ``_build_ssl_context``: SSL context with mTLS verification.
  - ``_extract_principal``: extract CN from the verified peer cert.
  - ``_user_allowed``: principal × users.allowed check.
  - ``_close``: clean writer close.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from .authz_cache import AuthzCache, SOURCE_CA
from .ca import MsshdCAClient
from .config import MsshdConfig
from .enforce_listener import (_build_ssl_context, _close, _extract_principal,
                                _user_allowed)
from .proxy import bidirectional_proxy

log = logging.getLogger('msshd.gated')


class GatedListener:
    """Outer mTLS listener for gated mode.

    Connection lifecycle:
      1. Accept TLS handshake; validate client cert against
         ``ca.auth_trust_root`` pin (§2.3 / §13.9.5).
      2. Extract principal from peer cert CN.
      3. ``users.allowed`` admission check (§14.3.1).
      4. Read JSON header (§14.7 session-RPC).
      5. Authz cache lookup; on miss, call mssh-ca.
      6. On grant: open TCP to ``fallback.host:port``, bidi-proxy.
      7. On deny: emit DENY ack, close.
    """

    def __init__(self, cfg: MsshdConfig, *,
                 ca_client: MsshdCAClient,
                 authz_cache: AuthzCache,
                 crl_sync=None,
                 inner_sshd_kind: str = '',
                 inner_sshd_version: str = '',
                 msshd_version: str = '',
                 protocol_version: str = ''):
        self.cfg = cfg
        self.ca_client = ca_client
        self.authz_cache = authz_cache
        self.crl_sync = crl_sync
        self.inner_sshd_kind = inner_sshd_kind
        self.inner_sshd_version = inner_sshd_version
        self.msshd_version = msshd_version
        self.protocol_version = protocol_version
        self._server: Optional[asyncio.base_events.Server] = None
        self._ssl_ctx = _build_ssl_context(cfg)
        self._active: set[asyncio.Task] = set()

    async def start(self) -> None:
        # §5.3.3 bind outer TLS-terminating socket.
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.cfg.listen.external_address,
            port=self.cfg.listen.external_port,
            ssl=self._ssl_ctx,
            reuse_address=True,
        )
        for s in self._server.sockets or []:
            log.info('gated listener bound to %s (mTLS → %s:%d)',
                     s.getsockname(),
                     self.cfg.fallback.host, self.cfg.fallback.port)

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
        for t in list(self._active):
            t.cancel()
        if self._active:
            await asyncio.gather(*self._active, return_exceptions=True)

    async def _on_client(self,
                         reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        # §5.3.3 per-connection gated-mode flow:
        # mTLS → principal → header → authz → proxy.
        conn_id = uuid.uuid4().hex[:8]
        peer = writer.get_extra_info('peername') or ('?', 0)
        source_ip, source_port = peer[0], peer[1]
        task = asyncio.current_task()
        if task is not None:
            self._active.add(task)
        try:
            # mTLS peer-cert extraction (same logic as enforce).
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is None:
                log.error('[%s] no ssl_object (TLS not configured?)', conn_id)
                await _close(writer)
                return
            peer_der = ssl_obj.getpeercert(binary_form=True)
            if not peer_der:
                log.warning('[%s] no client cert; rejecting', conn_id)
                await _close(writer)
                return
            try:
                principal = _extract_principal(peer_der)
            except ValueError as e:
                log.warning('[%s] no principal: %s', conn_id, e)
                await _close(writer)
                return
            if not _user_allowed(self.cfg, principal):
                log.warning('[%s] principal %r not in users.allowed',
                            conn_id, principal)
                await _close(writer)
                return
            log.info('[%s] gated: mTLS ok from %s:%d as principal=%s',
                     conn_id, source_ip, source_port, principal)

            # JSON session-RPC header read (§14.7).
            from .ssh_proxy import _read_header_line, _write_ack
            try:
                header = await _read_header_line(reader)
            except (asyncio.TimeoutError, Exception) as e:
                log.warning('[%s] gated: header read failed: %s', conn_id, e)
                try:
                    _write_ack(writer, ok=False, reason='bad_header')
                except Exception:
                    pass
                await _close(writer)
                return

            # Authz: cache lookup, else CA call.
            grant = self.authz_cache.get(principal)
            if grant is None:
                # §5.3.3 step 5: live CA call.
                from .ssh_proxy import _ssh_pubkey_blob_from_cert
                try:
                    pubkey_blob = _ssh_pubkey_blob_from_cert(peer_der)
                except Exception as e:
                    log.warning('[%s] gated: cannot derive pubkey: %s',
                                conn_id, e)
                    try:
                        _write_ack(writer, ok=False, reason='no_identity')
                    except Exception:
                        pass
                    await _close(writer)
                    return
                try:
                    grant_or_result = await self.ca_client.authorize(
                        principal=principal,
                        pubkey_blob=pubkey_blob,
                        source_ip=source_ip,
                        source_port=source_port,
                        last_crl_seqs=dict(self.authz_cache.last_crl_seqs),
                        inner_sshd_kind=self.inner_sshd_kind,
                        inner_sshd_version=self.inner_sshd_version,
                        msshd_version=self.msshd_version,
                    )
                except Exception as e:
                    log.warning('[%s] gated: CA unreachable: %s', conn_id, e)
                    try:
                        _write_ack(writer, ok=False, reason='ca_unreachable')
                    except Exception:
                        pass
                    await _close(writer)
                    return
                if not getattr(grant_or_result, 'granted', False):
                    deny_reason = getattr(grant_or_result, 'reason',
                                           'policy_mismatch')
                    log.info('[%s] gated: CA denied: %s', conn_id, deny_reason)
                    try:
                        _write_ack(writer, ok=False, reason=deny_reason)
                    except Exception:
                        pass
                    await _close(writer)
                    return
                # Store in cache for subsequent connections from same principal.
                grant = self.authz_cache.put(
                    principal, grant_or_result.grant, source=SOURCE_CA)
                if self.crl_sync is not None:
                    try:
                        await self.crl_sync.maybe_sync(grant_or_result.grant)
                    except Exception:
                        log.debug('[%s] CRL sync failed (non-fatal)',
                                  conn_id, exc_info=True)

            # Authz approved (cache hit or fresh grant). Ack + proxy.
            try:
                _write_ack(writer, ok=True, framing=False)
            except Exception:
                log.warning('[%s] gated: ack write failed', conn_id)
                await _close(writer)
                return

            # §5.3.3 step 6: open TCP to operator's sshd and proxy.
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host=self.cfg.fallback.host,
                        port=self.cfg.fallback.port),
                    timeout=10.0)
            except (OSError, asyncio.TimeoutError) as e:
                log.error('[%s] gated: upstream %s:%d unreachable: %s',
                          conn_id, self.cfg.fallback.host,
                          self.cfg.fallback.port, e)
                await _close(writer)
                return
            log.info('[%s] gated: proxying to %s:%d (operator sshd)',
                     conn_id, self.cfg.fallback.host, self.cfg.fallback.port)
            await bidirectional_proxy(reader, writer, up_reader, up_writer,
                                       conn_id=conn_id)
        finally:
            if task is not None:
                self._active.discard(task)
            log.info('[%s] gated: closed', conn_id)
