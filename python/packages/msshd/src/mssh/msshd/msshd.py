"""msshd — daemon entry point.

Phase 1A: fallback mode. Listens, proxies bytes to a downstream sshd.
No mTLS, no CA, no cert minting.

Phase 1B: enforce mode. TLS-terminating listener + CA call + cert mint
+ inner-sshd-managed handoff via asyncssh.

Invocation:
    python -m mssh.msshd --config /etc/mssh/msshd.yaml

Design: §5.3.1 (see design/mssh_design_v1.md) — msshd boot sequence,
mode selector dispatch (fallback vs enforce).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from .config import MODE_ENFORCE, MODE_FALLBACK, MODE_GATED, MsshdConfig
from .listener import FallbackListener


log = logging.getLogger('msshd')


_LEVELS = {
    'debug': logging.DEBUG, 'info': logging.INFO,
    'warn': logging.WARNING, 'warning': logging.WARNING,
    'error': logging.ERROR,
}


def _setup_logging(cfg: MsshdConfig) -> None:
    level = _LEVELS.get(cfg.logging_.level.lower(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(name)s [%(levelname)s] %(message)s',
        stream=sys.stderr,
    )


async def _run(cfg: MsshdConfig) -> int:
    # §5.3.1 mode-selector dispatch: fallback vs enforce.
    if cfg.mode == MODE_FALLBACK:
        listener = FallbackListener(cfg)
        await listener.start()

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)

        serve_task = asyncio.create_task(listener.serve_forever())
        try:
            await stop_event.wait()
            log.info('shutdown signal received')
        finally:
            await listener.stop()
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        return 0

    if cfg.mode == MODE_GATED:
        return await _run_gated(cfg)

    if cfg.mode == MODE_ENFORCE:
        return await _run_enforce(cfg)

    log.error('unknown mode: %r', cfg.mode)
    return 2


async def _run_gated(cfg: MsshdConfig) -> int:
    # §5.3.3 gated-mode boot: CA client + authz cache + CRL sync +
    # GatedListener. No user-CA, no inner sshd (the operator's existing
    # sshd is the auth endpoint).
    from mssh._protocol import PROTOCOL_VERSION
    from mssh._version import __version__ as MSSHD_VERSION
    from .authz_cache import AuthzCache
    from .ca import MsshdCAClient
    from .crl_sync import CRLSync
    from .gated_listener import GatedListener

    state_dir = os.environ.get('MSSHD_STATE_DIR', '/var/lib/mssh')

    try:
        ca_client = MsshdCAClient(cfg)
    except Exception as e:
        log.error('CA client init failed: %s', e)
        return 4

    authz_cache = AuthzCache(
        persist_path=os.path.join(state_dir, 'authz_cache.json'),
        max_per_principal=cfg.performance.authz_cache_max_per_principal,
        max_total=cfg.performance.authz_cache_max_total,
    )
    crl_sync = CRLSync(authz_cache, ca_client,
                       fetch_limit=cfg.ca.crl_fetch_limit)

    listener = GatedListener(
        cfg, ca_client=ca_client, authz_cache=authz_cache,
        crl_sync=crl_sync,
        inner_sshd_kind='operator-sshd',   # informational only
        inner_sshd_version='',
        msshd_version=MSSHD_VERSION,
        protocol_version=PROTOCOL_VERSION,
    )
    try:
        await listener.start()
    except Exception as e:
        log.error('gated listener failed to start: %s', e)
        return 5

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)
    serve_task = asyncio.create_task(listener.serve_forever())
    try:
        await stop_event.wait()
        log.info('shutdown signal received')
    finally:
        await listener.stop()
        serve_task.cancel()
        try:
            await serve_task
        except (asyncio.CancelledError, Exception):
            pass
    return 0


async def _run_enforce(cfg: MsshdConfig) -> int:
    # §5.3.1 enforce-mode boot: user-CA load, inner sshd, CA client,
    # authz cache, CRL sync, EnforceListener.
    # Lazy imports — enforce mode pulls in asyncssh + cryptography
    # heavy paths only when needed.
    from mssh._protocol import PROTOCOL_VERSION
    from mssh._version import __version__ as MSSHD_VERSION
    from .authz_cache import AuthzCache
    from .ca import MsshdCAClient
    from .config import INNER_MODE_PER_CONNECTION
    from .crl_sync import CRLSync
    from .enforce_listener import EnforceListener
    from .inner import (InnerSshd, PerConnectionInnerSshd,
                        _detect_sshd_version)
    from .userca import UserCA

    state_dir = os.environ.get(
        'MSSHD_STATE_DIR',
        '/var/lib/mssh')

    # 1. Load the user-CA private key (in memory only after this).
    user_ca_priv_path = os.path.join(state_dir, 'msshd-user-ca')
    try:
        user_ca = UserCA.load(user_ca_priv_path)
    except (FileNotFoundError, ValueError) as e:
        log.error('cannot load msshd-user-ca from %s: %s. '
                  'Run: msshd-admin init',
                  user_ca_priv_path, e)
        return 2

    # 2. Inner sshd lifecycle — branch on inner.mode.
    inner: 'InnerSshd | PerConnectionInnerSshd'
    if cfg.inner.mode == INNER_MODE_PER_CONNECTION:
        log.info('inner sshd mode: per-connection')
        inner = PerConnectionInnerSshd(
            cfg, state_dir=os.path.join(state_dir, 'inner-sshd'),
            user_ca_pubkey_path=os.path.join(
                state_dir, 'inner-sshd', 'msshd-user-ca.pub'),
        )
    else:
        log.info('inner sshd mode: long-lived')
        inner = InnerSshd(
            cfg, state_dir=os.path.join(state_dir, 'inner-sshd'),
            user_ca_pubkey_path=os.path.join(
                state_dir, 'inner-sshd', 'msshd-user-ca.pub'),
        )
    try:
        await inner.start()
    except Exception as e:
        log.error('inner sshd failed to start: %s', e)
        return 3

    try:
        # 3. CA client.
        try:
            ca_client = MsshdCAClient(cfg)
        except Exception as e:
            log.error('CA client init failed: %s', e)
            await inner.stop()
            return 4

        # 3a. Detect inner sshd binary version (once; logged + forwarded
        #     to the CA on every authz call for fleet-version tracking
        #     and per-version directive-compatibility checks).
        inner_sshd_version = await _detect_sshd_version(cfg.inner.sshd_binary)
        log.info('inner sshd version: %s', inner_sshd_version)

        # 3b. Authz cache (persistent on-disk, loaded at startup).
        # Stores the same grants the CA would return; operator can
        # also inject bypass-cert entries that survive CA outages.
        # Eviction caps configurable via msshd.yaml's
        # performance.authz_cache_max_per_principal +
        # performance.authz_cache_max_total.
        authz_cache = AuthzCache(
            persist_path=os.path.join(state_dir, 'authz_cache.json'),
            max_per_principal=cfg.performance.authz_cache_max_per_principal,
            max_total=cfg.performance.authz_cache_max_total,
        )

        # 3c. CRL sync — pulls revocations from the CA in the
        # background after each authorize call. See crl_sync.py.
        crl_sync = CRLSync(authz_cache, ca_client,
                           fetch_limit=cfg.ca.crl_fetch_limit)

        # 4. The actual outer mTLS listener.
        listener = EnforceListener(
            cfg, user_ca=user_ca, ca_client=ca_client, inner_sshd=inner,
            authz_cache=authz_cache,
            crl_sync=crl_sync,
            inner_sshd_kind='openssh',
            inner_sshd_version=inner_sshd_version,
            msshd_version=MSSHD_VERSION,
            protocol_version=PROTOCOL_VERSION,
        )
        try:
            await listener.start()
        except Exception as e:
            log.error('enforce listener failed to start: %s', e)
            return 5

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)

        serve_task = asyncio.create_task(listener.serve_forever())
        try:
            await stop_event.wait()
            log.info('shutdown signal received')
        finally:
            await listener.stop()
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        return 0
    finally:
        await inner.stop()


def main(argv: list[str] | None = None) -> int:
    # §5.3.1 entry: parse args, load+validate config, run asyncio loop.
    ap = argparse.ArgumentParser(prog='msshd')
    ap.add_argument('--config', default='/etc/mssh/msshd.yaml',
                    help='path to msshd.yaml')
    args = ap.parse_args(argv)

    try:
        cfg = MsshdConfig.load(args.config)
        cfg.validate()
        cfg.check_permissions()
    except (FileNotFoundError, ValueError) as e:
        print(f'config error: {e}', file=sys.stderr)
        return 2
    except Exception as e:
        print(f'config load failed: {e}', file=sys.stderr)
        return 2

    _setup_logging(cfg)
    log.info('msshd starting (mode=%s)', cfg.mode)

    try:
        return asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())
