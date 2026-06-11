"""Console entry point for ``mssh-passkey``.

Two run modes (see design/mssh-passkey-module.md § 8):
  - ``front_end: apache`` — bind plain HTTP on localhost; Apache2
    handles TLS + mTLS upstream.
  - ``front_end: dev`` — bind two TLS listeners directly; one
    public HTTPS, one mTLS broker. Used by the adhoc-lab and for
    development.

Design: §8 mssh-passkey broker (see design/mssh_design_v1.md).
"""

from __future__ import annotations

import argparse
import logging
import os
import ssl
import sys
import threading

from .app import create_app
from .callback import CallbackWorker
from .config import Config
from .sweeper import ExpirySweeper


log = logging.getLogger('mssh_passkey')


def _run_apache_mode(app, config: Config) -> int:
    """Plain HTTP bind; Apache2 handles all TLS upstream."""
    listen = config.listen
    log.info('mssh-passkey serving plain HTTP on %s:%d '
             '(Apache2 expected upstream)', listen.bind, listen.port)
    log.info('Apache2 must set X-Client-CN from SSL_CLIENT_S_DN_CN '
             'for any /broker request.')
    app.run(host=listen.bind, port=listen.port,
            use_reloader=False, threaded=True)
    return 0


def _ssl_context_for_public(public: dict) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=public['cert'], keyfile=public['key'])
    return ctx


def _ssl_context_for_broker(broker: dict) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=broker['cert'], keyfile=broker['key'])
    if not broker.get('client_ca_cert'):
        raise ValueError(
            'broker_mtls.client_ca_cert must be set in dev mode')
    ctx.load_verify_locations(cafile=broker['client_ca_cert'])
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _run_dev_mode(app, config: Config) -> int:
    """In-process TLS on two ports. Used by the adhoc-lab + dev.

    Werkzeug doesn't natively expose the mTLS-peer-cert to the WSGI
    environ, so we use a custom request handler that sets the
    X-Client-CN header from the SSL peer cert. See _mTLSHandler
    below.
    """
    listen = config.listen
    if not listen.public_https or not listen.broker_mtls:
        raise ValueError(
            'front_end: dev requires both listen.public_https and '
            'listen.broker_mtls in config')

    from werkzeug.serving import make_server

    public_ctx = _ssl_context_for_public(listen.public_https)
    broker_ctx = _ssl_context_for_broker(listen.broker_mtls)

    # Two listeners. Both serve the same Flask app; they're
    # distinguished by what gets enforced upstream + what header is
    # set. The broker listener wraps the request handler to inject
    # X-Client-CN.
    public = listen.public_https
    broker = listen.broker_mtls

    public_server = make_server(
        host=public['host'], port=int(public['port']),
        app=app, ssl_context=public_ctx, threaded=True)

    broker_server = make_server(
        host=broker['host'], port=int(broker['port']),
        app=app, ssl_context=broker_ctx, threaded=True,
        request_handler=_make_mtls_handler())

    log.info('mssh-passkey dev mode')
    log.info('  public HTTPS  https://%s:%d  (browser-facing)',
             public['host'], public['port'])
    log.info('  broker mTLS   https://%s:%d  (back-end clients)',
             broker['host'], broker['port'])

    t1 = threading.Thread(target=public_server.serve_forever,
                          name='mssh-passkey-public', daemon=True)
    t2 = threading.Thread(target=broker_server.serve_forever,
                          name='mssh-passkey-broker', daemon=True)
    t1.start(); t2.start()
    try:
        t1.join(); t2.join()
    except KeyboardInterrupt:
        public_server.shutdown(); broker_server.shutdown()
    return 0


def _make_mtls_handler():
    """Build a Werkzeug request handler that extracts the peer cert's
    CN and sets it as X-Client-CN in the WSGI environ. Mirrors what
    Apache2 + mod_ssl do upstream in production.
    """
    from werkzeug.serving import WSGIRequestHandler

    class _MTLSRequestHandler(WSGIRequestHandler):
        def make_environ(self):
            env = super().make_environ()
            try:
                peer = self.connection.getpeercert()
            except Exception:
                peer = None
            cn = ''
            if peer:
                for tup in peer.get('subject', ()):
                    for k, v in tup:
                        if k == 'commonName':
                            cn = v
                            break
                    if cn:
                        break
            env['HTTP_X_CLIENT_CN'] = cn
            return env

    return _MTLSRequestHandler


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description='mssh-passkey — WebAuthn ceremony broker (relay-only)')
    p.add_argument('--config', required=False,
                   default=os.environ.get('MSSH_PASSKEY_CONFIG',
                                          '/etc/mssh-passkey/config.yaml'),
                   help='Path to YAML config '
                        '(default: $MSSH_PASSKEY_CONFIG or '
                        '/etc/mssh-passkey/config.yaml)')
    p.add_argument('--log-level', default='INFO',
                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    args = p.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s %(name)s [%(levelname)s] %(message)s')

    try:
        config = Config.load(args.config)
    except (OSError, ValueError) as e:
        log.error('config %s: %s', args.config, e)
        return 2

    app = create_app(config)

    # Background workers — sweeper + callback delivery.
    sweeper = ExpirySweeper(app.config['CEREMONY_STORE'])
    sweeper.start()

    cb_worker = CallbackWorker(app.config['CEREMONY_STORE'],
                                config.callback)
    cb_worker.start()

    try:
        if config.front_end == 'apache':
            return _run_apache_mode(app, config)
        return _run_dev_mode(app, config)
    finally:
        sweeper.stop()
        cb_worker.stop()


if __name__ == '__main__':
    sys.exit(main())
