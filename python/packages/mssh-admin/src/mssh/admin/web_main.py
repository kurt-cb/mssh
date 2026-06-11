"""Entry point for ``msshd-admin-web``.

Starts the Flask admin portal bound to 127.0.0.1 by default. See
design/future-ideas.md §26 for the deployment model (mssh local-port-
forward to this listener; never expose it on a public address).

Design: §11 (mssh-admin-web) + §11.3.4 (auth model — relies on the
mssh-mediated localhost tunnel for caller identity; the portal itself
binds to 127.0.0.1 only).
"""

from __future__ import annotations

import argparse
import sys

from .web import create_app
from .web.app import _ca_client_from_config


def main() -> int:
    p = argparse.ArgumentParser(
        description='Run the mssh-admin web portal (Flask, localhost-only).')
    p.add_argument('--host', default='127.0.0.1',
                   help='bind host (default 127.0.0.1; do NOT expose '
                        'on a public address — see design/future-ideas.md §26)')
    p.add_argument('--port', type=int, default=8443,
                   help='bind port (default 8443)')
    p.add_argument('--config', default=None,
                   help='path to mssh-admin config '
                        '(default ~/.mssh-admin/config or $MSSH_ADMIN_CONFIG)')
    p.add_argument('--dev', action='store_true',
                   help='enable Flask debug + auto-reload (DO NOT use on a '
                        'machine that handles real CA traffic)')
    args = p.parse_args()

    try:
        client = _ca_client_from_config(args.config)
    except Exception as e:
        sys.stderr.write(f'error: {e}\n')
        return 2

    app = create_app(client, dev_mode=args.dev)

    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        sys.stderr.write(
            f'WARNING: binding to {args.host} — this portal expects '
            f'mssh-mediated localhost-only access. See '
            f'design/future-ideas.md §26.\n')

    print(f'mssh-admin web portal: http://{args.host}:{args.port}/',
          file=sys.stderr, flush=True)
    app.run(host=args.host, port=args.port, debug=args.dev,
            use_reloader=args.dev)
    return 0


if __name__ == '__main__':
    sys.exit(main())
