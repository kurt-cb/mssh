"""msshd-admin — operator CLI for msshd.

Operator-side diagnostics for the msshd daemon. Runs locally on the
msshd host; does NOT call out to the CA. Reads on-disk state
(config + persisted authz cache).

Subcommands:
  lint                  Validate msshd.yaml and on-disk file permissions.
  status                Print mode and the listen / fallback config.
  authz-cache status    Inspect the persisted authz cache.

Future (Phase 1B):
  init / rotate-ca / verify (placeholders today).

Design: §5.3.14 (see design/mssh_design_v1.md) — msshd-admin server-side
diagnostic CLI (lint, status, authz-cache status). Reads only on-disk
state; never contacts the CA.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from .config import MsshdConfig


def cmd_lint(args: argparse.Namespace) -> int:
    path = args.config
    try:
        cfg = MsshdConfig.load(path)
    except FileNotFoundError:
        print(f'config not found: {path}', file=sys.stderr)
        return 2
    except Exception as e:
        print(f'config load error: {e}', file=sys.stderr)
        return 2
    try:
        cfg.validate()
        cfg.check_permissions()
    except ValueError as e:
        print(f'config validation failed: {e}', file=sys.stderr)
        return 1
    print(f'OK — {path} valid for mode={cfg.mode}')
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    try:
        cfg = MsshdConfig.load(args.config)
    except FileNotFoundError:
        print(f'config not found: {args.config}', file=sys.stderr)
        return 2
    print(f'mode:             {cfg.mode}')
    print(f'listen:           {cfg.listen.external_address}:'
          f'{cfg.listen.external_port}')
    if cfg.mode == 'fallback':
        print(f'fallback target:  {cfg.fallback.host}:{cfg.fallback.port}')
    else:
        print(f'ca endpoints:     {", ".join(cfg.ca.endpoints) or "(none)"}')
        print(f'inner sshd:       {cfg.inner.sshd_binary}')
        print(f'allowed users:    {", ".join(cfg.users.allowed) or "(none)"}')
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    print('init: not implemented in Phase 1A '
          '(generates local user-CA key + state dirs in Phase 1B)',
          file=sys.stderr)
    return 2


def cmd_rotate_ca(args: argparse.Namespace) -> int:
    print('rotate-ca: not implemented in Phase 1A (see Phase 1B)',
          file=sys.stderr)
    return 2


def cmd_verify(args: argparse.Namespace) -> int:
    print('verify: not implemented in Phase 1A (see Phase 1B)',
          file=sys.stderr)
    return 2


def _state_dir() -> str:
    return os.environ.get('MSSHD_STATE_DIR', '/var/lib/mssh')


def cmd_authz_cache_status(args: argparse.Namespace) -> int:
    # §5.3.14 authz-cache diagnostic: read §14.6 persistence JSON.
    """Inspect the persisted authz cache. Useful for incident response
    (which principals are cached, how many bypass entries vs CA-grant
    entries, what CRL state msshd has applied)."""
    path = (Path(args.cache_path) if args.cache_path
            else Path(_state_dir()) / 'authz_cache.json')
    if not path.exists():
        if args.json:
            print(json.dumps({'status': 'no_cache', 'path': str(path)}))
        else:
            print(f'no authz cache at {path}', file=sys.stderr)
        return 0 if not args.json else 0
    try:
        body = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f'cannot read cache at {path}: {e}', file=sys.stderr)
        return 2

    entries = body.get('entries') or []
    by_source: dict[str, int] = {}
    soonest_expiry: str = ''
    for e in entries:
        src = str(e.get('source') or 'unknown')
        by_source[src] = by_source.get(src, 0) + 1
        na = str(e.get('not_after') or '')
        if na and (not soonest_expiry or na < soonest_expiry):
            soonest_expiry = na

    # Backward-compat: prefer the new last_crl_seqs map; fall back
    # to the legacy single int.
    seqs = body.get('last_crl_seqs')
    if not isinstance(seqs, dict):
        legacy = body.get('last_crl_seq')
        seqs = ({'user-mint': int(legacy)} if isinstance(legacy, int)
                and legacy else {})

    summary = {
        'path': str(path),
        'total_entries': len(entries),
        'by_source': by_source,
        'soonest_expiry': soonest_expiry,
        'last_crl_seqs': seqs,
    }
    if args.verbose:
        summary['entries'] = [{
            'principal': e.get('principal'),
            'serial': e.get('serial'),
            'source': e.get('source'),
            'not_after': e.get('not_after'),
            'injected_at': e.get('injected_at'),
        } for e in entries]

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f'cache:           {path}')
    print(f'total entries:   {len(entries)}')
    if by_source:
        print('by source:')
        for src in sorted(by_source):
            print(f'  {src:<8} {by_source[src]}')
    print(f'soonest expiry:  {soonest_expiry or "(none)"}')
    print('CRL applied (per issuer):')
    if seqs:
        for issuer in sorted(seqs):
            print(f'  {issuer:<14} seq={seqs[issuer]}')
    else:
        print('  (none)')
    if args.verbose:
        print()
        print('entries:')
        for e in entries:
            print(f'  {e.get("principal"):<20}'
                   f' source={e.get("source"):<7}'
                   f' serial={e.get("serial"):<24}'
                   f' not_after={e.get("not_after")}')
    return 0


def main(argv: list[str] | None = None) -> int:
    # §5.3.14 msshd-admin entry: subcommand dispatch.
    ap = argparse.ArgumentParser(prog='msshd-admin')
    ap.add_argument('--config', default='/etc/mssh/msshd.yaml',
                    help='path to msshd.yaml')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('lint',      help='validate msshd.yaml').set_defaults(fn=cmd_lint)
    sub.add_parser('status',    help='print msshd state').set_defaults(fn=cmd_status)
    sub.add_parser('init',      help='generate state dirs + local user-CA').set_defaults(fn=cmd_init)
    sub.add_parser('rotate-ca', help='rotate the local user-CA key').set_defaults(fn=cmd_rotate_ca)
    sub.add_parser('verify',    help='health-check').set_defaults(fn=cmd_verify)
    # authz-cache <subcommand>
    cache_sub = sub.add_parser(
        'authz-cache', help='inspect the persisted authz cache')
    cache_inner = cache_sub.add_subparsers(dest='cache_cmd', required=True)
    cache_status = cache_inner.add_parser(
        'status', help='summary of the on-disk authz cache')
    cache_status.add_argument(
        '--cache-path', default='',
        help='override the cache JSON path '
             '(default: $MSSHD_STATE_DIR/authz_cache.json)')
    cache_status.add_argument(
        '--verbose', action='store_true',
        help='include the full per-entry list, not just the summary')
    cache_status.add_argument(
        '--json', action='store_true',
        help='emit machine-parseable JSON instead of human text')
    cache_status.set_defaults(fn=cmd_authz_cache_status)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    sys.exit(main())
