"""Tool implementations for the mssh-mcp read-only server.

Each tool is a plain function that takes a dict of arguments and
returns a string (the human-readable response the MCP client renders
to the LLM). The MCP transport layer in ``server.py`` is responsible
for the protocol envelope; the tools here are pure data marshaling
over the existing CAClient + state detector.

Keeping the tool surface deliberately small in v1:
  - status, server_list, user_list, user_inspect, audit_search,
    admin_list.

Anything that *mutates* the CA (server_add, user_add, policy_add,
key rotation, …) is out of scope. Mutation requires a write-grant
mechanism described in design/future-ideas.md §12.

Design: §12.4.1 (read-only diagnostics surface — list servers, users,
admins, audit search) + §12.4.3 (TOOL_REGISTRY is the strict-subset
capability allow-list; bypass-cert mint is NEVER allowed per §12.2).
"""
from __future__ import annotations

import json
from typing import Any

from mssh.admin import state as _state
from mssh.admin.client import CAClient, CAClientError


# ---------------------------------------------------------------------------
# Marshaling helpers
# ---------------------------------------------------------------------------


def _format_user(u: dict[str, Any]) -> str:
    """One-line summary of a user record."""
    nkeys = len(u.get('keys') or [])
    npolicies = len(u.get('policies') or [])
    return f'{u["username"]}: {nkeys} key(s), {npolicies} policy(ies)'


def _format_server(s: dict[str, Any]) -> str:
    groups = ', '.join(s.get('groups') or []) or '(no groups)'
    return f'{s["name"]}: groups=[{groups}]'


def _format_state_node(n: _state.StateNode) -> str:
    mark = 'ok' if n.ok else 'NOT_OK'
    parts = [f'[{mark}] {n.message}']
    if not n.ok and n.next_step:
        parts.append(f'  Next: {n.next_step}')
    if not n.ok and n.next_command:
        parts.append(f'  Command: {n.next_command}')
    return '\n'.join(parts)


def _wrap_call(fn, *args, **kwargs) -> tuple[bool, Any]:
    """Run a CAClient call; return (ok, data) so callers don't have
    to import CAClientError."""
    try:
        return True, fn(*args, **kwargs)
    except CAClientError as e:
        return False, f'CA error {e.status}: {e.body}'
    except Exception as e:
        return False, f'unexpected error: {e}'


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def status(*, client: CAClient | None, ca_dir: str | None = None,
           detect_legacy: bool = True) -> str:
    """Return the full deployment-state walk — same content as
    `mssh-admin status`.

    ``client`` may be None; the detector handles that case by reporting
    "admin client configured" as a failing check.
    """
    from pathlib import Path
    s = _state.detect_state(
        ca_dir=Path(ca_dir) if ca_dir else None,
        ca_client=client,
        detect_legacy=detect_legacy,
    )
    return _state.render_status(s)


def server_list(*, client: CAClient, group: str = '',
                name_prefix: str = '') -> str:
    """List enrolled servers, optionally filtered by group or name prefix."""
    ok, data = _wrap_call(
        client.server_list,
        group=group or None,
        name_prefix=name_prefix or None,
    )
    if not ok:
        return data
    if not data:
        return 'No servers enrolled.'
    lines = [f'{len(data)} server(s):']
    lines.extend(f'  - {_format_server(s)}' for s in data)
    return '\n'.join(lines)


def user_list(*, client: CAClient, username: str = '',
              fingerprint: str = '') -> str:
    """List enrolled users with a key + policy count per row."""
    ok, data = _wrap_call(
        client.user_list,
        username=username or None,
        fingerprint=fingerprint or None,
    )
    if not ok:
        return data
    if not data:
        return 'No users enrolled.'
    lines = [f'{len(data)} user(s):']
    lines.extend(f'  - {_format_user(u)}' for u in data)
    return '\n'.join(lines)


def user_inspect(*, client: CAClient, username: str) -> str:
    """Full detail for one user — every key, every policy."""
    if not username:
        return 'username is required'
    ok, data = _wrap_call(client.user_list, username=username)
    if not ok:
        return data
    if not data:
        return f'No user named {username!r}.'
    u = data[0]
    lines = [f'User: {u["username"]}']
    keys = u.get('keys') or []
    if keys:
        lines.append(f'Keys ({len(keys)}):')
        for k in keys:
            lines.append(f'  - {k.get("type", "?")} '
                         f'{k.get("fingerprint", "?")} '
                         f'(key_type={k.get("key_type", "?")})')
    else:
        lines.append('Keys: (none)')
    policies = u.get('policies') or []
    if policies:
        lines.append(f'Policies ({len(policies)}):')
        for p in policies:
            servers = ', '.join(p.get('servers') or []) or '*'
            groups = ', '.join(p.get('server_groups') or []) or '*'
            channels = ', '.join(p.get('channels') or []) or '*'
            cidrs = ', '.join(p.get('source_cidrs') or []) or 'any'
            lines.append(f'  - id={p.get("id", "?")} '
                         f'servers=[{servers}] groups=[{groups}] '
                         f'channels=[{channels}] '
                         f'source_cidrs=[{cidrs}] '
                         f'max_validity={p.get("max_cert_validity_seconds", "?")}s')
            if p.get('force_command'):
                lines.append(f'      force_command: {p["force_command"]}')
    else:
        lines.append('Policies: (none) — user can authenticate but reach no host')
    return '\n'.join(lines)


def audit_search(*, client: CAClient, user: str = '', server: str = '',
                 decision: str = '', since: str = '',
                 limit: int = 50) -> str:
    """Recent authorize decisions. Filters: user, server, decision, since."""
    filters: dict[str, Any] = {}
    if user:
        filters['user'] = user
    if server:
        filters['server'] = server
    if decision:
        if decision not in ('allow', 'deny', 'error'):
            return (f'decision must be one of allow|deny|error, '
                    f'got {decision!r}')
        filters['result'] = decision
    if since:
        filters['since'] = since
    if limit:
        filters['limit'] = int(limit)
    ok, data = _wrap_call(client.audit, **filters)
    if not ok:
        return data
    entries = data.get('entries') if isinstance(data, dict) else data
    entries = entries or []
    if not entries:
        return 'No matching audit entries.'
    lines = [f'{len(entries)} matching audit entr{"y" if len(entries) == 1 else "ies"}:']
    for e in entries[: limit or 50]:
        ts = e.get('timestamp', '?')
        u = e.get('user', '?')
        s = e.get('server', '?')
        result = e.get('decision') or e.get('result') or '?'
        reason = e.get('denied_reason') or ''
        lines.append(f'  [{ts}] {result:>5} {u} → {s}'
                     + (f' ({reason})' if reason else ''))
    return '\n'.join(lines)


def admin_list(*, client: CAClient) -> str:
    """List enrolled admins + their roles."""
    ok, data = _wrap_call(client.admin_list)
    if not ok:
        return data
    if not data:
        return 'No admins enrolled.'
    lines = [f'{len(data)} admin(s):']
    for a in data:
        lines.append(f'  - {a.get("name", "?")} role={a.get("role", "?")}')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Tool registry — what the MCP server exposes
# ---------------------------------------------------------------------------


# Each entry: (name, description, JSON-schema for arguments, callable).
# The callable always takes a `client` keyword (the CAClient instance)
# plus whatever named arguments the schema declares.
# §12.4.3 capability allow-list — strict subset of mssh-admin;
# bypass-cert mint is NEVER allowed per §12.2. All entries here are
# §12.4.1 read-only diagnostics.
TOOL_REGISTRY: list[dict[str, Any]] = [
    {
        'name': 'status',
        'description': 'Show the mssh deployment state — CA reachable, '
                       'admins/servers/users enrolled, every user keyed '
                       'and policied, etc. Returns the same content as '
                       '`mssh-admin status`.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'ca_dir': {
                    'type': 'string',
                    'description': 'Optional path to the CA directory to '
                                   'inspect (default: empty — skips '
                                   'filesystem-only checks).',
                },
                'detect_legacy': {
                    'type': 'boolean',
                    'description': 'Whether to scan for existing '
                                   '/etc/ssh/sshd_config and '
                                   '~/.ssh/authorized_keys on the host '
                                   '(default true).',
                    'default': True,
                },
            },
        },
        'fn': status,
    },
    {
        'name': 'server_list',
        'description': 'List enrolled servers. Optional group filter '
                       'narrows to one server-group.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'group': {'type': 'string',
                          'description': 'Filter to this server-group only.'},
                'name_prefix': {'type': 'string',
                                'description': 'Filter to names starting '
                                               'with this prefix.'},
            },
        },
        'fn': server_list,
    },
    {
        'name': 'user_list',
        'description': 'List enrolled users with a count of their keys and '
                       'policies. Optional username or fingerprint filter.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string',
                             'description': 'Filter to this username.'},
                'fingerprint': {'type': 'string',
                                'description': 'Filter to the user who '
                                               'owns this key fingerprint.'},
            },
        },
        'fn': user_list,
    },
    {
        'name': 'user_inspect',
        'description': 'Show full detail for one user — every key, every '
                       'policy with all its constraints (servers, groups, '
                       'channels, source CIDRs, max validity).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string',
                             'description': 'The user to inspect.'},
            },
            'required': ['username'],
        },
        'fn': user_inspect,
    },
    {
        'name': 'audit_search',
        'description': 'Search the CA audit log for recent authorize '
                       'decisions. Filters: user, server, decision, since '
                       '(human "5 minutes ago" or ISO timestamp). Returns '
                       'up to `limit` matching entries (default 50).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'user': {'type': 'string'},
                'server': {'type': 'string'},
                'decision': {'type': 'string',
                             'enum': ['allow', 'deny', 'error']},
                'since': {'type': 'string'},
                'limit': {'type': 'integer', 'default': 50},
            },
        },
        'fn': audit_search,
    },
    {
        'name': 'admin_list',
        'description': 'List enrolled admins and their roles.',
        'inputSchema': {'type': 'object', 'properties': {}},
        'fn': admin_list,
    },
]


def tool_names() -> list[str]:
    return [t['name'] for t in TOOL_REGISTRY]


def find_tool(name: str) -> dict[str, Any] | None:
    for t in TOOL_REGISTRY:
        if t['name'] == name:
            return t
    return None
