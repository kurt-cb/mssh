"""Routes for the mssh-admin web portal.

Each route fetches data via the configured CAClient and renders a
Bootstrap-5 template. v1 is read-only with cert-export actions for
users + servers; mutating CRUD lives in a follow-on (§26 v2).
"""

from __future__ import annotations

import io
import tarfile
from collections import defaultdict
from typing import Any

from flask import (Blueprint, Flask, abort, current_app, jsonify,
                   render_template, request, send_file)

from ..client import CAClient, CAClientError


bp = Blueprint('mssh_admin_web', __name__)


def _client() -> CAClient:
    return current_app.config['CA_CLIENT']


def register_views(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- pages -----------------------------------------------------------------

@bp.route('/')
def index():
    """Dashboard — counts + green/red status from the CA."""
    try:
        servers = _client().server_list()
        users = _client().user_list()
        admins = _client().admin_list()
    except CAClientError as e:
        return render_template('error.html', error=str(e)), 502

    # Server-group rollup (CA exposes per-server groups; derive set
    # union here — same trick as the CLI's status command).
    groups: dict[str, list[str]] = defaultdict(list)
    for s in servers:
        for g in s.get('groups') or []:
            groups[g].append(s['name'])

    return render_template('index.html',
                           server_count=len(servers),
                           user_count=len(users),
                           admin_count=len(admins),
                           group_count=len(groups))


@bp.route('/users')
def users():
    try:
        users = _client().user_list()
    except CAClientError as e:
        return render_template('error.html', error=str(e)), 502

    # Sort by username ascending — JS handles re-sorts on click.
    users = sorted(users, key=lambda u: u['username'])
    return render_template('users.html', users=users)


@bp.route('/groups')
def groups():
    """Server groups — derived from server enrollments (CA stores
    groups per-server, not as a first-class entity yet)."""
    try:
        servers = _client().server_list()
        users = _client().user_list()
    except CAClientError as e:
        return render_template('error.html', error=str(e)), 502

    grp_to_servers: dict[str, list[str]] = defaultdict(list)
    for s in servers:
        for g in s.get('groups') or []:
            grp_to_servers[g].append(s['name'])

    # Find which users have policies targeting each group.
    grp_to_users: dict[str, list[str]] = defaultdict(list)
    for u in users:
        for pol in u.get('policies') or []:
            for g in pol.get('server_groups') or []:
                grp_to_users[g].append(u['username'])

    groups_rendered = [
        {
            'name': g,
            'server_count': len(grp_to_servers[g]),
            'user_count': len(set(grp_to_users[g])),
            'servers': sorted(grp_to_servers[g]),
            'users': sorted(set(grp_to_users[g])),
        }
        for g in sorted(set(grp_to_servers) | set(grp_to_users))
    ]
    return render_template('groups.html', groups=groups_rendered)


@bp.route('/hosts')
def hosts():
    try:
        servers = _client().server_list()
    except CAClientError as e:
        return render_template('error.html', error=str(e)), 502

    servers = sorted(servers, key=lambda s: s['name'])
    return render_template('hosts.html', servers=servers)


@bp.route('/audit')
def audit():
    """Audit log — last 100 entries by default; filterable via
    query-string params (?decision=denied&user=alice)."""
    filters = {}
    if 'decision' in request.args:
        filters['decision'] = request.args['decision']
    if 'user' in request.args:
        filters['user'] = request.args['user']
    if 'server' in request.args:
        filters['server'] = request.args['server']
    filters['limit'] = int(request.args.get('limit', 100))

    try:
        rows = _client().audit(**filters).get('entries', [])
    except CAClientError as e:
        return render_template('error.html', error=str(e)), 502

    return render_template('audit.html', rows=rows, filters=filters)


# ---- cert export actions ---------------------------------------------------

@bp.route('/api/server/<name>/mtls', methods=['POST'])
def api_server_mtls(name: str):
    """Re-issue a server's mTLS keypair (the cert msshd uses to
    authenticate to the CA). Returns a tarball with ca-cert.pem +
    <name>-cert.pem + <name>-key.pem — same shape as the CLI's
    `mssh-admin server add --out-dir`.

    Implementation: we DELETE + ADD the server with its existing
    groups, since the CA's add endpoint is also the issue path. The
    CA's signing key stays untouched.
    """
    try:
        servers = _client().server_list()
        existing = next((s for s in servers if s['name'] == name), None)
        if not existing:
            abort(404, f'no server enrolled with name {name!r}')
        groups = list(existing.get('groups') or [])

        _client().server_remove(name)
        resp = _client().server_add(name, groups=groups)
    except CAClientError as e:
        return jsonify({'error': str(e)}), 502

    creds = resp.get('credentials') or {}
    tar_bytes = _tarball({
        'ca-cert.pem':         _ca_pem(),
        f'{name}-cert.pem':    creds.get('cert_pem', ''),
        f'{name}-key.pem':     creds.get('key_pem', ''),
    })
    return send_file(io.BytesIO(tar_bytes),
                     mimetype='application/x-tar',
                     as_attachment=True,
                     download_name=f'{name}-mtls.tar')


@bp.route('/api/user/<username>/pki', methods=['POST'])
def api_user_pki(username: str):
    """Mint a user-facing PKI bundle for ``username``: user-CA pubkey
    (for trust on the operator's workstation) + per-user mTLS cert+key.

    Currently the CA does NOT mint user-facing mTLS certs directly —
    that's the user-facing CA's job ([scripts/mint-user-pki.py](../../../scripts/mint-user-pki.py)).
    For v1 this endpoint returns a 501 with a pointer to the helper
    script. Real flow lands when [§25](../../../design/future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony)
    (mssh-admin pki) lands.
    """
    return jsonify({
        'error': 'not_implemented',
        'detail': (
            'Per-user mTLS cert minting goes through scripts/mint-user-pki.py '
            'today. Web UI integration depends on future-ideas §25 '
            '(mssh-admin pki). The operator workflow remains: '
            'python scripts/mint-user-pki.py --out-dir ... --users '
            f'{username} --servers <name:ip,...>'
        ),
    }), 501


# ---- helpers ---------------------------------------------------------------

def _ca_pem() -> str:
    """Read the CA-cert path the CAClient is configured to trust;
    return its PEM contents for inclusion in the export tarball."""
    from pathlib import Path
    return Path(_client().ca_cert).read_text()


def _tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for name, content in files.items():
            data = content.encode('utf-8')
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600 if name.endswith('-key.pem') else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()
