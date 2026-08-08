"""mssh-admin CLI entry point (click-based).

Design: §7.3.1 (full CLI command tree; full enum in §14.2.2) +
§7.3.2 (2FA 202-Accepted polling loop in ``_handle_2fa_call``) +
§7.3.3 (cert auto-renewal helper, ``cert_renew_cmd``) +
§7.3.4 (PKI ceremony helpers — intermediate rotate / mint-external,
per §2.5).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import click
import yaml

from mssh.ca.cert_minter import bootstrap_ca

from . import formatters
from .client import CAClient, CAClientError
from .key_parser import b64_blob, parse_key_file


CONFIG_PATH_DEFAULT = Path.home() / '.mssh-admin' / 'config'


def _load_cli_config(path: str | Path | None) -> dict[str, Any]:
    p = Path(path) if path else CONFIG_PATH_DEFAULT
    if not p.exists():
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def _make_client(ctx: click.Context) -> CAClient:
    conf = ctx.obj.get('_config', {})
    ca_url = ctx.obj.get('ca_url') or conf.get('ca_url')
    cert = ctx.obj.get('admin_cert') or conf.get('admin_cert')
    key = ctx.obj.get('admin_key') or conf.get('admin_key')
    ca_cert = ctx.obj.get('ca_cert') or conf.get('ca_cert')
    if not all([ca_url, cert, key, ca_cert]):
        raise click.UsageError(
            'must provide --ca-url, --admin-cert, --admin-key, --ca-cert '
            '(or set them in ~/.mssh-admin/config)')
    return CAClient(base_url=ca_url, admin_cert=cert, admin_key=key,
                    ca_cert=ca_cert)


def _output(ctx: click.Context, data: Any) -> None:
    click.echo(formatters.render(data, fmt=ctx.obj.get('format', 'table')))


def _handle_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except CAClientError as e:
        click.echo(f'error: HTTP {e.status}: {e.body}', err=True)
        raise SystemExit(1)


# Poll interval + total timeout when waiting on a 2FA ceremony. The
# broker's TTL sweeper is the authoritative deadline; we just need to
# poll often enough to feel responsive without spamming.
_PASSKEY_POLL_INTERVAL_SECONDS = 2.0
_PASSKEY_POLL_TIMEOUT_SECONDS = 180.0


def _print_qr_to_stderr(url: str) -> None:
    """Render a terminal QR code of the URL to stderr so the operator
    can scan with a phone. Skips silently if stderr isn't a TTY (e.g.
    piped or in CI) or if the qrcode lib isn't importable, since
    neither case is a failure mode for the 2FA flow itself — the URL
    is also printed in clear text directly above."""
    try:
        if not sys.stderr.isatty():
            return
        import qrcode
        qr = qrcode.QRCode(border=1,
                           error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(out=sys.stderr, invert=True)
    except Exception:
        # QR rendering is convenience; never break the auth flow on it.
        pass


def _handle_2fa_call(client, fn, *args, **kwargs):
    """Like `_handle_call`, but recognises the 2FA challenge protocol.

    Server returns ``{'status': 'pending_2fa', ...}`` when the
    operation needs a passkey ceremony. We print the URL (plus a
    terminal QR for phone-scan convenience), poll the ceremony, and
    on approval retry the original request — the second call hits the
    2FA cache and proceeds.
    """
    # §7.3.2 202-Accepted polling loop
    resp = _handle_call(fn, *args, **kwargs)
    if not isinstance(resp, dict) or resp.get('status') != 'pending_2fa':
        return resp
    ceremony_id = resp.get('ceremony_id')
    url = resp.get('url') or '(no URL)'
    click.echo(f'2FA required — approve on your phone:\n    {url}',
               err=True)
    _print_qr_to_stderr(url)
    deadline = time.monotonic() + _PASSKEY_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        time.sleep(_PASSKEY_POLL_INTERVAL_SECONDS)
        poll = _handle_call(client.passkey_poll, ceremony_id)
        if poll.get('status') == 'pending':
            continue
        outcome = poll.get('outcome')
        if outcome == 'approved':
            click.echo('  ✓ approved — retrying operation', err=True)
            return _handle_call(fn, *args, **kwargs)
        if outcome == 'denied':
            click.echo('error: 2FA denied by user', err=True)
            raise SystemExit(2)
        if outcome == 'expired':
            click.echo('error: 2FA ceremony expired', err=True)
            raise SystemExit(2)
        click.echo(f'error: unexpected 2FA outcome: {outcome!r}', err=True)
        raise SystemExit(2)
    click.echo('error: 2FA timed out waiting for approval', err=True)
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Group + global options
# ---------------------------------------------------------------------------

@click.group()
@click.option('--config', 'config_path', type=click.Path(),
              help='Path to mssh-admin config (default: ~/.mssh-admin/config).')
@click.option('--ca-url')
@click.option('--admin-cert', type=click.Path())
@click.option('--admin-key', type=click.Path())
@click.option('--ca-cert', type=click.Path())
@click.option('--format', 'output_format',
              type=click.Choice(['table', 'json', 'yaml']), default='table')
@click.pass_context
def cli(ctx, config_path, ca_url, admin_cert, admin_key, ca_cert, output_format):
    """mssh-admin — management CLI for mssh."""
    # §7.3.1 CLI command tree root (full enum in §14.2.2)
    ctx.ensure_object(dict)
    ctx.obj['_config'] = _load_cli_config(config_path)
    ctx.obj['ca_url'] = ca_url
    ctx.obj['admin_cert'] = admin_cert
    ctx.obj['admin_key'] = admin_key
    ctx.obj['ca_cert'] = ca_cert
    ctx.obj['format'] = output_format


# ---------------------------------------------------------------------------
# init (no CA call — writes config + bootstrap admin cert)
# ---------------------------------------------------------------------------

# §15.23 — per-kind validity defaults written as documented YAML so
# operators can see + tune them in place.
_CERT_KINDS_YAML_BLOCK = """

# ============================================================================
# §15.23 — Per-kind certificate validity policy.
#
# Operators tune defaults + caps per cert kind here. Each kind's lookup
# falls through in this order:
#   1. per_kind[<kind>][default|max]
#   2. default_validity_days / default_max_validity_days below
#   3. mssh built-in baseline for that kind (matches v0.4.x byte-for-byte)
# So you can comment out per_kind entries and the CA still has a working
# default per kind.
# ============================================================================
cert_kinds:
  default_validity_days:     90
  default_max_validity_days: 825

  per_kind:
    # Per-session authz certs — intentionally very short-lived.
    authz-user:
      default_validity_days: 1      # 24 hours
      max_validity_days:     7      # 1 week ceiling

    # Operator's offline bypass credential — longer-lived but bounded.
    authz-bypass:
      default_validity_days: 90
      max_validity_days:     3650   # 10 years (v0.4.x cap)

    # Server identifies itself to the network; rotation hygiene matters.
    server-tls:
      default_validity_days: 365
      max_validity_days:     825

    # Operator -> CA admin mTLS.
    admin-mtls:
      default_validity_days: 365
      max_validity_days:     825

    # Enrolled msshd -> CA mTLS.
    client-mtls:
      default_validity_days: 365
      max_validity_days:     825

    # Browser -> admin-web; shorter so revocation latency is bounded.
    https-user:
      default_validity_days: 90
      max_validity_days:     825

    # VPN — short-lived; CRL latency matters less when certs cycle fast.
    openvpn:
      default_validity_days: 90
      max_validity_days:     365

    # Code-signing certs — medium-lived.
    code-sign:
      default_validity_days: 365
      max_validity_days:     1825   # 5 years

    # External-use (device-identity, BMC, firmware-id, etc.) — very
    # long lifetimes. --never-expires available for ROM-burned identifiers.
    external-use:
      default_validity_days: 7305   # 20 years
      max_validity_days:     9125   # 25 years
"""

# §15.21 — operator-OID allowlist with reserved-arc commentary.
_CUSTOM_OIDS_YAML_BLOCK = """

# ============================================================================
# §15.21 — Operator-defined X.509 extension OIDs accepted on cert mints.
#
# Each entry declares an OID the operator may pass via cert-mint requests
# (`--custom-oid <oid|name>=<value>`). Requests carrying any OID NOT
# listed below are rejected (strict allowlist; default-deny).
#
# OID ARCS:
#
#   1.3.6.1.4.1.55555.[1-4999].*   - RESERVED for mssh. Hard-rejected even
#                                    if allowlisted; the CA refuses to start
#                                    with a config error.
#
#   1.3.6.1.4.1.55555.[5000-65535].*  - OPERATOR sub-arc. Assigned by mssh
#                                       for your own custom OIDs. Use this
#                                       if you don't have an IANA PEN of
#                                       your own; entries here are not
#                                       globally unique so don't use them
#                                       for certs verified outside your
#                                       organization.
#
#   1.3.6.1.4.1.<your-PEN>.*       - Your own IANA Private Enterprise
#                                    Number arc (https://pen.iana.org/).
#                                    Use this if certs will be verified
#                                    by external parties.
#
# Reserved mssh sub-arcs (informational; cannot be allowlisted):
#
#   .1.*  authz/bypass cert policy fields (§14.5)
#     .1  OID_SOURCE_BIND     UTF8       authz: source principal
#     .2  OID_SERVER_BIND     UTF8       authz: target server
#     .3  OID_CHANNEL_POLICY  SEQ UTF8   authz: channel permissions
#     .4  OID_FORCE_COMMAND   UTF8 *crit authz: forced SSH command
#     .5  OID_ENVIRONMENT     UTF8 *crit authz: environment vars
#     .6  OID_MAX_SESSION     INTEGER    authz: max concurrent sessions
#     .7  OID_2FA_EVIDENCE    UTF8       authz: 2FA proof
#     .8  OID_CA_BYPASS       NULL *crit bypass-cert marker
#
#   .2.*  intermediate-purpose markers (§15.20, §15.23)
#     .1  OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE  NULL
#
#   .3.*  leaf cert-kind markers (§15.23)
#     .1  OID_KIND_AUTHZ_USER     .2  OID_KIND_AUTHZ_BYPASS
#     .3  OID_KIND_SERVER_TLS     .4  OID_KIND_ADMIN_MTLS
#     .5  OID_KIND_CLIENT_MTLS    .6  OID_KIND_HTTPS_USER
#     .7  OID_KIND_CODE_SIGN      .8  OID_KIND_OPENVPN
#     .9  OID_KIND_EXTERNAL_USE
#
# Examples below use the mssh operator sub-arc so no IANA registration
# is needed. Uncomment + adapt for your use case.
# ============================================================================
custom_oids: []

# Example: operator-defined OIDs for external-use device-identity certs.
# Uncomment to enable:
#
# custom_oids:
#   - oid:         1.3.6.1.4.1.55555.5001.1
#     name:        device_oem
#     encoding:    utf8
#     max_length:  64
#     description: "OEM identifier (external-use device-identity profile)"
#
#   - oid:         1.3.6.1.4.1.55555.5001.2
#     name:        device_serial
#     encoding:    utf8
#     max_length:  128
#     description: "Device serial number (per-unit; opaque)"
"""

@cli.command()
@click.option('--ca-dir', required=True, type=click.Path(),
              help='Directory to write CA keys and certs into.')
@click.option('--bootstrap-admin', default='bootstrap-admin',
              help='CN for the initial superuser admin cert.')
@click.option('--tls-server-cn', default='mssh-ca',
              help='CN for the CA\'s TLS server cert.')
@click.option('--tls-server-san', multiple=True,
              help='SubjectAltName for the CA\'s TLS server cert (repeatable). '
                   'Default: DNS:localhost, IP:127.0.0.1.')
@click.option('--root-cn', default=None,
              help='CN for the self-signed Root CA. Default: '
                   '`<hostname> Root CA` (derived at init from '
                   'socket.gethostname()). Set to something recognizable '
                   'so operators can distinguish this CA from others '
                   'in a trust-store listing or audit log.')
def init(ca_dir, bootstrap_admin, tls_server_cn, tls_server_san, root_cn):
    """Initialize a fresh CA: signing key + bootstrap admin cert."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)
    ca_dir = Path(ca_dir)
    if any(ca_dir.glob('*.pem')) and ca_dir.exists():
        raise click.UsageError(f'{ca_dir} already contains certs; refusing to overwrite')
    sans = list(tls_server_san) or ['DNS:localhost', 'IP:127.0.0.1']
    artifacts = bootstrap_ca(
        ca_dir, bootstrap_admin_cn=bootstrap_admin,
        tls_server_cn=tls_server_cn, tls_server_sans=sans,
        root_cn=root_cn,
    )

    # Drop a default ca-config.yaml so the user can run the server immediately.
    ca_config = {
        'listen': '127.0.0.1:8443',
        'signing_key': str(ca_dir / 'signing-key.pem'),
        'signing_cert': str(ca_dir / 'signing-cert.pem'),
        'tls_cert': str(ca_dir / 'tls-server-cert.pem'),
        'tls_key': str(ca_dir / 'tls-server-key.pem'),
        'client_ca_cert': str(ca_dir / 'tls-ca-cert.pem'),
        'identity_trust_roots': [],
        'enrollment': {'type': 'file', 'path': str(ca_dir / 'enrollment.yaml')},
        'audit': {'type': 'file', 'path': str(ca_dir / 'audit.jsonl')},
        'defaults': {'max_cert_validity_seconds': 3600,
                     'timestamp_drift_seconds': 60},
        'cert_generation': {'key_type': 'ec',
                            'server_cert_validity_days': 365,
                            'admin_cert_validity_days': 365},
    }
    base_yaml = yaml.safe_dump(ca_config, sort_keys=True)
    # §15.23 cert_kinds + §15.21 custom_oids — written as documented text
    # rather than via yaml.safe_dump so the reserved-arc commentary stays
    # in-file for operators to discover.
    documented = _CERT_KINDS_YAML_BLOCK + _CUSTOM_OIDS_YAML_BLOCK
    (ca_dir / 'ca-config.yaml').write_text(base_yaml + documented)

    # Empty enrollment file so the CA can boot. Seed it with the bootstrap admin.
    enroll = {
        'admins': {
            bootstrap_admin: {
                'role': 'superuser',
                'mtls_subject': f'CN={bootstrap_admin}',
                'enrolled_at': '', 'enrolled_by': 'init',
            }
        }
    }
    (ca_dir / 'enrollment.yaml').write_text(yaml.safe_dump(enroll, sort_keys=True))

    click.echo(f'CA initialized in {ca_dir}')
    click.echo(f'Bootstrap admin cert: {ca_dir}/bootstrap-admin-cert.pem')
    click.echo(f'Bootstrap admin key:  {ca_dir}/bootstrap-admin-key.pem')
    click.echo(f'CA config:            {ca_dir}/ca-config.yaml')


# ---------------------------------------------------------------------------
# status / next — adoption-state introspection
# ---------------------------------------------------------------------------

def _build_state_client(ctx, ca_dir):
    """Best-effort CAClient builder for status/next. Returns None if we
    can't construct one — state.detect_state() reports the gap as one of
    its checks rather than crashing."""
    from .client import CAClient
    from . import state as _state

    # First try the global --ca-url / --admin-cert / etc. options.
    try:
        return _make_client(ctx)
    except click.UsageError:
        pass

    # Fall back to bootstrap creds inside ca_dir, if it exists.
    if not ca_dir:
        return None
    ca_dir = Path(ca_dir)
    if not ca_dir.is_dir():
        return None
    url = _state.ca_url_from_config(ca_dir)
    cert = ca_dir / 'bootstrap-admin-cert.pem'
    key = ca_dir / 'bootstrap-admin-key.pem'
    root = ca_dir / 'tls-ca-cert.pem'
    if not (url and cert.exists() and key.exists() and root.exists()):
        return None
    return CAClient(base_url=url, admin_cert=str(cert),
                    admin_key=str(key), ca_cert=str(root))


@cli.command()
@click.option('--ca-dir', type=click.Path(),
              help='CA directory to inspect (default: try config-defined dir).')
@click.option('--no-legacy-detect', is_flag=True,
              help='Skip detection of existing sshd_config / authorized_keys '
                   'on the local host.')
@click.pass_context
def status(ctx, ca_dir, no_legacy_detect):
    """Show current deployment state — what's set up, what's not."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)
    from . import state as _state
    ca_dir_path = Path(ca_dir) if ca_dir else None
    client = _build_state_client(ctx, ca_dir_path)
    s = _state.detect_state(ca_dir=ca_dir_path, ca_client=client,
                            detect_legacy=not no_legacy_detect)
    click.echo(_state.render_status(s))


@cli.command(name='next')
@click.option('--ca-dir', type=click.Path())
@click.option('--no-legacy-detect', is_flag=True)
@click.pass_context
def next_cmd(ctx, ca_dir, no_legacy_detect):
    """Show only the next step in adoption — what to do right now."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)
    from . import state as _state
    ca_dir_path = Path(ca_dir) if ca_dir else None
    client = _build_state_client(ctx, ca_dir_path)
    s = _state.detect_state(ca_dir=ca_dir_path, ca_client=client,
                            detect_legacy=not no_legacy_detect)
    click.echo(_state.render_next(s))


# ---------------------------------------------------------------------------
# server commands
# ---------------------------------------------------------------------------

@cli.group()
def server():
    """Server enrollment commands."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@server.command('add')
@click.option('--name', required=True)
@click.option('--groups', default='', help='Comma-separated group list.')
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def server_add(ctx, name, groups, out_dir):
    groups_list = [g.strip() for g in groups.split(',') if g.strip()]
    c = _make_client(ctx)
    resp = _handle_call(c.server_add, name, groups_list)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        (od / 'ca-cert.pem').write_text(resp['credentials']['ca_cert_pem'])
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['server'])


@server.command('remove')
@click.option('--name', required=True)
@click.pass_context
def server_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_remove, name))


@server.command('list')
@click.option('--group', help='Filter to a specific group.')
@click.option('--name', help='Filter to servers whose name starts with this prefix.')
@click.pass_context
def server_list(ctx, group, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_list, group=group, name_prefix=name))


@server.command('show')
@click.option('--name', required=True,
              help='Server canonical name to look up.')
@click.pass_context
def server_show(ctx, name):
    """Inspect a single server's enrollment record."""
    c = _make_client(ctx)
    matches = _handle_call(c.server_list, name_prefix=name)
    # Walk for an exact name match; --name as prefix is a filter.
    exact = [s for s in matches if s.get('name') == name]
    if not exact:
        click.echo(f'error: no server named {name!r}', err=True)
        ctx.exit(1)
    _output(ctx, exact[0])


@server.command('groups')
@click.option('--name', required=True, help='Server to modify.')
@click.option('--add', multiple=True,
              help='Add this group (repeatable). e.g. --add ops --add prod')
@click.option('--remove', multiple=True,
              help='Remove this group (repeatable).')
@click.option('--set', 'set_groups', default=None,
              help='Replace the group list with this comma-separated list. '
                   'Mutually exclusive with --add / --remove.')
@click.pass_context
def server_groups(ctx, name, add, remove, set_groups):
    """Manage a server's group memberships at runtime.

    Group changes take effect on the next authorize call (CA cache is
    keyed by principal, not by server-groups).
    """
    if set_groups is not None and (add or remove):
        click.echo('error: --set is mutually exclusive with --add/--remove',
                   err=True)
        ctx.exit(2)
    c = _make_client(ctx)
    if set_groups is not None:
        new_groups = [g.strip() for g in set_groups.split(',') if g.strip()]
    else:
        # Compute from current state + add/remove.
        matches = _handle_call(c.server_list, name_prefix=name)
        srv = next((s for s in matches if s.get('name') == name), None)
        if srv is None:
            click.echo(f'error: no server named {name!r}', err=True)
            ctx.exit(1)
        current = set(srv.get('groups') or [])
        new_groups = sorted(current.union(add) - set(remove))
    _output(ctx, _handle_call(c.server_set_groups, name, new_groups))


# ---------------------------------------------------------------------------
# user commands
# ---------------------------------------------------------------------------

@cli.group()
def user():
    """User enrollment commands."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@user.command('add')
@click.option('--user', 'username', required=True)
@click.option('--key', 'key_path', type=click.Path(exists=True),
              help='SSH pubkey or OpenSSH cert file. Creates user if missing.')
@click.option('--cert', 'cert_path', type=click.Path(exists=True),
              help='OpenSSH cert file (alias of --key for clarity).')
@click.pass_context
def user_add(ctx, username, key_path, cert_path):
    c = _make_client(ctx)
    try:
        _handle_call(c.user_add, username)
    except SystemExit:
        # user may already exist — continue and let the key add report
        pass
    path = key_path or cert_path
    if path:
        parsed = parse_key_file(path)
        resp = _handle_call(c.user_key_add, username, parsed.type, b64_blob(parsed))
        _output(ctx, resp['key'])
    else:
        _output(ctx, {'user_added': username})


@user.command('remove')
@click.option('--user', 'username', required=True)
@click.pass_context
def user_remove(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_2fa_call(c, c.user_remove, username))


@user.command('remove-key')
@click.option('--user', 'username', required=True)
@click.option('--fingerprint', required=True)
@click.pass_context
def user_remove_key(ctx, username, fingerprint):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_key_remove, username, fingerprint))


@user.command('list')
@click.option('--user', 'username')
@click.pass_context
def user_list(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_list, username=username))


@user.command('show')
@click.option('--user', 'username', required=True,
              help='User to look up.')
@click.pass_context
def user_show(ctx, username):
    """Inspect a single user's enrollment record. Same data as
    `user list --user X` but errors clearly if the user isn't enrolled."""
    c = _make_client(ctx)
    users = _handle_call(c.user_list, username=username)
    exact = [u for u in users if u.get('username') == username]
    if not exact:
        click.echo(f'error: no user named {username!r}', err=True)
        ctx.exit(1)
    _output(ctx, exact[0])


# ---------------------------------------------------------------------------
# user passkey commands — admin-2FA enrollment (design/admin-2fa.md)
# ---------------------------------------------------------------------------

@user.group('passkey')
def user_passkey():
    """Manage admin passkey credentials for 2FA on privileged operations."""


@user_passkey.command('enroll')
@click.option('--user', 'admin_name', required=True,
              help='The enrolled admin whose phone will register a passkey.')
@click.option('--label', default='',
              help='Operator-visible label for the credential, e.g. '
                   '"alice yubikey 5C".')
@click.option('--display-name', default='',
              help='Display name shown on the registration page '
                   '(defaults to the admin name).')
@click.pass_context
def user_passkey_enroll_cmd(ctx, admin_name, label, display_name):
    """Mint a one-time URL the admin opens on their phone to register
    a new passkey.

    The URL expires in 5 minutes. mssh-ca records the credential
    against the admin's enrollment record when the broker callback
    fires after the WebAuthn ceremony completes.
    """
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_enroll, admin_name,
                       label=label, display_name=display_name)
    click.echo('passkey enrollment URL (1-time, expires in 5 min):', err=True)
    click.echo(f'  {out["url"]}', err=True)
    click.echo('Open this on the admin\'s phone and follow the prompts.', err=True)
    _output(ctx, {
        'ceremony_id': out['ceremony_id'],
        'expires_at': out['expires_at'],
    })


@user_passkey.command('list')
@click.option('--user', 'admin_name', required=True)
@click.pass_context
def user_passkey_list_cmd(ctx, admin_name):
    """List registered passkey credentials for an admin."""
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_list, admin_name)
    _output(ctx, out['credentials'])


@user_passkey.command('revoke')
@click.option('--user', 'admin_name', required=True)
@click.option('--credential-id', required=True,
              help='base64url credential ID, as shown by `list`.')
@click.pass_context
def user_passkey_revoke_cmd(ctx, admin_name, credential_id):
    """Revoke one passkey credential.

    Active 2FA cache entries for this admin are also invalidated.
    """
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_revoke, admin_name, credential_id)
    _output(ctx, out)


# ---------------------------------------------------------------------------
# policy commands
# ---------------------------------------------------------------------------

@cli.group()
def policy():
    """Policy commands."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@policy.command('add')
@click.option('--user', 'username', required=True)
@click.option('--servers', default='', help='Comma-separated server canonical names.')
@click.option('--server-groups', default='', help='Comma-separated group names.')
@click.option('--channels', required=True,
              help='Comma-separated channel types (e.g. session,direct-tcpip).')
@click.option('--source-cidrs', default='')
@click.option('--max-validity', 'max_validity', default=3600, type=int)
@click.option('--force-command', default=None)
@click.option('--require-2fa', 'require_2fa',
              type=click.Choice(['none', 'passkey']), default='none',
              help='Require an additional factor for actions matching '
                   'this policy. "passkey" triggers a mssh-passkey '
                   'ceremony before mssh-ca executes the action; the '
                   'CLI shows a one-time URL the operator opens on '
                   'their phone.')
@click.option('--2fa-within-seconds', 'twofa_within_seconds',
              type=int, default=60,
              help='Cache window (seconds) after a successful 2FA. '
                   'Subsequent matching actions within the window '
                   'skip the prompt. Default 60.')
@click.pass_context
def policy_add(ctx, username, servers, server_groups, channels, source_cidrs,
               max_validity, force_command, require_2fa, twofa_within_seconds):
    def _split(s): return [x.strip() for x in s.split(',') if x.strip()]
    policy = {
        'servers': _split(servers),
        'server_groups': _split(server_groups),
        'channels': _split(channels),
        'source_cidrs': _split(source_cidrs),
        'max_cert_validity_seconds': max_validity,
        'force_command': force_command,
        'require_2fa': require_2fa,
        'twofa_within_seconds': twofa_within_seconds,
    }
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_add, username, policy))


@policy.command('remove')
@click.option('--id', 'policy_id', required=True)
@click.pass_context
def policy_remove(ctx, policy_id):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_remove, policy_id))


# ---------------------------------------------------------------------------
# admin commands
# ---------------------------------------------------------------------------

@cli.group()
def admin():
    """Admin user commands (superuser-only operations)."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@admin.command('add')
@click.option('--name', required=True)
@click.option('--role', required=True,
              type=click.Choice(['superuser', 'server-admin', 'user-admin', 'auditor']))
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def admin_add(ctx, name, role, out_dir):
    c = _make_client(ctx)
    resp = _handle_2fa_call(c, c.admin_add, name, role)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['admin'])


@admin.command('remove')
@click.option('--name', required=True)
@click.pass_context
def admin_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_2fa_call(c, c.admin_remove, name))


@admin.command('list')
@click.pass_context
def admin_list(ctx):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.admin_list))


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command('audit')
@click.option('--type', 'type_', default='all')
@click.option('--decision')
@click.option('--user', 'username')
@click.option('--server', 'srv')
@click.option('--limit', default=100, type=int)
@click.pass_context
def audit(ctx, type_, decision, username, srv, limit):
    # §7.3.1 CLI command tree (full enum in §14.2.2)
    c = _make_client(ctx)
    out = _handle_call(c.audit, type=type_, decision=decision,
                       username=username, server=srv, limit=limit)
    _output(ctx, out.get('entries', []))


# ---------------------------------------------------------------------------
# template — per-scope inner sshd_config templates (Phase 1d)
# ---------------------------------------------------------------------------

@cli.group('template')
def template_group():
    """Manage CA-side inner sshd config templates."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


def _resolve_scope(scope: str, name: str | None) -> tuple[str, str | None]:
    if scope not in ('default', 'group', 'server'):
        raise click.UsageError(
            "--scope must be one of: default, group, server")
    if scope in ('group', 'server') and not name:
        raise click.UsageError(f'--scope {scope} requires --name')
    if scope == 'default' and name:
        raise click.UsageError("--scope default doesn't take --name")
    return scope, name


@template_group.command('list')
@click.pass_context
def template_list_cmd(ctx):
    """Show all stored templates (built-in + default + groups + servers)."""
    c = _make_client(ctx)
    out = _handle_call(c.template_list)
    _output(ctx, out.get('templates', {}))


@template_group.command('show')
@click.option('--scope', default='default',
              help='default | group | server | effective')
@click.option('--name',
              help='Required for scope=group/server/effective.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_show(ctx, scope, name, kind):
    """Print the template for a scope to stdout. For scope=effective the
    output is what would actually be used at session time (after
    walking per-server → per-group → default → built-in precedence)."""
    c = _make_client(ctx)
    if scope == 'effective':
        if not name:
            raise click.UsageError('--scope effective requires --name')
        out = _handle_call(c.template_effective, name, kind=kind)
        click.echo(f'# source={out["source"]} '
                   f'detail={out.get("source_detail") or "-"}',
                   err=True)
        click.echo(out['content'], nl=False)
        return
    out = _handle_call(c.template_list)
    tpls = out.get('templates', {})
    if scope == 'default':
        content = tpls.get('default', {}).get(kind)
    elif scope == 'group':
        _resolve_scope('group', name)
        content = (tpls.get('groups', {}).get(name) or {}).get(kind)
    elif scope == 'server':
        _resolve_scope('server', name)
        content = (tpls.get('servers', {}).get(name) or {}).get(kind)
    else:
        raise click.UsageError(
            "--scope must be one of: default, group, server, effective")
    if content is None:
        click.echo(f'(no override for scope={scope} name={name} '
                   f'kind={kind}; showing built-in)', err=True)
        click.echo(tpls.get('builtin', {}).get(kind, ''), nl=False)
    else:
        click.echo(content, nl=False)


@template_group.command('set')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.option('--content-file', type=click.Path(exists=False),
              help='Read template from this file. Use - for stdin.')
@click.pass_context
def template_set_cmd(ctx, scope, name, kind, content_file):
    """Set the template at this scope from a file or stdin."""
    scope, name = _resolve_scope(scope, name)
    if not content_file:
        raise click.UsageError('--content-file is required')
    if content_file == '-':
        content = click.get_text_stream('stdin').read()
    else:
        p = Path(content_file)
        if not p.exists():
            raise click.UsageError(f'no such file: {content_file}')
        content = p.read_text()
    c = _make_client(ctx)
    out = _handle_call(c.template_set, scope, kind, content, scope_name=name)
    _output(ctx, out)


@template_group.command('unset')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_unset_cmd(ctx, scope, name, kind):
    """Remove the template override at this scope (revert to the
    next-level fallback). Idempotent."""
    scope, name = _resolve_scope(scope, name)
    c = _make_client(ctx)
    out = _handle_call(c.template_unset, scope, kind, scope_name=name)
    _output(ctx, out)


@template_group.command('edit')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_edit(ctx, scope, name, kind):
    """Open the current template in $EDITOR; save back on exit.

    For default: starts from the existing override or the built-in.
    For group / server: starts from the current effective template (so
    the editor opens the directives that are actually in force, ready
    to override). Saving with no changes is a no-op.
    """
    import subprocess
    import tempfile
    scope, name = _resolve_scope(scope, name)
    c = _make_client(ctx)

    if scope == 'default':
        snapshot = _handle_call(c.template_list).get('templates', {})
        current = (snapshot.get('default', {}).get(kind)
                   or snapshot.get('builtin', {}).get(kind, ''))
    elif scope == 'server':
        eff = _handle_call(c.template_effective, name, kind=kind)
        current = eff['content']
    else:  # group
        snapshot = _handle_call(c.template_list).get('templates', {})
        current = ((snapshot.get('groups', {}).get(name) or {}).get(kind)
                   or snapshot.get('default', {}).get(kind)
                   or snapshot.get('builtin', {}).get(kind, ''))

    editor = os.environ.get('VISUAL') or os.environ.get('EDITOR') or 'vi'
    with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sshd_config.template', delete=False) as f:
        f.write(current)
        tmp_path = f.name
    try:
        rc = subprocess.call([editor, tmp_path])
        if rc != 0:
            click.echo(f'editor exited {rc}; not saving', err=True)
            return
        new_content = Path(tmp_path).read_text()
        if new_content == current:
            click.echo('no changes; not saving.', err=True)
            return
        out = _handle_call(c.template_set, scope, kind, new_content,
                           scope_name=name)
        _output(ctx, out)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@template_group.command('diff')
@click.argument('server_name')
@click.option('--kind', default='openssh')
@click.option('--against', default='builtin',
              help='What to diff against: builtin | default')
@click.pass_context
def template_diff(ctx, server_name, kind, against):
    """Show how a server's effective template differs from baseline.

    Useful for audits — "which hosts are special, and why?"
    """
    import difflib
    c = _make_client(ctx)
    eff = _handle_call(c.template_effective, server_name, kind=kind)
    snapshot = _handle_call(c.template_list).get('templates', {})
    if against == 'builtin':
        baseline = snapshot.get('builtin', {}).get(kind, '')
        baseline_label = f'builtin/{kind}'
    elif against == 'default':
        baseline = (snapshot.get('default', {}).get(kind)
                    or snapshot.get('builtin', {}).get(kind, ''))
        baseline_label = f'default/{kind}'
    else:
        raise click.UsageError("--against must be 'builtin' or 'default'")
    eff_label = f'{eff["source"]}/{eff.get("source_detail") or kind}'
    diff_lines = difflib.unified_diff(
        baseline.splitlines(keepends=True),
        eff['content'].splitlines(keepends=True),
        fromfile=baseline_label,
        tofile=f'{server_name} ({eff_label})',
    )
    diff_text = ''.join(diff_lines)
    if not diff_text:
        click.echo(f"(no difference between {server_name}'s effective "
                   f'template and {baseline_label})')
    else:
        click.echo(diff_text, nl=False)


# ---------------------------------------------------------------------------
# CA-bypass cert
# ---------------------------------------------------------------------------

@cli.group('bypass-cert')
def bypass_cert_group():
    """Mint operator-presentable CA-bypass authz certs.

    A bypass cert is a normal authz cert with one extra marker
    extension. The operator stores it offline; when presented via
    `mssh --inject-bypass-cert <cert>`, msshd validates the cert and
    injects it directly into its authz cache without a live CA call.
    Lets the operator reach msshd hosts whose CA is currently
    unreachable. See archive/design/notes-bypass-cache.md.
    """
    # §7.3.1 CLI command tree (full enum in §14.2.2)


def _read_ssh_pubkey_blob(path: str) -> bytes:
    """Read an OpenSSH-format ``.pub`` file and return the raw
    wire-format pubkey blob (the bit between ``ssh-ed25519 `` and the
    optional comment)."""
    text = Path(path).read_text().strip()
    parts = text.split()
    if len(parts) < 2:
        raise click.ClickException(
            f'{path}: not an SSH public key (expected '
            f'"<type> <base64> [comment]")')
    import base64 as _b64
    try:
        return _b64.b64decode(parts[1], validate=True)
    except Exception as e:
        raise click.ClickException(f'{path}: bad base64: {e}')


@bypass_cert_group.command('mint')
@click.argument('username')
@click.option('--pubkey', 'pubkey_path', required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="Path to the user's .pub file (the SSH pubkey to "
                   'bind into the bypass cert).')
@click.option('--valid-days', type=int, default=90,
              show_default=True,
              help='Bypass cert validity window in days.')
@click.option('--source-bind', default=None,
              help='Restrict bypass to a source CIDR. Default: any.')
@click.option('--server-bind', default=None,
              help='Restrict bypass to a server pattern. '
                   'Default: any.')
@click.option('--force-command', default=None,
              help='Force a specific command for bypass sessions '
                   '(e.g. /usr/local/bin/emergency-shell).')
@click.option('--max-session-seconds', type=int, default=None,
              help='Cap each bypass session duration.')
@click.option('--out', 'out_path',
              type=click.Path(dir_okay=False),
              help='Write the minted PEM cert to this path '
                   '(default: stdout).')
@click.pass_context
def bypass_cert_mint_cmd(ctx, username, pubkey_path, valid_days,
                         source_bind, server_bind, force_command,
                         max_session_seconds, out_path):
    """Mint a CA-bypass authz cert for USERNAME and write the PEM.

    Example:
        mssh-admin bypass-cert mint alice \
            --pubkey ~/.ssh/alice.pub \
            --valid-days 90 \
            --out alice-bypass.crt
    """
    import base64 as _b64
    c = _make_client(ctx)
    pubkey_blob = _read_ssh_pubkey_blob(pubkey_path)
    pubkey_b64 = _b64.b64encode(pubkey_blob).decode('ascii')

    out = _handle_call(
        c.bypass_cert_mint, username, pubkey_b64,
        validity_days=valid_days,
        source_bind=source_bind, server_bind=server_bind,
        force_command=force_command,
        max_session_seconds=max_session_seconds,
    )

    cert_pem = out.get('cert_pem', '')
    if out_path:
        Path(out_path).write_text(cert_pem)
        click.echo(f'wrote {out_path}', err=True)
    else:
        click.echo(cert_pem, nl=False)
    click.echo(
        f'\n# username={out["username"]} serial={out["serial"]} '
        f'not_after={out["not_after"]}',
        err=True)


# ---------------------------------------------------------------------------
# CRL / cert revocation
# ---------------------------------------------------------------------------

@cli.group('cert')
def cert_group():
    """Manage authz certs minted by this CA (revoke, §5 mint, …)."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@cert_group.command('mint')
@click.option('--type', 'cert_type',
              type=click.Choice(['tls-server', 'https-user', 'code-sign']),
              required=True,
              help='Cert flavor. tls-server: serverAuth EKU + optional SANs. '
                   'https-user: clientAuth EKU, browser-importable. '
                   'code-sign: codeSigning EKU.')
@click.option('--cn', required=True, help='Common Name on the leaf cert.')
@click.option('--san', 'sans', multiple=True,
              help='SubjectAltName (tls-server only). '
                   'Forms: DNS:foo.example.com, IP:10.0.0.1, or bare host. '
                   'Repeat for multiple. Merged with any SANs from --csr.')
@click.option('--validity-days', type=int, default=None,
              help='Cert validity in days (default per type; capped at 825).')
@click.option('--csr', 'csr_path', default=None,
              type=click.Path(exists=True, dir_okay=False),
              help='Path to a PKCS#10 CSR file. When set, the CA uses '
                   'the CSR\'s public key + merges its SANs (if any) '
                   'with --san. The private key stays on the target '
                   'host — no OUT-key.pem is written. Recommended for '
                   'TLS server certs where the key must not traverse '
                   'the network to reach the target.')
@click.option('--fullchain', is_flag=True, default=False,
              help='Write OUT-cert.pem as leaf + issuing intermediate '
                   '(the "fullchain" that TLS servers must present in '
                   'the handshake) instead of leaf-only. Without this '
                   'flag the v0.5.3 layout is preserved byte-identical: '
                   'OUT-cert.pem is leaf-only, OUT-ca.pem is the '
                   'intermediate, and an operator wanting a fullchain '
                   'concats them (`cat OUT-cert.pem OUT-ca.pem > '
                   'fullchain.pem`). Use --fullchain to skip the '
                   'concat step and get the ready-to-serve file '
                   'directly.')
@click.option('--out', 'out_prefix', default=None, type=click.Path(),
              help='Write outputs to OUT-cert.pem, OUT-key.pem, OUT-ca.pem. '
                   'For --type https-user also writes OUT.p12 if --p12-password '
                   'is set. Without --out, the cert + key are printed to stdout. '
                   'With --csr, no OUT-key.pem is written. See --fullchain '
                   'for the OUT-cert.pem content.')
@click.option('--p12-password', default=None,
              help='Password for PKCS#12 export (https-user only). '
                   'If unset, no .p12 is generated.')
@click.pass_context
def cert_mint_cmd(ctx, cert_type, cn, sans, validity_days, csr_path,
                  fullchain, out_prefix, p12_password):
    """Mint a §5 cert via the CA.

    Examples:

      \b
      # TLS server cert for an internal HTTPS endpoint:
      mssh-admin cert mint --type tls-server \\
                           --cn grafana.internal.example.com \\
                           --san DNS:grafana.internal.example.com \\
                           --san IP:10.10.0.42 \\
                           --validity-days 30 \\
                           --out grafana

      \b
      # Browser-importable HTTPS client cert:
      mssh-admin cert mint --type https-user --cn alice \\
                           --p12-password CHANGEME --out alice

      \b
      # Code-signing cert:
      mssh-admin cert mint --type code-sign --cn 'Build agent 03' \\
                           --validity-days 180 --out build03
    """
    if sans and cert_type != 'tls-server':
        click.echo(f'error: --san is only valid for --type tls-server '
                   f'(got --type {cert_type})', err=True)
        ctx.exit(2)
    if p12_password and cert_type != 'https-user':
        click.echo('error: --p12-password is only valid for '
                   '--type https-user', err=True)
        ctx.exit(2)
    if csr_path and p12_password:
        click.echo('error: --p12-password bundles the CA-generated '
                   'key into PKCS#12, which cannot happen when --csr '
                   'is set (no key was generated CA-side)', err=True)
        ctx.exit(2)

    csr_pem: str | None = None
    if csr_path:
        csr_pem = Path(csr_path).read_text()

    c = _make_client(ctx)
    resp = _handle_call(c.cert_mint, cert_type, cn,
                        sans=list(sans) if sans else None,
                        validity_days=validity_days,
                        csr_pem=csr_pem)
    creds = resp['credentials']
    csr_based = resp.get('cert', {}).get('csr_based', False)
    # v0.5.6 — surface CN/SAN validation warnings from the CA. The
    # mint SUCCEEDED (else we'd have returned earlier via _handle_call);
    # warnings just flag operator-facing issues the browser or a
    # downstream verifier will run into.
    for w in resp.get('warnings') or []:
        click.echo(f'WARNING: {w}', err=True)
    # File layout matches v0.5.3 (backward compat). --fullchain opts
    # into leaf+intermediate in OUT-cert.pem (skips the operator's
    # `cat OUT-cert.pem OUT-ca.pem > fullchain.pem` step).
    # `full_chain_pem` is always present in the response since v0.5.5;
    # fall back to concat of cert_pem + ca_cert_pem for very old
    # server versions that don't include the field.
    if fullchain:
        out_cert_body = creds.get('full_chain_pem') \
                        or (creds['cert_pem'] + creds['ca_cert_pem'])
    else:
        out_cert_body = creds['cert_pem']
    if out_prefix:
        od = Path(out_prefix)
        if od.suffix:                       # e.g. --out alice.pem.bad
            od = od.with_suffix('')
        od.parent.mkdir(parents=True, exist_ok=True)
        cert_path = od.with_name(f'{od.name}-cert.pem')
        ca_path   = od.with_name(f'{od.name}-ca.pem')
        cert_path.write_text(out_cert_body)
        ca_path.write_text(creds['ca_cert_pem'])
        cert_label = 'fullchain' if fullchain else 'leaf'
        # CSR path — CA didn't generate a key. Skip -key.pem file.
        if csr_based:
            click.echo(
                f'wrote {cert_path} ({cert_label}), {ca_path} — no key '
                f'file (private key stays on target host)', err=True)
        else:
            key_path = od.with_name(f'{od.name}-key.pem')
            key_path.write_text(creds['key_pem'])
            os.chmod(key_path, 0o600)
            click.echo(
                f'wrote {cert_path} ({cert_label}), {key_path}, {ca_path}',
                err=True)
            if cert_type == 'https-user' and p12_password:
                p12_path = od.with_name(f'{od.name}.p12')
                # PKCS#12 needs the leaf, not the fullchain. When
                # --fullchain is set out_cert_body is chain; use the
                # response's leaf-only cert_pem here regardless.
                _write_pkcs12(creds['cert_pem'], creds['key_pem'],
                              friendly_name=cn,
                              password=p12_password.encode('utf-8'),
                              out_path=p12_path)
                click.echo(f'wrote {p12_path} (PKCS#12, encrypted)',
                           err=True)
    else:
        label = 'fullchain' if fullchain else 'leaf'
        click.echo(f'--- cert ({label}) ---', err=True)
        click.echo(out_cert_body)
        if not csr_based:
            click.echo('--- key ---', err=True)
            click.echo(creds['key_pem'])
    _output(ctx, resp['cert'])


def _write_pkcs12(cert_pem: str, key_pem: str, *,
                  friendly_name: str, password: bytes,
                  out_path: Path) -> None:
    """Convert PEM cert + key to a password-encrypted PKCS#12 blob.

    Browsers (Chrome, Firefox, Safari) accept .p12 imports natively;
    this saves the operator from running ``openssl pkcs12 -export``
    by hand after every mint.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
    key  = serialization.load_pem_private_key(key_pem.encode('ascii'),
                                              password=None)
    p12 = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode('utf-8'),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    out_path.write_bytes(p12)
    os.chmod(out_path, 0o600)


@cert_group.command('external-use')
@click.option('--cn', required=True,
              help='Common Name on the leaf cert.')
@click.option('--csr', 'csr_path', required=True,
              type=click.Path(exists=True, dir_okay=False),
              help='Path to a PKCS#10 CSR file (PEM). The CA verifies '
                   'the CSR self-signature and extracts the public key. '
                   'The operator\'s private key never touches the CA.')
@click.option('--issuer-intermediate', required=True,
              help='Name of the external intermediate that will sign '
                   'this leaf. Must have been minted via '
                   '`mssh-admin intermediate mint-external --profile <name>` '
                   '(non-generic profile stamps the §15.20 purpose marker).')
@click.option('--validity-days', type=int, default=None,
              help='Cert validity in days (overrides ca-config '
                   'cert_kinds.external-use.default_validity_days; '
                   'default 7305 = 20yr; cap 9125 = 25yr). Mutually '
                   'exclusive with --never-expires.')
@click.option('--never-expires', is_flag=True, default=False,
              help='§15.19 — set notAfter to the RFC 5280 §4.1.2.5 '
                   'sentinel (99991231235959Z) for ROM-burned device '
                   'identity certs. Mutually exclusive with --validity-days.')
@click.option('--custom-oid', 'custom_oids', multiple=True,
              help='Operator-defined custom OIDs to attach, from the '
                   '§15.21 ca-config allowlist. Form: `NAME=VALUE` or '
                   '`OID=VALUE`. Repeat for multiple.')
@click.option('--out', 'out_prefix', required=True, type=click.Path(),
              help='Write outputs to OUT-cert.pem (leaf+chain) + '
                   'OUT-leaf.pem (leaf only) + OUT-ca.pem (issuer '
                   'intermediate). No key is written — operator\'s CSR '
                   'private key stays on-device.')
@click.pass_context
def cert_external_use_cmd(ctx, cn, csr_path, issuer_intermediate,
                          validity_days, never_expires,
                          custom_oids, out_prefix):
    """§15.19 — mint a CSR-based external-use leaf.

    The CA never sees the private key. Prereqs:

    \b
      1. An external intermediate must exist with a non-generic profile:
             mssh-admin intermediate mint-external \\
                 --name device-mfg --profile device-identity \\
                 --out-cert device-mfg.crt --out-key device-mfg.key
         And the intermediate's key.pem must be placed at
         <ca_dir>/external/device-mfg/key.pem (mode 0600) for the CA
         to sign external-use leaves under it.
      2. Any --custom-oid names/OIDs referenced must be declared in
         the CA's ca-config.yaml `custom_oids:` allowlist.

    Example — device-identity CSR:

    \b
      openssl ecparam -name prime256v1 -genkey -noout -out dev.key
      openssl req -new -key dev.key -subj "/CN=device-0001" -out dev.csr
      mssh-admin cert external-use \\
          --cn device-0001 --csr dev.csr \\
          --issuer-intermediate device-mfg \\
          --validity-days 7305 \\
          --custom-oid device_oem=acme \\
          --out device-0001
    """
    # §7.3.1 CLI tree; §15.19 external-use kind
    if validity_days is not None and never_expires:
        click.echo('error: --validity-days and --never-expires are '
                   'mutually exclusive', err=True)
        ctx.exit(2)

    # Parse `--custom-oid NAME=VALUE` args into the request-body shape.
    coids: list[dict] = []
    for spec in custom_oids:
        if '=' not in spec:
            click.echo(f'error: --custom-oid must be NAME=VALUE '
                       f'(got: {spec!r})', err=True)
            ctx.exit(2)
        key, _, value = spec.partition('=')
        entry: dict = {'value': value}
        # Ambiguity: could be an OID (dotted digits) or a name (alpha).
        if all(part.isdigit() for part in key.split('.')):
            entry['oid'] = key
        else:
            entry['name'] = key
        coids.append(entry)

    csr_pem = Path(csr_path).read_text()

    c = _make_client(ctx)
    resp = _handle_call(c.cert_external_use_mint,
                        cn=cn, csr_pem=csr_pem,
                        issuer_intermediate=issuer_intermediate,
                        validity_days=validity_days,
                        never_expires=never_expires,
                        custom_oids=coids or None)
    creds = resp['credentials']
    od = Path(out_prefix)
    if od.suffix:
        od = od.with_suffix('')
    od.parent.mkdir(parents=True, exist_ok=True)
    (od.with_name(f'{od.name}-cert.pem')).write_text(creds['cert_pem'])
    (od.with_name(f'{od.name}-leaf.pem')).write_text(creds['leaf_only_pem'])
    (od.with_name(f'{od.name}-ca.pem')).write_text(creds['ca_cert_pem'])
    click.echo(f'wrote {od.name}-cert.pem (leaf+chain), '
               f'{od.name}-leaf.pem (leaf only), '
               f'{od.name}-ca.pem (issuer intermediate)', err=True)
    _output(ctx, {
        'type': resp['cert']['type'],
        'subject_cn': resp['cert']['subject_cn'],
        'issuer_intermediate': resp['cert']['issuer_intermediate'],
        'never_expires': resp['cert']['never_expires'],
        'validity_days': resp['cert']['validity_days'],
        'not_valid_after': resp['cert']['not_valid_after'],
    })


@cert_group.command('renew')
@click.option('--cert', 'cert_path', required=True, type=click.Path(),
              help='Path to the cert being renewed. Used as the mTLS '
                   'client cert when calling the CA.')
@click.option('--key', 'key_path', required=True, type=click.Path(),
              help='Path to the cert\'s private key.')
@click.option('--ca-cert', 'ca_cert_path', default=None, type=click.Path(),
              help='CA trust root for verifying mssh-ca\'s TLS server '
                   'cert. Defaults to the value in ~/.mssh-admin/config.')
@click.option('--ca-url', 'ca_url', default=None,
              help='mssh-ca URL. Defaults to the value in '
                   '~/.mssh-admin/config.')
@click.option('--out-cert', 'out_cert_path', required=True, type=click.Path(),
              help='Write the renewed cert here (atomic rename).')
@click.option('--out-key', 'out_key_path', required=True, type=click.Path(),
              help='Write the renewed key here (mode 0600).')
@click.option('--threshold-days', type=int, default=14, show_default=True,
              help='Renew only if the cert expires within this many '
                   'days. Otherwise exit 0 silently (cron-friendly).')
@click.option('--revoke-old', is_flag=True, default=False,
              help='Also revoke the old cert (CRL append). Default: '
                   'old cert remains valid until its not_after.')
@click.option('--on-renew', 'on_renew_cmd', default=None,
              help='Shell command to run after a successful renewal. '
                   'E.g. "systemctl reload nginx".')
@click.pass_context
def cert_renew_cmd(ctx, cert_path, key_path, ca_cert_path, ca_url,
                   out_cert_path, out_key_path, threshold_days,
                   revoke_old, on_renew_cmd):
    """Renew a cert that mssh-ca has previously issued.

    The endpoint is auth-by-cert — the cert at ``--cert`` IS the
    credential. mssh-ca validates the chain at the TLS layer, checks
    the CRL, and re-mints with the same CN/SAN/EKU/validity_days
    when within the renewable window (default 30 days from expiry,
    7-day grace past expiry).

    Designed for daily systemd-timer execution per service. Exits 0
    silently when the cert is more than ``--threshold-days`` from
    expiry, so cron entries can fire daily without churning.

    Example (systemd unit):

      \b
      ExecStart=mssh-admin cert renew \\
          --cert /etc/grafana/tls.crt --key /etc/grafana/tls.key \\
          --out-cert /etc/grafana/tls.crt --out-key /etc/grafana/tls.key \\
          --threshold-days 14 --on-renew "systemctl reload grafana"
    """
    # §7.3.3 cert auto-renewal helper
    from datetime import datetime, timezone
    from cryptography import x509

    cp = Path(cert_path)
    if not cp.exists():
        click.echo(f'error: --cert not found: {cp}', err=True)
        ctx.exit(2)
    try:
        cert = x509.load_pem_x509_certificate(cp.read_bytes())
    except Exception as e:
        click.echo(f'error: --cert at {cp} not parseable: {e}', err=True)
        ctx.exit(2)

    not_after = cert.not_valid_after_utc
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days_to_expiry = (not_after
                      - datetime.now(timezone.utc)).total_seconds() / 86400

    if days_to_expiry > threshold_days:
        click.echo(
            f'cert valid until {not_after.isoformat()} '
            f'({int(days_to_expiry)} days); nothing to do '
            f'(threshold {threshold_days})',
            err=True)
        ctx.exit(0)

    # Build a CAClient using the cert/key being renewed as the mTLS
    # client identity, NOT the admin creds.
    conf = ctx.obj.get('_config', {})
    base_url = ca_url or conf.get('ca_url')
    ca_root = ca_cert_path or conf.get('ca_cert')
    if not base_url or not ca_root:
        click.echo('error: --ca-url and --ca-cert required (or set in '
                   '~/.mssh-admin/config)', err=True)
        ctx.exit(2)

    renew_client = CAClient(
        base_url=base_url,
        admin_cert=str(cp),
        admin_key=str(key_path),
        ca_cert=str(ca_root),
    )

    try:
        resp = renew_client.cert_renew(revoke_predecessor=revoke_old)
    except CAClientError as e:
        click.echo(f'renewal failed: HTTP {e.status} — {e.body}', err=True)
        ctx.exit(3)

    if resp.get('status') == 'too_early':
        click.echo(f'cert not yet renewable: {resp.get("detail")}',
                   err=True)
        ctx.exit(0)
    if resp.get('status') != 'ok':
        click.echo(f'unexpected response: {resp}', err=True)
        ctx.exit(4)

    # Atomic write: write to a tmp file, fsync, rename. Same pattern
    # the broker uses for hosts_live.py.
    creds = resp['credentials']
    _atomic_write(out_cert_path, creds['cert_pem'].encode('ascii'),
                   mode=0o644)
    _atomic_write(out_key_path, creds['key_pem'].encode('ascii'),
                   mode=0o600)

    cert_info = resp['cert']
    click.echo(
        f'renewed {cert_info["subject_cn"]} '
        f'(old serial {cert_info["old_serial"]}); '
        f'validity {cert_info["validity_days"]} days',
        err=True)

    if on_renew_cmd:
        click.echo(f'running --on-renew: {on_renew_cmd}', err=True)
        import subprocess
        rc = subprocess.run(on_renew_cmd, shell=True).returncode
        if rc != 0:
            click.echo(f'warning: --on-renew exited {rc}', err=True)
            ctx.exit(5)


def _atomic_write(path, data, *, mode=0o644):
    """Write bytes to ``path`` atomically via rename. Inherits the
    target's directory."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + '.tmp')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    os.chmod(str(p), mode)


@cert_group.command('revoke')
@click.argument('serials', nargs=-1, required=True)
@click.option('--reason', default='',
              help='Free-text reason recorded in the CRL entry + audit.')
@click.option('--issuer', default='user-mint',
              type=click.Choice(['user-mint', 'bypass-mint',
                                  'host-mint', 'auth']),
              help='Which intermediate signed the cert(s) being revoked. '
                   'Default user-mint (matches v0.2.0 single-signer behavior).')
@click.pass_context
def cert_revoke_cmd(ctx, serials, reason, issuer):
    """Revoke one or more cert SERIALS (lowercase hex) under --issuer.

    Appends a CRL entry to that intermediate's log; the fleet picks it
    up on next authorize call. Affects both normal CA-grant entries
    AND bypass-injected entries in each msshd's authz cache. See
    archive/design/notes-bypass-cache.md "CRL Amendment".

    Example:
        mssh-admin cert revoke deadbeef abcd1234 --reason 'key rotation'
        mssh-admin cert revoke abc --issuer bypass-mint --reason 'lost'
    """
    c = _make_client(ctx)
    out = _handle_2fa_call(c, c.cert_revoke, list(serials),
                            reason=reason, issuer=issuer)
    click.echo(f'revoked seq={out["seq"]} serials={out["serials"]}',
               err=True)
    _output(ctx, out)


@cli.group('intermediate')
def intermediate_group():
    """Inspect / rotate the named intermediates (user-mint, bypass-mint,
    host-mint, auth). See design/notes-pki-hierarchy.md."""
    # §7.3.1 CLI command tree (full enum in §14.2.2); §7.3.4 PKI ceremony helpers


@intermediate_group.command('list')
@click.pass_context
def intermediate_list_cmd(ctx):
    """Show issuer_id + validity for each intermediate.

    Example:
        mssh-admin intermediate list
        # role         issuer_id                                 not_after
        # user-mint    user-mint:7f3c4b2a8d1e5f60               2036-05-22T...
        # bypass-mint  bypass-mint:a1b2c3d4e5f60718              2036-05-22T...
    """
    c = _make_client(ctx)
    out = _handle_call(c.intermediate_list)
    _output(ctx, out['intermediates'])


@intermediate_group.command('rotate')
@click.argument('role',
                type=click.Choice(['user-mint', 'bypass-mint',
                                    'host-mint', 'auth']))
@click.option('--force', is_flag=True,
              help='Required: confirms operator understands that '
                   'validators pinning to this intermediate must '
                   'have the NEW cert distributed before existing '
                   'leaves expire.')
@click.pass_context
def intermediate_rotate_cmd(ctx, role, force):
    """Generate a fresh keypair for one intermediate; sign with root;
    archive the old key+cert. DESTRUCTIVE: requires --force.

    After rotation, distribute the new intermediate cert to validators
    that pin it (msshd's bypass_trust_root, auth_trust_root,
    user_ca_pubkey, or ca.ca_pubkey depending on role) before existing
    leaves expire. Until distributed, leaves freshly minted by the
    new key will fail to validate against the old trust store.
    """
    # §7.3.4 PKI ceremony helpers; per §2.5
    if not force:
        raise click.UsageError(
            'intermediate rotate is destructive — pass --force to confirm. '
            'See `mssh-admin intermediate rotate --help` for the '
            'redistribution requirement.')
    c = _make_client(ctx)
    out = _handle_2fa_call(c, c.intermediate_rotate, role)
    click.echo(f'rotated {role} → new issuer_id {out["new_issuer_id"]}',
                err=True)
    click.echo(f'archive suffix: {out["archive_suffix"]}', err=True)
    click.echo(f'WARNING: {out["warning"]}', err=True)
    _output(ctx, {
        'role': out['role'],
        'new_issuer_id': out['new_issuer_id'],
        'archive_suffix': out['archive_suffix'],
    })


@intermediate_group.command('mint-external')
@click.option('--name', required=True,
              help='Short identifier for the external entity (no /, '
                   'no leading dot). Becomes Organization= in the cert.')
@click.option('--path-length', type=int, default=0,
              help='Sub-CA path length (default 0 = the external entity '
                   'can mint only leaves, no further sub-CAs).')
@click.option('--validity-days', type=int, default=None,
              help='Cert validity. Defaults per profile: 3650 for generic, '
                   '10950 (30yr) for device-identity.')
@click.option('--profile',
              type=click.Choice(['generic', 'device-identity']),
              default='generic',
              help='§15.20 profile. `generic` = v0.4.x behavior. '
                   '`device-identity` stamps the §15.23 intermediate-'
                   'purpose marker so external-use leaves (§15.19) can '
                   'pin to it as their issuer, and bumps the default '
                   'validity to 30 years.')
@click.option('--new-root', is_flag=True, default=False,
              help='§15.22 opt-in — create a fresh Root and sign this '
                   'intermediate under it (default: sign under the '
                   "primary Root). The new Root is persisted under "
                   "<ca_dir>/roots/<root-name>/{cert,key}.pem.")
@click.option('--root', 'root_name', default=None,
              help='Name for the new Root created with --new-root. '
                   'Defaults to the intermediate name. Reusing an '
                   'existing non-primary Root name signs under that '
                   'existing Root instead of creating a new one.')
@click.option('--out-cert', required=True, type=click.Path(),
              help='Where to write the external intermediate cert PEM.')
@click.option('--out-key', required=True, type=click.Path(),
              help='Where to write the external intermediate private key. '
                   'Mode 0600. See --retain-key / --no-retain-key for '
                   'whether the CA also keeps a copy.')
@click.option('--retain-key/--no-retain-key', default=None,
              help='Whether the CA retains a copy of the intermediate '
                   "key on disk. Default depends on --profile: `generic` "
                   "→ no retain (v0.4.x §2.6 delegation semantics); "
                   "any other profile → retain (the CA needs the key "
                   "to sign external-use leaves under this intermediate). "
                   "Pass explicitly to override the default either way.")
@click.pass_context
def intermediate_mint_external_cmd(ctx, name, path_length, validity_days,
                                     profile, new_root, root_name,
                                     out_cert, out_key, retain_key):
    """Mint an external Intermediate CA per the trust-model amendment.

    The external entity then runs their own signing infrastructure;
    leaves they sign chain back to mssh-root (or a --new-root),
    but mssh validators do NOT trust external CAs for any auth
    decision — the chain terminates without a trust anchor.

    Examples:

      \b
      # v0.4.x default — sign under primary Root, generic intermediate:
      mssh-admin intermediate mint-external \\
          --name partner-corp --path-length 1 \\
          --out-cert partner-corp.crt --out-key partner-corp.key

      \b
      # v0.5.0 device-identity — for external-use (§15.19) leaves:
      mssh-admin intermediate mint-external \\
          --name device-mfg --profile device-identity \\
          --out-cert device-mfg.crt --out-key device-mfg.key

      \b
      # v0.5.0 separate-Root manufacturing PKI:
      mssh-admin intermediate mint-external \\
          --name device-mfg --profile device-identity \\
          --new-root --root mfg-pki \\
          --out-cert device-mfg.crt --out-key device-mfg.key
    """
    # §7.3.4 PKI ceremony helpers; §2.5 rotation semantics; §15.20/§15.22
    c = _make_client(ctx)
    out = _handle_2fa_call(c, c.intermediate_mint_external, name,
                            path_length=path_length,
                            validity_days=validity_days,
                            profile=profile,
                            new_root=new_root,
                            root_name=root_name,
                            retain_key=retain_key)
    Path(out_cert).write_text(out['cert_pem'])
    _atomic_write(Path(out_key), out['key_pem'].encode('ascii'), mode=0o600)
    click.echo(f'wrote {out_cert} (cert) and {out_key} (key, mode 0600)',
                err=True)
    if out.get('key_retained_by_ca'):
        click.echo(
            f'NOTE: CA has retained a copy of the key. `mssh-admin cert '
            f'external-use --issuer-intermediate {out["name"]}` can now '
            f'sign leaves under this intermediate directly — no '
            f'operator key-placement step needed.', err=True)
    click.echo(f'WARNING: {out["warning"]}', err=True)
    _output(ctx, {
        'name': out['name'],
        'issuer_id': out['issuer_id'],
        'path_length': out['path_length'],
        'profile': out.get('profile', 'generic'),
        'root_name': out.get('root_name', 'primary'),
        'key_retained_by_ca': out.get('key_retained_by_ca', False),
        'serial': out['serial'],
    })


@intermediate_group.command('list-external')
@click.pass_context
def intermediate_list_external_cmd(ctx):
    """List external Intermediate CAs previously minted by this CA."""
    c = _make_client(ctx)
    out = _handle_call(c.intermediate_list_external)
    _output(ctx, out['external_intermediates'])


@cli.group('crl')
def crl_group():
    """View the CA's CRL (revocation log)."""
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@crl_group.command('list')
@click.option('--after', type=int, default=0,
              help='Return entries with seq > AFTER.')
@click.option('--limit', type=int, default=None,
              help='Cap the number of entries returned.')
@click.option('--issuer', default='user-mint',
              type=click.Choice(['user-mint', 'bypass-mint',
                                  'host-mint', 'auth']),
              help='Which intermediate\'s CRL to list (default user-mint).')
@click.pass_context
def crl_list_cmd(ctx, after, limit, issuer):
    """List CRL entries for one issuer, optionally filtered by seq."""
    c = _make_client(ctx)
    out = _handle_call(c.crl_list, after, limit, issuer)
    _output(ctx, out)


@cli.group('openvpn')
def openvpn_group():
    """Issue OpenVPN client bundles signed by this CA's TLS hierarchy.

    Output is a single ``.ovpn`` file with the client cert + key + CA
    inlined plus the connection metadata. Drop into the user's OpenVPN
    client; revocation goes through ``mssh-admin cert revoke <serial>``
    (OpenVPN server polls the CA's CRL).
    """
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@openvpn_group.command('issue')
@click.option('--cn', required=True,
              help='Common Name on the client cert (typically the username).')
@click.option('--server-endpoint', required=True,
              help='"host port" form for the .ovpn remote directive, '
                   'e.g. "vpn.example.com 1194".')
@click.option('--proto', type=click.Choice(['udp', 'tcp']), default='udp',
              show_default=True)
@click.option('--dev', type=click.Choice(['tun', 'tap']), default='tun',
              show_default=True)
@click.option('--validity-days', type=int, default=None,
              help='Cert validity in days (default 90; capped at 825).')
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the .ovpn bundle to this path. '
                   'Without --out, the .ovpn is printed to stdout.')
@click.pass_context
def openvpn_issue_cmd(ctx, cn, server_endpoint, proto, dev,
                      validity_days, out_path):
    """Issue an OpenVPN client bundle.

    Example:

      \b
      mssh-admin openvpn issue --cn alice \\
                                --server-endpoint "vpn.example.com 1194" \\
                                --validity-days 30 \\
                                --out alice-vpn.ovpn
    """
    c = _make_client(ctx)
    resp = _handle_call(c.openvpn_issue, cn, server_endpoint,
                        proto=proto, dev=dev,
                        validity_days=validity_days)
    creds = resp['credentials']
    meta  = resp['openvpn']
    ovpn  = _format_ovpn_bundle(
        ca_pem=creds['ca_cert_pem'],
        cert_pem=creds['cert_pem'],
        key_pem=creds['key_pem'],
        server_endpoint=meta['server_endpoint'],
        proto=meta['proto'],
        dev=meta['dev'],
    )
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(ovpn)
        os.chmod(op, 0o600)
        click.echo(f'wrote {op}', err=True)
    else:
        click.echo(ovpn)
    _output(ctx, meta)


def _format_ovpn_bundle(*, ca_pem: str, cert_pem: str, key_pem: str,
                        server_endpoint: str, proto: str, dev: str) -> str:
    """Assemble a single-file .ovpn config with inline cert/key/ca."""
    return (
        f'# mssh-admin openvpn issue — single-file client config\n'
        f'client\n'
        f'dev {dev}\n'
        f'proto {proto}\n'
        f'remote {server_endpoint}\n'
        f'resolv-retry infinite\n'
        f'nobind\n'
        f'persist-key\n'
        f'persist-tun\n'
        f'remote-cert-tls server\n'
        f'cipher AES-256-GCM\n'
        f'auth SHA256\n'
        f'verb 3\n'
        f'\n'
        f'<ca>\n{ca_pem.strip()}\n</ca>\n'
        f'<cert>\n{cert_pem.strip()}\n</cert>\n'
        f'<key>\n{key_pem.strip()}\n</key>\n'
    )


@cli.group('wireguard')
def wireguard_group():
    """Manage WireGuard servers + peers signed by this CA's catalog.

    The CA owns the server's keypair and tracks IP allocation; peer
    issuance returns a wg-quick config the recipient drops into their
    laptop. Server-side, the operator runs ``wireguard server show``
    periodically to refresh ``/etc/wireguard/<server>.conf`` and
    reload the WireGuard daemon — revocation propagates that way.
    """
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@wireguard_group.command('server-init')
@click.option('--name', required=True,
              help='Server (interface) name, e.g. wg0.')
@click.option('--network', default='',
              help='IPv4 address pool in CIDR form, e.g. 10.20.0.0/24. '
                   'First usable IP becomes the server\'s address; '
                   'subsequent peers take the next free addresses. '
                   'Independently optional (v0.4.0+) — pass --network, '
                   '--network-v6, or both; at least one required.')
@click.option('--network-v6', default='',
              help='IPv6 address pool, e.g. fd00:98:123::/64 (ULA). '
                   'Server takes ::1; peers share host numbers with v4 '
                   'when dual-stack. Independently optional.')
@click.option('--endpoint', required=True,
              help='Public endpoint peers connect to, '
                   'e.g. vpn.example.com:51820.')
@click.option('--listen-port', type=int, default=51820, show_default=True)
@click.pass_context
def wireguard_server_init_cmd(ctx, name, network, network_v6,
                               endpoint, listen_port):
    """Create a new WireGuard server (interface).

    v0.4.0+ supports dual-stack: pass --network for v4-only, --network-v6
    for v6-only, or both for dual-stack. The server takes host number 1
    in each family; peers take the next free number.
    """
    if not network and not network_v6:
        raise click.UsageError(
            'at least one of --network or --network-v6 is required')
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_init,
                       name, endpoint,
                       network=network,
                       network_v6=network_v6,
                       listen_port=listen_port)
    click.echo(f'created WireGuard server {name!r} '
               f'(pubkey {out["server"]["public_key_b64"][:12]}...)',
               err=True)
    _output(ctx, out['server'])


@wireguard_group.command('server-show')
@click.option('--name', required=True)
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the wg0.conf-style server config to this path.')
@click.pass_context
def wireguard_server_show_cmd(ctx, name, out_path):
    """Emit the server-side ``/etc/wireguard/<name>.conf``.

    Contains the server's private key + every active peer's PublicKey
    + AllowedIPs. Re-run this after every issue/revoke and reload
    WireGuard on the server (``wg syncconf <name> <(wg-quick strip <name>)``).
    """
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_show, name)
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(out['server_config'])
        os.chmod(op, 0o600)
        click.echo(f'wrote {op}', err=True)
    else:
        click.echo(out['server_config'])
    _output(ctx, out['server'])


@wireguard_group.command('server-list')
@click.pass_context
def wireguard_server_list_cmd(ctx):
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_list)
    _output(ctx, out['servers'])


@wireguard_group.command('server-remove')
@click.option('--name', required=True)
@click.pass_context
def wireguard_server_remove_cmd(ctx, name):
    """Delete the server and ALL its peers. Irreversible."""
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_remove, name)
    _output(ctx, out)


@wireguard_group.command('issue')
@click.option('--name', required=True,
              help='Peer name (typically the username).')
@click.option('--server', required=True,
              help='Server (interface) name the peer joins.')
@click.option('--persistent-keepalive', type=int, default=0,
              help='Seconds between WireGuard keepalive packets. '
                   '0 disables. Use 25 for peers behind NAT.')
@click.option('--dns', default=None,
              help='DNS to push into the peer config '
                   '(written as the [Interface] DNS = ... line).')
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the wg-quick client config to this path.')
@click.pass_context
def wireguard_peer_issue_cmd(ctx, name, server, persistent_keepalive,
                             dns, out_path):
    """Mint a peer keypair, allocate the next free IP, return the
    client wg-quick config.

    The private key in the returned config is generated on the CA
    and returned exactly once — write it somewhere safe before
    delivering to the user.
    """
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_issue,
                       name, server,
                       persistent_keepalive=persistent_keepalive,
                       dns=dns)
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(out['client_config'])
        os.chmod(op, 0o600)
        click.echo(f'wrote {op} (mode 0600 — contains private key)', err=True)
    else:
        click.echo(out['client_config'])
    _output(ctx, out['peer'])


@wireguard_group.command('revoke')
@click.option('--name', required=True)
@click.option('--server', required=True)
@click.pass_context
def wireguard_peer_revoke_cmd(ctx, name, server):
    """Revoke a peer. The peer is removed from the catalog
    immediately; for the change to take effect on a running
    WireGuard server, re-run ``wireguard server-show`` and reload."""
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_revoke, name, server)
    _output(ctx, out['revoked'])


@wireguard_group.command('peer-list')
@click.option('--server', default=None,
              help='Filter to peers on this server only.')
@click.pass_context
def wireguard_peer_list_cmd(ctx, server):
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_list, server)
    _output(ctx, out['peers'])


@cli.group('external-tool')
def external_tool_group():
    """Manage external tools that use mssh-ca as their WebAuthn RP.

    See [design/ca-integration.md § Passkey RP service for external
    tools].
    """
    # §7.3.1 CLI command tree (full enum in §14.2.2)


@external_tool_group.command('add')
@click.option('--name', required=True,
              help='Operator-visible tool name (also used as the mTLS CN '
                   'prefix for the tool\'s client cert).')
@click.option('--rp-id', required=True,
              help='WebAuthn RP ID. Usually the broker\'s public '
                   'hostname.')
@click.option('--outcome-url-prefix', required=True,
              help='Allowed prefix for the tool\'s outcome callback URLs. '
                   'A compromised tool cert can only deliver outcomes to '
                   'URLs under this prefix.')
@click.option('--out-dir', default=None, type=click.Path(),
              help='Write the tool\'s mTLS cert + key here (mode 600 on '
                   'the key file).')
@click.pass_context
def external_tool_add_cmd(ctx, name, rp_id, outcome_url_prefix, out_dir):
    """Enroll an external tool. Mints an mTLS client cert the tool
    presents when calling /v1/external/passkey/*."""
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_add, name, rp_id, outcome_url_prefix)
    creds = out['credentials']
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(creds['cert_pem'])
        kp = od / f'{name}-key.pem'
        kp.write_text(creds['key_pem'])
        os.chmod(kp, 0o600)
        (od / f'{name}-ca.pem').write_text(creds['ca_cert_pem'])
        click.echo(f'wrote {od}/{name}-cert.pem, {name}-key.pem, '
                   f'{name}-ca.pem', err=True)
    _output(ctx, out['tool'])


@external_tool_group.command('list')
@click.pass_context
def external_tool_list_cmd(ctx):
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_list)
    _output(ctx, out['tools'])


@external_tool_group.command('remove')
@click.option('--name', required=True)
@click.pass_context
def external_tool_remove_cmd(ctx, name):
    """Delete an external tool. The tool's stored user-passkey
    credentials are removed too."""
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_remove, name)
    _output(ctx, out)


if __name__ == '__main__':
    sys.exit(cli())  # pragma: no cover
