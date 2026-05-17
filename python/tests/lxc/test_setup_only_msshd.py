"""Set-up-only test for the Tier-1 (msshd) adoption journey.

Walks the same containers through three states and leaves them at the
final state with helper scripts to flip between modes:

    Phase 0 — vanilla sshd on every server; users `ssh user@host` works.
    Phase 1 — drop msshd in fallback in front (port 2200); users now
              `ssh -p 2200 user@host`, still using their SSH keypair.
              No CA involvement; msshd is a transparent TCP proxy.
    Phase 2 — generate user-CA + per-user X.509 mTLS material, enroll
              users at the CA, flip msshd to enforce mode; users now
              `mssh user@host:2200` with cert-bound, CA-mediated auth.

End state is Phase 2. Helper scripts (flip-to-fallback.sh /
flip-to-enforce.sh) let the operator bounce between modes after
provisioning.

Containers (FIXED names, stomped on each run):

    mssh-adhoc-ca       CA + mssh-admin
    mssh-adhoc-acct     Accounting SSH server
    mssh-adhoc-sales    Sales SSH server
    mssh-adhoc-hr       HR SSH server
    mssh-adhoc-eng      Engineering server (Alpine, cross-distro)

Vanilla sshd lives on port 22 in every server (always alive — your
backdoor if msshd is misbehaving). msshd lives on port 2200 in
whichever mode you last flipped it to.

Run with::

    pytest tests/lxc/test_setup_only_msshd.py -v -m setup_only_msshd
"""
from __future__ import annotations

import base64
import datetime as _dt
import importlib.util as _ilu
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest


_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    ALPINE_IMAGE, UBUNTU_IMAGE,
    ensure_fixed_images, get_ip, lxc, lxc_exec, pull_diagnostics,
    push_file, push_source, push_text,
    wait_for_apt_quiescent, wait_for_port,
)
from log_helpers import banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.setup_only_msshd]


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

CA_NAME    = 'mssh-adhoc-ca'
ACCT_NAME  = 'mssh-adhoc-acct'
SALES_NAME = 'mssh-adhoc-sales'
HR_NAME    = 'mssh-adhoc-hr'
ENG_NAME   = 'mssh-adhoc-eng'

SSH_CONTAINERS = [ACCT_NAME, SALES_NAME, HR_NAME, ENG_NAME]
ALL_CONTAINERS = [CA_NAME] + SSH_CONTAINERS

CA_PORT     = 8443
VANILLA_SSHD_PORT = 22      # in-container; reachable from host via lxc IP
MSSHD_PORT  = 2200


@dataclass
class _Server:
    container: str
    canonical: str
    image: str
    group: str


@dataclass
class _User:
    username: str
    department: str
    description: str
    allowed_groups: list[str]


SERVERS: list[_Server] = [
    _Server(ACCT_NAME,  'srv-acct',  UBUNTU_IMAGE, 'accounting'),
    _Server(SALES_NAME, 'srv-sales', UBUNTU_IMAGE, 'sales'),
    _Server(HR_NAME,    'srv-hr',    UBUNTU_IMAGE, 'hr'),
    _Server(ENG_NAME,   'srv-eng',   ALPINE_IMAGE, 'engineering'),
]

USERS: list[_User] = [
    _User('alice',      'accounting',  'Accounting analyst', ['accounting']),
    _User('amy',        'accounting',  'Accounting manager', ['accounting']),
    _User('bob',        'sales',       'Sales rep',          ['sales']),
    _User('bart',       'sales',       'Sales engineer',     ['sales']),
    _User('carol',      'hr',          'HR generalist',      ['hr']),
    _User('charlie',    'hr',          'HR director',        ['hr']),
    _User('dave',       'engineering', 'Backend engineer',   ['engineering']),
    _User('diana',      'engineering', 'SRE',                ['engineering']),
    _User('root-admin', 'superuser',   'Cross-dept break-glass',
          ['accounting', 'sales', 'hr', 'engineering']),
]
ALL_USERNAMES = [u.username for u in USERS]
SUPERUSER = next(u for u in USERS if u.department == 'superuser')


def _primary_container_for(user: _User) -> str:
    if user.department == 'superuser':
        return CA_NAME
    return {'accounting': ACCT_NAME, 'sales': SALES_NAME,
            'hr': HR_NAME, 'engineering': ENG_NAME}[user.department]


def _allowed_servers_for(user: _User) -> list[_Server]:
    return [s for s in SERVERS if s.group in user.allowed_groups]


def _is_alpine(container: str) -> bool:
    return container == ENG_NAME


# ---------------------------------------------------------------------------
# Phase 0 — vanilla sshd + SSH keypair per user
# ---------------------------------------------------------------------------

def _ensure_unix_account(container: str, username: str) -> None:
    if _is_alpine(container):
        lxc_exec(container, 'adduser', '-D', '-s', '/bin/sh', username,
                 check=False)
        # Alpine adduser -D leaves the account locked ("!" in /etc/shadow);
        # sshd refuses login for locked accounts even on pubkey auth
        # ("User X not allowed because account is locked"). Flip to "*"
        # (no password set, but not locked).
        lxc_exec(container, 'sh', '-c',
                 f"sed -i 's|^{username}:!:|{username}:*:|' /etc/shadow",
                 check=False)
    else:
        lxc_exec(container, 'useradd', '-m', '-s', '/bin/bash', username,
                 check=False)
        lxc_exec(container, 'usermod', '-p', '*', username, check=False)
    lxc_exec(container, 'sh', '-c',
             f'mkdir -p /home/{username}/.ssh && '
             f'chmod 700 /home/{username}/.ssh && '
             f'chown -R {username}:{username} /home/{username}/.ssh')


def _keygen_in_container(container: str, username: str,
                         artifacts_dir: Path) -> dict:
    """Generate the user's Ed25519 keypair INSIDE their primary container,
    then pull both halves to ``artifacts_dir``.
    """
    from mssh.ca.identity_parser import sha256_fingerprint

    _ensure_unix_account(container, username)
    priv = f'/home/{username}/.ssh/id_ed25519'
    pub  = f'{priv}.pub'
    comment = f'{username}@{container}'

    if _is_alpine(container):
        db_path = f'/home/{username}/.ssh/id_ed25519.dropbear'
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv} {pub} {db_path}; '
                 f'dropbearkey -t ed25519 -f {db_path} >/dev/null; '
                 f'dropbearconvert dropbear openssh {db_path} {priv} '
                 f'>/dev/null 2>&1; chmod 600 {priv}; '
                 f'dropbearkey -y -f {db_path} | grep "^ssh-" '
                 f'| sed "s| dropbear@.*$| {comment}|" > {pub}; '
                 f'chmod 644 {pub}',
                 timeout=30)
    else:
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv} {pub}; '
                 f'ssh-keygen -t ed25519 -f {priv} -N "" -C "{comment}"',
                 timeout=30)

    priv_host = artifacts_dir / username
    pub_host  = artifacts_dir / f'{username}.pub'
    for h, container_path in [(priv_host, priv), (pub_host, pub)]:
        if h.exists():
            h.unlink()
        subprocess.run(['lxc', 'file', 'pull',
                        f'{container}{container_path}', str(h)],
                       check=True, capture_output=True)
    os.chmod(priv_host, 0o600)

    pub_line = pub_host.read_text().strip()
    blob = base64.b64decode(pub_line.split()[1])
    return {
        'priv': str(priv_host),
        'pub_path': str(pub_host),
        'pub_line': pub_line,
        'blob': blob,
        'fingerprint': sha256_fingerprint(blob),
        'primary': container,
    }


def _provision_vanilla_sshd(server: _Server) -> None:
    """Make sure sshd is running on port 22 in ``server.container``.

    On Ubuntu containers openssh-server is installed and started during
    the deps step. On Alpine we install + enable openrc-style.
    """
    c = server.container
    if _is_alpine(c):
        lxc_exec(c, 'sh', '-c',
                 'rc-update add sshd default 2>/dev/null || true; '
                 'rc-service sshd start 2>/dev/null || true')
    else:
        lxc_exec(c, 'systemctl', 'enable', '--now', 'ssh', check=False)


def _push_authorized_keys(server: _Server,
                          user_keys: dict[str, dict]) -> None:
    """Concat the *allowed* users' pubkeys into each user's
    ~/.ssh/authorized_keys. The superuser's pubkey is appended to every
    user's authorized_keys (so the superuser can su-via-ssh to any user)
    AND added to /root/.ssh/authorized_keys (so the superuser can ssh
    in as root for admin config-push, modelling a real break-glass
    admin path).
    """
    superkey = user_keys[SUPERUSER.username]['pub_line']
    for u in USERS:
        if server.group not in u.allowed_groups:
            continue
        _ensure_unix_account(server.container, u.username)
        ak_lines = [user_keys[u.username]['pub_line']]
        if u.username != SUPERUSER.username:
            ak_lines.append(superkey)
        ak = '\n'.join(ak_lines) + '\n'
        push_text(server.container, ak,
                  f'/home/{u.username}/.ssh/authorized_keys', mode='600',
                  owner=f'{u.username}:{u.username}')
    # Superuser bypass: ssh root@server with their key works on every
    # box. This is how an operator would drive the flip scripts.
    lxc_exec(server.container, 'mkdir', '-p', '/root/.ssh')
    lxc_exec(server.container, 'chmod', '700', '/root/.ssh')
    push_text(server.container, superkey + '\n',
              '/root/.ssh/authorized_keys', mode='600', owner='root:root')


# ---------------------------------------------------------------------------
# Phase 1 / Phase 2 — msshd provisioning
# ---------------------------------------------------------------------------

def _ssh_pubkey_blob_from_ed25519(pubkey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    name = b'ssh-ed25519'
    return (struct.pack('>I', len(name)) + name
            + struct.pack('>I', len(raw)) + raw)


def _gen_user_ca_and_mtls_certs(out_dir: Path, *,
                                wrapper_host_sans: dict[str, str],
                                user_principals: list[str]) -> dict:
    """Generate a fresh Ed25519 user-CA and use it to sign:

      - one wrapper TLS server cert per container (CN/SAN = container IP)
      - one mTLS client cert per principal in ``user_principals``

    Returns paths + the ssh-ed25519 pubkey blob for each user (needed
    when enrolling the user at the CA).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    out_dir.mkdir(parents=True, exist_ok=True)
    user_ca_key = ed25519.Ed25519PrivateKey.generate()
    user_ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'mssh-adhoc-user-ca')])
    user_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(user_ca_name).issuer_name(user_ca_name)
        .public_key(user_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(user_ca_key, None))
    (out_dir / 'user-ca.crt').write_bytes(
        user_ca_cert.public_bytes(serialization.Encoding.PEM))

    # Wrapper TLS server cert per container (SAN = container's IP).
    wrapper_certs = {}
    for container, ip in wrapper_host_sans.items():
        ws_key = ed25519.Ed25519PrivateKey.generate()
        ws_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .issuer_name(user_ca_name)
            .public_key(ws_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(_ipaddr(ip)),
                     x509.DNSName('localhost')]),
                critical=False)
            .sign(user_ca_key, None))
        cp = out_dir / f'wrapper-{container}.crt'
        kp = out_dir / f'wrapper-{container}.key'
        cp.write_bytes(ws_cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(ws_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(kp, 0o600)
        wrapper_certs[container] = {'cert': str(cp), 'key': str(kp)}

    # Per-user mTLS client certs.
    clients = {}
    for principal in user_principals:
        ck = ed25519.Ed25519PrivateKey.generate()
        cc = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, principal)]))
            .issuer_name(user_ca_name)
            .public_key(ck.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .sign(user_ca_key, None))
        cert_path = out_dir / f'{principal}.crt'
        key_path  = out_dir / f'{principal}.key'
        cert_path.write_bytes(cc.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(ck.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        clients[principal] = {
            'cert': str(cert_path), 'key': str(key_path),
            'ssh_pubkey_blob': _ssh_pubkey_blob_from_ed25519(ck.public_key()),
        }
    return {'user_ca_path': str(out_dir / 'user-ca.crt'),
            'wrapper_certs': wrapper_certs, 'clients': clients}


def _ipaddr(s):
    import ipaddress
    return ipaddress.ip_address(s)


def _gen_wrapper_user_ca(out_dir: Path) -> tuple[Path, Path]:
    """Local wrapper user-CA — signs the ephemeral OpenSSH user certs
    that msshd hands to the inner sshd."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / 'wrapper-user-ca'
    pub  = out_dir / 'wrapper-user-ca.pub'
    for p in (priv, pub):
        if p.exists():
            p.unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '',
                    '-f', str(priv), '-q'],
                   check=True, capture_output=True)
    return priv, pub


# ---- wrapper.yaml renderers -------------------------------------------------

def _wrapper_yaml_fallback() -> str:
    return (
        'mode: fallback\n'
        f'fallback:\n'
        f'  host: 127.0.0.1\n'
        f'  port: {VANILLA_SSHD_PORT}\n'
        f'listen:\n'
        f'  external_address: 0.0.0.0\n'
        f'  external_port: {MSSHD_PORT}\n'
        f'  interfaces: []\n'
        f'logging:\n'
        f'  level: info\n'
        f'  destination: stderr\n'
        f'  audit_destination: file:/var/log/mssh/wrapper-audit.jsonl\n'
    )


def _wrapper_yaml_enforce(ca_ip: str, *, inner_mode: str = 'long-lived') -> str:
    return (
        'mode: enforce\n'
        f'listen:\n'
        f'  external_address: 0.0.0.0\n'
        f'  external_port: {MSSHD_PORT}\n'
        f'  interfaces: []\n'
        f'tls:\n'
        f'  server_cert: /etc/mssh/wrapper-server.crt\n'
        f'  server_key:  /etc/mssh/wrapper-server.key\n'
        f'  user_ca_pubkey: /etc/mssh/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://{ca_ip}:{CA_PORT}]\n'
        f'  client_cert: /etc/mssh/wrapper-mtls.crt\n'
        f'  client_key:  /etc/mssh/wrapper-mtls.key\n'
        f'  ca_pubkey:   /etc/mssh/server-mtls-ca.pub\n'
        f'  timeout_seconds: 5\n'
        f'inner:\n'
        f'  sshd_binary: /usr/sbin/sshd\n'
        f'  port_range: [49152, 65535]\n'
        f'  mode: {inner_mode}\n'
        f'users:\n'
        f'  allowed: ["*"]\n'
        f'logging:\n'
        f'  level: info\n'
        f'  destination: stderr\n'
        f'  audit_destination: file:/var/log/mssh/wrapper-audit.jsonl\n'
    )


def _systemd_msshd_unit() -> str:
    return (
        '[Unit]\nDescription=mssh wrapper (msshd)\n'
        'After=network-online.target\n'
        '[Service]\nWorkingDirectory=/app\n'
        'Environment="PYTHONPATH=/app/src"\n'
        'Environment="SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/mssh"\n'
        'ExecStart=/usr/bin/python3 -m mssh.msshd '
        '--config /etc/mssh/wrapper.yaml\n'
        'Restart=on-failure\nStandardError=journal\n'
        '[Install]\nWantedBy=multi-user.target\n'
    )


def _install_msshd(c: str, *, mode: str,
                   ca_ip: str | None = None) -> None:
    """Install msshd in the given mode and (re)start it. ``mode`` ∈
    {'fallback', 'enforce'}. On Alpine we use a nohup-style spawn
    because openrc init scripts for arbitrary Python daemons are messy.
    """
    yaml = (_wrapper_yaml_fallback() if mode == 'fallback'
            else _wrapper_yaml_enforce(ca_ip))
    lxc_exec(c, 'mkdir', '-p',
             '/etc/mssh',
             '/var/lib/mssh',
             '/var/lib/mssh/inner-sshd',
             '/var/log/mssh')
    push_text(c, yaml, '/etc/mssh/wrapper.yaml', mode='644')

    if _is_alpine(c):
        # Kill any prior instance, then nohup.
        lxc_exec(c, 'sh', '-c',
                 'fuser -k -9 {p}/tcp 2>/dev/null; sleep 1'.format(p=MSSHD_PORT),
                 check=False)
        lxc_exec(c, 'sh', '-c',
                 'cd /app && PYTHONPATH=/app/src '
                 'SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/mssh '
                 'nohup /usr/bin/python3 -m mssh.msshd '
                 '--config /etc/mssh/wrapper.yaml '
                 '> /var/log/mssh/msshd.log 2>&1 & '
                 'echo $! > /run/msshd.pid')
    else:
        push_text(c, _systemd_msshd_unit(),
                  '/etc/systemd/system/msshd.service')
        lxc_exec(c, 'systemctl', 'daemon-reload')
        lxc_exec(c, 'systemctl', 'restart', 'msshd')

    try:
        wait_for_port(c, MSSHD_PORT, max_wait=30)
    except Exception:
        if _is_alpine(c):
            log = lxc_exec(c, 'cat', '/var/log/mssh/msshd.log',
                           check=False)
            print(f'--- msshd log on {c} ---\n{log.stdout or ""}',
                  file=sys.stderr)
        else:
            log = lxc_exec(c, 'journalctl', '-u', 'msshd', '--no-pager',
                           '-n', '100', check=False)
            print(f'--- msshd journal on {c} ---\n{log.stdout or ""}',
                  file=sys.stderr)
        raise


def _push_msshd_cert_material(server: _Server, *,
                              wrapper_cert: str, wrapper_key: str,
                              user_ca_pub: str,
                              wrapper_mtls_cert: Path, wrapper_mtls_key: Path,
                              ca_tls_root: Path,
                              wrapper_user_ca_priv: Path,
                              wrapper_user_ca_pub: Path) -> None:
    """Push the cert material needed by enforce mode. Safe to push
    even when in fallback mode (msshd ignores it)."""
    c = server.container
    lxc_exec(c, 'mkdir', '-p',
             '/etc/mssh',
             '/var/lib/mssh',
             '/var/lib/mssh/inner-sshd')
    push_file(c, wrapper_cert, '/etc/mssh/wrapper-server.crt', mode='644')
    push_file(c, wrapper_key,  '/etc/mssh/wrapper-server.key', mode='600')
    push_file(c, user_ca_pub,  '/etc/mssh/user-ca.pub', mode='644')
    push_file(c, wrapper_mtls_cert, '/etc/mssh/wrapper-mtls.crt', mode='644')
    push_file(c, wrapper_mtls_key,  '/etc/mssh/wrapper-mtls.key', mode='600')
    push_file(c, ca_tls_root, '/etc/mssh/server-mtls-ca.pub', mode='644')
    push_file(c, str(wrapper_user_ca_priv),
              '/var/lib/mssh/wrapper-user-ca', mode='600')
    push_file(c, str(wrapper_user_ca_pub),
              '/var/lib/mssh/inner-sshd/wrapper-user-ca.pub', mode='644')


# ---------------------------------------------------------------------------
# In-container mssh shim — a 3-line shell wrapper around `python3 -m mssh.client`
# ---------------------------------------------------------------------------

_MSSH_WRAPPER_SCRIPT = '''#!/bin/sh
# /usr/local/bin/mssh — invokes the Python mssh client with the
# in-tree source code (no pip install required inside the container).
# Looks for ~/.mssh/{cert,key,ca}.pem; pass them via env to mssh.
exec env \\
    MSSH_CERT="${MSSH_CERT:-$HOME/.mssh/cert.pem}" \\
    MSSH_KEY="${MSSH_KEY:-$HOME/.mssh/key.pem}" \\
    MSSH_CA="${MSSH_CA:-$HOME/.mssh/ca.pem}" \\
    PYTHONPATH=/app/src \\
    /usr/bin/python3 -m mssh.client "$@"
'''


def _push_mssh_per_user(server: _Server, user: _User, pki: dict) -> None:
    """Drop per-user mssh material into /home/<user>/.mssh/."""
    c = server.container
    _ensure_unix_account(c, user.username)
    home_mssh = f'/home/{user.username}/.mssh'
    lxc_exec(c, 'sh', '-c',
             f'mkdir -p {home_mssh} && chmod 700 {home_mssh} && '
             f'chown -R {user.username}:{user.username} {home_mssh}')
    push_file(c, pki['clients'][user.username]['cert'],
              f'{home_mssh}/cert.pem', mode='600',
              owner=f'{user.username}:{user.username}')
    push_file(c, pki['clients'][user.username]['key'],
              f'{home_mssh}/key.pem', mode='600',
              owner=f'{user.username}:{user.username}')
    push_file(c, pki['user_ca_path'],
              f'{home_mssh}/ca.pem', mode='644',
              owner=f'{user.username}:{user.username}')


def _install_mssh_wrapper(c: str) -> None:
    push_text(c, _MSSH_WRAPPER_SCRIPT, '/usr/local/bin/mssh',
              mode='755')


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _verify_ssh(*, from_container: str, key_path: str, user: str,
                target_ip: str, target_port: int,
                expected_substr: str | None = None,
                expect_ok: bool = True) -> None:
    """Run a `whoami` over SSH and assert the outcome. ``from_container``
    is where the ssh binary runs; the keypair has been pushed there
    earlier as part of provisioning."""
    cmd = [
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10',
        '-i', key_path, '-p', str(target_port),
        f'{user}@{target_ip}', 'whoami',
    ]
    r = lxc_exec(from_container, *cmd, check=False, timeout=30)
    if expect_ok:
        assert r.returncode == 0, (
            f'ssh from {from_container} as {user}@{target_ip}:{target_port} '
            f'failed: rc={r.returncode} stdout={r.stdout!r} '
            f'stderr={r.stderr!r}')
        if expected_substr is not None:
            assert expected_substr in (r.stdout or ''), (
                f'expected {expected_substr!r} in stdout, got {r.stdout!r}')
    else:
        assert r.returncode != 0, (
            f'ssh from {from_container} as {user}@{target_ip}:{target_port} '
            f'unexpectedly succeeded: stdout={r.stdout!r}')


def _verify_mssh(*, from_container: str, user: str,
                 target_ip: str, target_port: int) -> None:
    """Run `mssh user@target:port -- whoami` from ``from_container`` (as
    root, using the user's mTLS material). Asserts success and that
    the remote whoami matches ``user``."""
    cmd = (
        f'MSSH_CERT=/home/{user}/.mssh/cert.pem '
        f'MSSH_KEY=/home/{user}/.mssh/key.pem '
        f'MSSH_CA=/home/{user}/.mssh/ca.pem '
        f'PYTHONPATH=/app/src '
        f'/usr/bin/python3 -m mssh.client '
        f'{user}@{target_ip}:{target_port} -- whoami'
    )
    r = lxc_exec(from_container, 'sh', '-c', cmd, check=False, timeout=30)
    assert r.returncode == 0, (
        f'mssh from {from_container} as {user}@{target_ip}:{target_port} '
        f'failed: rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')
    assert user in (r.stdout or ''), (
        f'expected {user!r} in mssh stdout, got {r.stdout!r}')


# ---------------------------------------------------------------------------
# adhoc-env artifact writers
# ---------------------------------------------------------------------------

def _write_cleanup_script(path: Path) -> None:
    path.write_text(
        '#!/usr/bin/env bash\n'
        '# Delete every container provisioned by the msshd adhoc lab.\n'
        'set -u\n'
        'for c in ' + ' '.join(ALL_CONTAINERS) + '; do\n'
        '    echo "deleting $c"\n'
        '    lxc delete --force "$c" 2>/dev/null || true\n'
        'done\n')
    path.chmod(0o755)


def _msshd_restart_cmd(server: _Server) -> str:
    """Per-container shell snippet to restart msshd in-place."""
    if _is_alpine(server.container):
        return (
            f'fuser -k -9 {MSSHD_PORT}/tcp 2>/dev/null; sleep 1; '
            f'cd /app && PYTHONPATH=/app/src '
            f'SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/mssh '
            f'nohup /usr/bin/python3 -m mssh.msshd '
            f'--config /etc/mssh/wrapper.yaml '
            f'> /var/log/mssh/msshd.log 2>&1 & '
            f'echo $! > /run/msshd.pid'
        )
    return 'systemctl restart msshd'


def _flip_script(target_mode: str, yaml: str, ips: dict,
                 ca_ip: str, *, script_label: str | None = None) -> str:
    """Render a self-contained flip script that runs on the CA container.

    ``target_mode`` is what the post-flip verify command should expect
    (``enforce`` → use ``mssh``, ``fallback`` → use ``ssh -p MSSHD_PORT``).
    ``script_label`` controls the filename and headline only — useful
    when several enforce-mode variants (long-lived, per-connection)
    share the same verify transport but ship as distinct files.

    Uses ssh root@<server> (root-admin's pubkey is in /root/authorized_keys
    on every server) for the config-push step; reverts on verification
    failure.

    Models an actual operator workflow — no `lxc exec` anywhere.
    """
    if script_label is None:
        script_label = target_mode
    verify_cmd, verify_desc = ({
        'enforce':  ('mssh root-admin@$ip:$MSSHD_PORT -- whoami',
                     'mssh ↔ msshd (mTLS + CA-mediated)'),
        'fallback': ('ssh $SSH_N -p $MSSHD_PORT root-admin@$ip whoami',
                     'ssh -p ${MSSHD_PORT} (proxied via msshd to inner sshd)'),
    })[target_mode]

    rows = []
    for s in SERVERS:
        rows.append(f'{s.canonical}|{ips[s.container]}|{_msshd_restart_cmd(s)}')
    server_table = '\n'.join(rows)

    return f'''#!/bin/sh
# /home/root-admin/flip-to-{script_label}.sh
#
# Operator-grade flip script. Runs on the CA container as root-admin.
# For each server: backs up the current wrapper.yaml, pushes the
# {script_label} config, restarts msshd, verifies via
# {verify_desc}, and reverts on failure.
#
# No `lxc exec` — only ssh (config push via the root@<server> backdoor
# that root-admin's pubkey was added to during lab setup) and mssh
# (post-flip verification when target=enforce).

set -u

SSH_KEY=/home/root-admin/.ssh/id_ed25519
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no \\
    -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"
# -n on every ssh that doesn't consume stdin — otherwise ssh swallows
# the pipe feeding our `while read` loop and we only process one server.
SSH_N="$SSH_OPTS -n"
MSSHD_PORT={MSSHD_PORT}
CA_IP={ca_ip}

export MSSH_CERT=/home/root-admin/.mssh/cert.pem
export MSSH_KEY=/home/root-admin/.mssh/key.pem
export MSSH_CA=/home/root-admin/.mssh/ca.pem

# Heredoc would interfere with shell substitution; write the YAML to
# a temp file and scp/cat it across.
WRAPPER_YAML=$(cat <<'YAML'
{yaml}YAML
)

flip_one() {{
    name="$1"; ip="$2"; restart="$3"
    printf '%-12s (%s) ... ' "$name" "$ip"

    # Backup, push new, restart.
    if ! ssh $SSH_N root@$ip \\
            'cp /etc/mssh/wrapper.yaml /tmp/wrapper.yaml.bak' \\
            2>/dev/null; then
        echo "SSH UNREACHABLE — skipped"
        return 1
    fi
    printf '%s' "$WRAPPER_YAML" | ssh $SSH_OPTS root@$ip \\
        'cat > /etc/mssh/wrapper.yaml'
    ssh $SSH_N root@$ip "$restart" >/dev/null 2>&1
    sleep 3

    # Verify with the post-flip transport.
    if {verify_cmd} 2>/dev/null | grep -q '^root-admin$'; then
        echo "OK ({script_label})"
        return 0
    fi
    # Verify failed: revert.
    echo "FAILED — reverting"
    ssh $SSH_N root@$ip \\
        'cp /tmp/wrapper.yaml.bak /etc/mssh/wrapper.yaml' \\
        2>/dev/null
    ssh $SSH_N root@$ip "$restart" >/dev/null 2>&1
    return 1
}}

SERVERS_TABLE='{server_table}'

echo "Flipping all servers to: {script_label}..."
echo "$SERVERS_TABLE" | while IFS='|' read -r name ip restart; do
    [ -z "$name" ] && continue
    # </dev/null protects the loop's pipe from being consumed by any
    # ssh/mssh inside flip_one (mssh forwards stdin to the remote PTY).
    flip_one "$name" "$ip" "$restart" </dev/null || true
done

echo
echo "Done. Verify a session by running, e.g.:"
echo "  mssh alice@$(echo \"$SERVERS_TABLE\" | head -1 | cut -d'|' -f2):$MSSHD_PORT -- whoami"
'''


def _push_flip_scripts_to_ca(ips: dict, ca_ip: str) -> None:
    """Generate the flip scripts and push them to /home/root-admin/
    on the CA container.

    Three operator-facing scripts:
      - flip-to-enforce.sh       — enforce + long-lived inner (default)
      - flip-to-per-connection.sh — enforce + per-connection inner (Phase 2)
      - flip-to-fallback.sh      — pure TCP proxy to system sshd
    """
    enforce_yaml         = _wrapper_yaml_enforce(ca_ip)
    enforce_perconn_yaml = _wrapper_yaml_enforce(ca_ip,
                                                  inner_mode='per-connection')
    fallback_yaml        = _wrapper_yaml_fallback()
    targets = (
        ('enforce',         enforce_yaml,         'enforce'),
        ('per-connection',  enforce_perconn_yaml, 'enforce'),
        ('fallback',        fallback_yaml,        'fallback'),
    )
    for label, yaml, verify_mode in targets:
        script = _flip_script(verify_mode, yaml, ips, ca_ip,
                              script_label=label)
        push_text(CA_NAME, script,
                  f'/home/root-admin/flip-to-{label}.sh',
                  mode='755',
                  owner=f'{SUPERUSER.username}:{SUPERUSER.username}')


def _ansible_template_dir() -> Path:
    """Path to the ansible-project skeleton this repo ships."""
    return Path(__file__).resolve().parent.parent / 'ansible-project'


def _render_ansible_hosts_ini(ips: dict, prefix: str) -> str:
    """Render the inventory matching the user's ansible-project template:
    groups by OS (ubuntu_servers / alpine_servers / fedora_servers /
    debian) and by role (ca_server / sales / accounting / hr / engineering).

    Each line carries the container's bridged IP. The ``[all:vars]``
    block tells ansible to ssh as root using the dedicated key the lab
    pushes to /root/.ssh/ on every container."""
    ubuntu_servers = [(CA_NAME, ips[CA_NAME]),
                      (ACCT_NAME, ips[ACCT_NAME]),
                      (SALES_NAME, ips[SALES_NAME]),
                      (HR_NAME, ips[HR_NAME])]
    alpine_servers = [(ENG_NAME, ips[ENG_NAME])]

    def block(name: str, members: list) -> str:
        lines = [f'[{name}]']
        for n, ip in members:
            lines.append(f'{n} ansible_host={ip}')
        lines.append('')
        return '\n'.join(lines)

    return '\n'.join([
        block('fedora_servers', []),
        block('ubuntu_servers', ubuntu_servers),
        block('alpine_servers', alpine_servers),
        block('debian', []),       # alias the operator can populate
        block('ca_server', [(CA_NAME, ips[CA_NAME])]),
        block('sales', [(SALES_NAME, ips[SALES_NAME])]),
        block('accounting', [(ACCT_NAME, ips[ACCT_NAME])]),
        block('hr', [(HR_NAME, ips[HR_NAME])]),
        block('engineering', [(ENG_NAME, ips[ENG_NAME])]),
        # Convenience parent group used by site.yml so a plain
        # `ansible-playbook site.yml` actually matches hosts. Every
        # OS group rolls up into proxy_clients by default.
        '[proxy_clients:children]',
        'ubuntu_servers',
        'alpine_servers',
        'debian',
        'fedora_servers',
        '',
        '[all:vars]',
        'ansible_user=root',
        # Relative to this hosts.ini's directory so the same inventory
        # works on the host (./ansible-project/ansible_id_ed25519) and
        # on the CA (/root/ansible-project/ansible_id_ed25519).
        'ansible_ssh_private_key_file=./ansible_id_ed25519',
        ('ansible_ssh_common_args=\'-o StrictHostKeyChecking=no '
         '-o UserKnownHostsFile=/dev/null\''),
        f'ansible_python_interpreter=/usr/bin/python3',
        '',
        f'# Lab prefix: {prefix}',
        '',
    ])


_EXAMPLE_PLAYBOOK_UPGRADE_ASYNCSSH = '''---
# Standalone playbook — fix the "interactive mssh session drops after
# first input" bug on Ubuntu 22.04 containers. Ubuntu's apt
# python3-asyncssh is pinned at 2.5.0 (from 2020); msshd needs 2.14+
# for stable interactive PTY data flow. Pip-overrides the apt version,
# then restarts msshd.
#
# Run from the CA:
#     cd ~/ansible-project
#     ansible-playbook -i hosts.ini playbook_upgrade_asyncssh.yml
#
# This is a STANDALONE playbook (its own `hosts:` block) so it doesn't
# depend on site.yml's `proxy_clients` group target. Delete it if your
# lab doesn't need the workaround.

- name: "Upgrade asyncssh to >=2.14 on every Ubuntu msshd host"
  hosts: ubuntu_servers
  become: true
  gather_facts: false
  tasks:
    - name: "Ensure python3-pip is installed (Ubuntu's python3 ships without it)"
      ansible.builtin.apt:
        name: python3-pip
        state: present
        update_cache: false

    - name: "pip-install asyncssh>=2.14 (overrides the apt 2.5.0)"
      ansible.builtin.pip:
        name: "asyncssh>=2.14"
        state: latest
      # NOTE: on Ubuntu 24.04 / Debian 12+ (PEP 668 enforcement), add
      #   extra_args: "--break-system-packages"
      # Ubuntu 22.04's pip doesn't recognize that flag, so it's omitted.

    - name: "Restart msshd (skipped if not yet installed)"
      ansible.builtin.systemd:
        name: msshd
        state: restarted
      failed_when: false
'''


def _write_ansible_project(out_dir: Path, ips: dict, prefix: str) -> None:
    """Copy the ansible-project skeleton from python/tests/ansible-project/
    to ``out_dir``, then overwrite hosts.ini with one rendered from the
    live lab's containers + groups. Adds an example
    ``task_upgrade_asyncssh.yml`` the operator can use to fix the known
    interactive-mssh-PTY bug (Ubuntu 22.04's python3-asyncssh is too old)."""
    template = _ansible_template_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    for src in template.iterdir():
        if src.is_file():
            shutil.copy2(src, out_dir / src.name)
    # Overwrite hosts.ini with the rendered version.
    (out_dir / 'hosts.ini').write_text(
        _render_ansible_hosts_ini(ips, prefix))
    # Drop the example standalone playbook. Operator can delete it.
    (out_dir / 'playbook_upgrade_asyncssh.yml').write_text(
        _EXAMPLE_PLAYBOOK_UPGRADE_ASYNCSSH)


def _setup_ansible_on_ca(ips: dict, prefix: str,
                        ansible_project_host_dir: Path) -> None:
    """Wire the lab for ansible — works from both the host and the CA.

      1. Install ansible-core on the CA (apt; Ubuntu has it).
      2. Generate a dedicated ed25519 keypair on the HOST at
         ``<ansible_project_host_dir>/ansible_id_ed25519`` (private key
         mode 600). This is the single source of truth for the key.
      3. Push the public half to /root/.ssh/authorized_keys on every
         SSH-capable container.
      4. Push the rendered ansible-project tree (including the private
         key) to /root/ansible-project/ on the CA.

    After this, an operator on EITHER side can:
        cd ./ansible-project        # host
        cd /root/ansible-project    # CA
        ansible all -m ping
        ansible-playbook site.yml

    hosts.ini's ``ansible_ssh_private_key_file=./ansible_id_ed25519``
    is relative, so the same inventory resolves in both contexts.
    """
    # 1. apt install ansible on CA.
    lxc_exec(CA_NAME, 'sh', '-c',
             'DEBIAN_FRONTEND=noninteractive apt-get install -y -q '
             'ansible-core 2>&1 | tail -5',
             check=False, timeout=180)

    # 2. Generate the ansible keypair on the HOST inside the rendered
    #    ansible-project dir. Idempotent: skip if it already exists from
    #    a prior run. mode 0600 on the private key so ssh + ansible
    #    accept it.
    key_priv = ansible_project_host_dir / 'ansible_id_ed25519'
    key_pub  = ansible_project_host_dir / 'ansible_id_ed25519.pub'
    if not key_priv.exists():
        subprocess.run(
            ['ssh-keygen', '-t', 'ed25519', '-N', '', '-q',
             '-f', str(key_priv), '-C', 'ansible@mssh-lab'],
            check=True)
    os.chmod(key_priv, 0o0600)
    ansible_pubkey = key_pub.read_text().strip() + '\n'

    # 3. Distribute to root@<each container> — INCLUDING the CA itself,
    #    since `[all]` in the inventory covers it. Ensure sshd is
    #    running on Alpine (Ubuntu's apt install enables it; Alpine
    #    needs explicit start).
    for c in ALL_CONTAINERS:
        if c.endswith('-eng'):
            # Alpine — install + start openssh-server explicitly.
            lxc_exec(c, 'sh', '-c',
                     'apk add --no-cache openssh-server openssh-keygen '
                     '2>&1 | tail -3', check=False, timeout=120)
            lxc_exec(c, 'ssh-keygen', '-A', check=False, timeout=30)
            lxc_exec(c, 'sh', '-c',
                     "sed -i 's|^#*PermitRootLogin.*|PermitRootLogin "
                     "prohibit-password|' /etc/ssh/sshd_config", check=False)
            lxc_exec(c, 'sh', '-c',
                     '/usr/sbin/sshd 2>/dev/null; true', check=False)
        else:
            # Ubuntu — sshd installed by apt is enabled; just ensure
            # PermitRootLogin is sane for key-auth.
            lxc_exec(c, 'sh', '-c',
                     "sed -i 's|^#*PermitRootLogin.*|PermitRootLogin "
                     "prohibit-password|' /etc/ssh/sshd_config "
                     "&& systemctl reload ssh 2>/dev/null || true",
                     check=False)
        # The CA's authorized_keys is special: it might also carry the
        # superuser's SSH key at a later phase. Append rather than
        # overwrite to preserve any prior content. Best-effort dedup.
        lxc_exec(c, 'mkdir', '-p', '/root/.ssh')
        lxc_exec(c, 'chmod', '700', '/root/.ssh')
        if c == CA_NAME:
            lxc_exec(c, 'sh', '-c',
                     'touch /root/.ssh/authorized_keys && '
                     'chmod 600 /root/.ssh/authorized_keys')
            # Append-if-missing using grep -F.
            push_text(c, ansible_pubkey, '/tmp/ansible.pub', mode='644')
            lxc_exec(c, 'sh', '-c',
                     'grep -qFx -f /tmp/ansible.pub '
                     '/root/.ssh/authorized_keys 2>/dev/null || '
                     'cat /tmp/ansible.pub >> /root/.ssh/authorized_keys; '
                     'rm /tmp/ansible.pub')
        else:
            push_text(c, ansible_pubkey, '/root/.ssh/authorized_keys',
                      mode='600')

    # 4. Push the rendered project to the CA. Pre-cleanup so re-runs
    #    don't accumulate stale tasks.
    lxc_exec(CA_NAME, 'rm', '-rf', '/root/ansible-project', check=False)
    lxc_exec(CA_NAME, 'mkdir', '-p', '/root/ansible-project')
    for f in sorted(ansible_project_host_dir.iterdir()):
        if f.is_file():
            # The private key MUST land at 0600 or ssh/ansible refuse
            # to use it. Everything else (yaml/cfg/ini/pubkey) at 0644.
            if f.name == 'ansible_id_ed25519':
                push_file(CA_NAME, f,
                          f'/root/ansible-project/{f.name}', mode='600')
            else:
                push_file(CA_NAME, f,
                          f'/root/ansible-project/{f.name}', mode='644')


def _write_root_readme(container: str, ca_ip: str, stop_at_phase: int) -> None:
    """Push /root/README.md to a container, telling an operator what
    state the lab is parked at and how to advance using mssh-admin's
    guide tools (`mssh-admin status` / `mssh-admin next`).

    The README is most useful at --phase 0 (blank slate) and --phase 1
    or 2 (partial setup) — that's where an operator might want to take
    over manually. Phase 3 (fully configured) still gets the README so
    the operator has reference material on the host.
    """
    phase_summary = {
        0: ('Blank slate. The CA is running but **nothing else** on this '
            'host is configured. From here, you walk the full SSH-to-mssh '
            'migration by hand. Start with `mssh-admin status` on the '
            'operator workstation to see the empty state, then '
            '`mssh-admin next` for the first command.'),
        1: ('Vanilla sshd is configured and `ssh user@host` works for '
            'enrolled users. Next: install msshd in fallback mode in '
            'front of the system sshd, then enrol this server at the CA '
            'and flip msshd to enforce.'),
        2: ('Fully configured: msshd is in enforce mode and `mssh '
            'user@host:2200` works through the CA-mediated path. '
            'Flip scripts live on the CA for switching between modes: '
            'flip-to-fallback (system sshd takes over), flip-to-enforce '
            '(default — long-lived inner sshd), flip-to-per-connection '
            '(enforce + fresh inner sshd per session, config rendered '
            'by the CA).'),
    }[stop_at_phase]

    body = f'''# mssh adhoc lab — manual-setup notes for {container}

**Current lab phase: {stop_at_phase}.** {phase_summary}

## What's installed already

  - mssh source tree at `/app/`. Either run via `PYTHONPATH=/app/src
    python3 -m mssh.<module>`, or `cd /app && pip install -e .` to put
    the CLI commands on this host's PATH:

        mssh         — client CLI
        msshd        — gateway daemon
        mssh-admin   — operator CLI (talks to the CA over mTLS)
        mssh-ca      — CA service
        mssh-mcp     — read-only MCP server for the CA (optional)

  - Python deps already on the host: asyncssh, cryptography, flask,
    pyyaml, click, requests.

  - OpenSSH server + client installed by the lab's apt step.

## CA reachability

  - CA listening at **https://{ca_ip}:8443** (mTLS-only). The CA's
    admin endpoints use this URL.
  - Admin credentials for the CA are **not** on this host — they live
    on the operator workstation that ran `setup_adhoc.sh`. You'll
    typically invoke `mssh-admin` from there, not from inside this
    container.

## Use `mssh-admin next` as your guide

From the operator workstation (the host that has admin creds):

    mssh-admin status     # full state walk: ✓ on what's done, ✗ on what's not
    mssh-admin next       # just the next concrete command to run

The status walk knows about: CA up, admins enrolled, servers enrolled,
users enrolled, every user with at least one key, every user with at
least one policy. As you provision, those checks flip from ✗ to ✓.

## Deploying via ansible from the CA

The lab installs ansible-core on the CA and pre-populates an inventory
at `/root/ansible-project/` covering every container in this lab. From
the CA:

    cd /root/ansible-project
    ansible all -m ping              # smoke-test all containers
    ansible-playbook site.yml        # runs every task*.yml + framework*.yml

The inventory groups containers by OS (`ubuntu_servers`,
`alpine_servers`, …) and by role (`ca_server`, `accounting`, `sales`,
`hr`, `engineering`). Drop your own `task_<name>.yml` files alongside
`task_ca.yml` / `task_squid.yml` and they get picked up by `site.yml`'s
glob (under whichever group `site.yml`'s `hosts:` is set to).

There's also a standalone `playbook_upgrade_asyncssh.yml` that fixes
the known "interactive mssh session drops on first input" bug on
Ubuntu 22.04 (Ubuntu's apt python3-asyncssh is pinned at 2.5.0; msshd
needs 2.14+). Run it directly:

    ansible-playbook -i hosts.ini playbook_upgrade_asyncssh.yml

Delete it if your fleet doesn't need it.

The same `/root/ansible-project/` exists on the operator host
(`./ansible-project/`) for editing locally. Push your edits to the CA
with `lxc file push` or rsync.

## Manual steps from Phase {stop_at_phase}

See the operator docs at `/app/docs/`:

  - **docs/MIGRATION.md** — production-style step-by-step runbook
    (Phase 1 set up CA → Phase 2 msshd fallback → Phase 4 enforce).
    This is the source of truth for "what command do I run next?"
    when `mssh-admin next` isn't enough.
  - **docs/TUTORIAL.md** — 60-minute guided walkthrough using this
    same adhoc lab as the sandbox.
  - **docs/operations.md** — day-to-day operator reference.

## What this README does NOT cover

  - Running the CA service. The CA is already up. To inspect it:
    `journalctl -u mssh-ca` (on the CA container, not here).
  - Generating user keypairs. The lab generates per-user keypairs at
    Phase 1; if you're at Phase 0 you'll do this yourself.

If you want the lab to go further automatically, exit the adhoc shell
and re-run `setup_adhoc.sh` with a higher `--phase`.
'''
    push_text(container, body, '/root/README.md', mode='644')


def _finalize_adhoc_artifacts(*, stop_at_phase: int, invocation_cwd: Path,
                              ips: dict, artifacts_dir: Path,
                              keys_generated: bool) -> None:
    """Write the host-side artifacts the operator needs to interact with
    the lab. Always writes everything: cleanup script, adhoc-env.sh,
    ADHOC_TEST_ENV.md, and per-container READMEs. At Phase 0 the env
    helpers reference per-user keypaths that don't exist yet — sourcing
    is still safe (env vars are just strings), and the helpers fail at
    use time with a missing-key error. The IPs and container names are
    useful even at Phase 0, so write them unconditionally.

    Pushes /root/README.md to every server container (and the CA) so an
    operator who `lxc exec`s in has setup notes wherever they land.
    """
    _write_cleanup_script(invocation_cwd / 'cleanup_containers.sh')
    _write_env_sh(invocation_cwd / 'adhoc-env.sh',
                  ips=ips, artifacts_dir=artifacts_dir,
                  keys_generated=keys_generated)
    _write_overview_md(invocation_cwd / 'ADHOC_TEST_ENV.md',
                       ips=ips, artifacts_dir=artifacts_dir,
                       keys_generated=keys_generated)
    for c in ALL_CONTAINERS:
        _write_root_readme(c, ips[CA_NAME], stop_at_phase)


def _write_overview_md(path: Path, *, ips: dict, artifacts_dir: Path,
                       keys_generated: bool = True) -> None:
    user_lines = []
    for u in USERS:
        allowed = _allowed_servers_for(u)
        allowed_str = ', '.join(s.canonical.replace('srv-', '')
                                for s in allowed) or '(none)'
        user_lines.append(
            f'| {u.username} | {u.department} | {allowed_str} |')
    server_lines = '\n'.join(
        f'| {s.canonical.replace("srv-", "")} | {s.canonical} | '
        f'{s.group} | {ips[s.container]} |'
        for s in SERVERS)
    phase0_banner = ('' if keys_generated else
        '> **Phase 0 stop point.** Per-user keypairs + mTLS material '
        'have not been generated yet — the `mssh_as` / `ssh_as` helpers '
        'in `adhoc-env.sh` reference files under `adhoc-keys/` that do '
        'not exist on disk. The IP / container-name exports work fine; '
        'use them with raw `lxc exec` or your own ssh until you rerun '
        'with `--phase 1` or `--phase 2`.\n\n')
    path.write_text(phase0_banner + f'''# mssh adhoc lab — what you've got

5 machines: 4 SSH servers (acct, sales, hr, eng) + 1 CA. All driven
**from the host** via ssh/mssh — you don't need to know or care that
they're LXC containers underneath.

## One-liner setup

```bash
source ./adhoc-env.sh
```

That exports every IP, every key path, and a few helper functions
(`mssh_as`, `ssh_as`, `ssh_as_2200`, `flip_to_enforce`,
`flip_to_fallback`). Everything below assumes you've sourced it.

## Servers

| short | canonical | group | IP |
|---|---|---|---|
{server_lines}
| ca | — | — | {ips[CA_NAME]} |

## Users

| user | department | allowed servers |
|---|---|---|
{chr(10).join(user_lines)}

`root-admin` is the superuser — has access everywhere via CA policy,
and their SSH key is in every other user's `authorized_keys` plus
`/root/.ssh/authorized_keys` on every server (the break-glass admin
path the flip scripts use).

## Trying things — host commands only

The lab leaves you in **Phase 2 (enforce)** mode. mssh goes through
msshd → CA → inner sshd. Three transports are available:

```bash
# Phase 2: mssh as alice, talking to msshd-enforce on port 2200
mssh_as alice acct whoami            # OK (alice's policy grants accounting)
mssh_as alice sales whoami           # denied — out-of-policy
mssh_as root-admin sales whoami      # OK (superuser policy grants everything)

# Phase 0: plain ssh to vanilla sshd on port 22. Always works,
# bypasses msshd entirely. Useful as your backdoor.
ssh_as alice acct                    # interactive shell
ssh_as alice acct whoami             # one-shot

# Phase 1: ssh through msshd-fallback on port 2200. Only works after
# `flip_to_fallback` has been run.
flip_to_fallback                     # all 4 servers → fallback mode
ssh_as_2200 alice acct whoami        # ssh transparently proxied via msshd
flip_to_enforce                      # back to Phase 2
```

## Flipping modes — operator workflow

`flip_to_enforce`, `flip_to_per_connection`, and `flip_to_fallback`
are shell functions that ssh to the CA as `root-admin` and run the
actual flip scripts (`/home/root-admin/flip-to-*.sh` on the CA).
The scripts loop over every server, push the new `wrapper.yaml`,
restart msshd, verify via the post-flip transport (mssh for the
enforce variants, ssh -p 2200 for fallback), and revert that
server's config if verification fails.

The three enforce-shaped modes:

  - **enforce** (default) — long-lived inner sshd, single hermetic
    config rendered at msshd boot. Lowest overhead.
  - **per-connection** — fresh inner sshd per session, config
    rendered by the CA per (user, server, policy). ~50–100 ms
    session-setup overhead. Unlocks per-user banner substitution
    and OpenSSH-native enforcement of per-session policy.
  - **fallback** — pure TCP proxy to the system sshd on port 22.
    No CA call. Operator's break-glass when the CA is broken.

No `lxc exec` anywhere — it's the same workflow a real operator
would use against an internet-routable CA.

## Per-user material (on the host)

```
adhoc-keys/
├── <user>                   # SSH Ed25519 private key      → $ALICE_KEY
├── <user>.pub               # SSH public key (Phase 0/1)
├── <user>.crt               # X.509 mTLS client cert (Phase 2) → $ALICE_CRT
├── <user>.key               # X.509 mTLS client key           → $ALICE_KEYPEM
└── user-ca.crt              # mTLS trust root                 → $USER_CA
```

Every per-user env var follows the same shape: `$ALICE_KEY`,
`$BOB_CRT`, `$ROOT_ADMIN_KEYPEM`, etc.

## Cleanup

```bash
./cleanup_containers.sh
```

## Advanced — when you actually want to be inside a container

You don't normally need this, but for debugging it's useful:

```bash
lxc exec {ACCT_NAME} -- su - alice    # interactive shell as alice in acct
lxc exec {CA_NAME}   -- cat /var/log/mssh/audit.jsonl
lxc exec {CA_NAME}   -- journalctl -u mssh-ca --no-pager -n 50
```

The full container names are `{CA_NAME}`, `{ACCT_NAME}`,
`{SALES_NAME}`, `{HR_NAME}`, `{ENG_NAME}`.
''')


def _write_env_sh(path: Path, *, ips: dict, artifacts_dir: Path,
                  keys_generated: bool = True) -> None:
    """adhoc-env.sh — source from the host. Exposes IPs, ports, key
    paths, and helper functions so the operator can act as any user
    via host-side ssh/mssh, with `lxc exec` nowhere in sight.

    At Phase 0 (keys_generated=False) the IP / port / container-name
    exports are still useful; the per-user key paths point at files
    that don't exist yet. The helper functions emit a clear warning if
    invoked before phase 1+ instead of failing with a cryptic
    'identity file not found'.
    """
    # Host-side mssh: invoke the in-tree module directly so we don't
    # depend on the venv's `mssh` entry-point shim being current.
    # app_root/python/src is the canonical PYTHONPATH for the
    # checked-out source tree.
    src_dir = Path(__file__).resolve().parent.parent.parent / 'src'
    # Server name → IP. Use short names (acct, sales, hr, eng, ca).
    server_env = []
    for s in SERVERS:
        short = s.canonical.replace('srv-', '')
        server_env.append(f'export {short}_IP={ips[s.container]}')
    server_env.append(f'export ca_IP={ips[CA_NAME]}')

    # User → key paths.
    user_env = []
    for u in USERS:
        n = u.username.upper().replace('-', '_')
        user_env += [
            f'export {n}_KEY={artifacts_dir}/{u.username}',
            f'export {n}_PUB={artifacts_dir}/{u.username}.pub',
            f'export {n}_CRT={artifacts_dir}/{u.username}.crt',
            f'export {n}_KEYPEM={artifacts_dir}/{u.username}.key',
        ]

    phase0_header = ('' if keys_generated else f'''# ---------------------------------------------------------------------------
# PHASE 0 STOP POINT
# ---------------------------------------------------------------------------
# This env was generated before any per-user keypairs or mTLS material
# was created. The IP / port / container exports below work; the
# mssh_as / ssh_as / ssh_as_2200 helpers will print a clear error
# until you re-run the test with --phase 1 or --phase 2.
_MSSH_LAB_PHASE0=1

''')
    body = f'''# Source me from the directory that contains adhoc-keys/.
# Lets you run ssh/mssh as any user directly from the host — no
# `lxc exec` required. The lab containers are addressable by their
# bridged IPs (exposed below).

export USER_CA={artifacts_dir}/user-ca.crt
export MSSHD_PORT={MSSHD_PORT}
export SSHD_PORT={VANILLA_SSHD_PORT}
# Where to find the mssh Python module (host-side invocations).
export MSSH_SRC_DIR={src_dir}

# Server short-name → IP
{chr(10).join(server_env)}

# Per-user identity material
{chr(10).join(user_env)}

# ---- Helper functions ------------------------------------------------------
#
# Usage in all three forms:
#   mssh_as     <user> <server> [cmd...]   # Phase 2: mssh → msshd → CA → inner sshd
#   ssh_as      <user> <server> [cmd...]   # Phase 0: ssh → vanilla sshd on 22 (always works)
#   ssh_as_2200 <user> <server> [cmd...]   # Phase 1: ssh → msshd-fallback → sshd on 22
#
# <server> is the short name: acct | sales | hr | eng | ca
# <user> is any USERS entry: alice amy bob bart carol charlie dave diana root-admin
# Run with no [cmd] to land in an interactive shell.

_resolve_ip() {{
    local short="$1"
    eval "echo \\"\\${{${{short}}_IP:-}}\\""
}}

_user_envvar() {{
    # Helpers accept either form: root-admin or root_admin. The env
    # var is always uppercase-underscore (ROOT_ADMIN_*); the Unix
    # account / SSH login name is always lowercase-hyphen (root-admin).
    echo "$1" | tr 'a-z-' 'A-Z_'
}}

_user_unix_name() {{
    echo "$1" | tr '_' '-'
}}

# Phase-0 guard. If the lab was set up with --phase 0, no per-user
# keypairs / mTLS material has been generated yet, so mssh_as /
# ssh_as / ssh_as_2200 cannot work. Bail out with a clear message.
_phase0_guard() {{
    if [ -n "${{_MSSH_LAB_PHASE0:-}}" ]; then
        echo "$1: lab is at Phase 0 — per-user keys not generated yet." >&2
        echo "  Re-run setup with: pytest ... --phase 1   (or --phase 2)" >&2
        return 1
    fi
}}

# -o IdentitiesOnly=yes ensures ssh offers ONLY the -i key, not
# every key in the agent — otherwise the server hits MaxAuthTries
# and disconnects before our key gets tried.
_SSH_OPTS='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes'

mssh_as() {{
    _phase0_guard mssh_as || return 1
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server (try acct/sales/hr/eng/ca)" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local cert key
    eval "cert=\\$${{U}}_CRT"
    eval "key=\\$${{U}}_KEYPEM"
    if [ "$#" -eq 0 ]; then
        MSSH_CERT="$cert" MSSH_KEY="$key" MSSH_CA="$USER_CA" \\
            PYTHONPATH="$MSSH_SRC_DIR" \\
            python3 -m mssh.client "$unix@$ip:$MSSHD_PORT"
    else
        MSSH_CERT="$cert" MSSH_KEY="$key" MSSH_CA="$USER_CA" \\
            PYTHONPATH="$MSSH_SRC_DIR" \\
            python3 -m mssh.client "$unix@$ip:$MSSHD_PORT" -- "$@"
    fi
}}

ssh_as() {{
    _phase0_guard ssh_as || return 1
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local key; eval "key=\\$${{U}}_KEY"
    ssh -i "$key" $_SSH_OPTS -p $SSHD_PORT "$unix@$ip" "$@"
}}

ssh_as_2200() {{
    _phase0_guard ssh_as_2200 || return 1
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local key; eval "key=\\$${{U}}_KEY"
    ssh -i "$key" $_SSH_OPTS -p $MSSHD_PORT "$unix@$ip" "$@"
}}

# Convenience: flip the lab between modes from the host. The script
# itself lives on the CA container at /home/root-admin/; we just invoke
# it via the superuser's ssh key (no `lxc exec`).

flip_to_enforce() {{
    _phase0_guard flip_to_enforce || return 1
    ssh -i "$ROOT_ADMIN_KEY" $_SSH_OPTS \\
        "root-admin@$ca_IP" ./flip-to-enforce.sh
}}

flip_to_per_connection() {{
    _phase0_guard flip_to_per_connection || return 1
    ssh -i "$ROOT_ADMIN_KEY" $_SSH_OPTS \\
        "root-admin@$ca_IP" ./flip-to-per-connection.sh
}}

flip_to_fallback() {{
    _phase0_guard flip_to_fallback || return 1
    ssh -i "$ROOT_ADMIN_KEY" $_SSH_OPTS \\
        "root-admin@$ca_IP" ./flip-to-fallback.sh
}}

echo "adhoc env loaded. Try:"
echo "  mssh_as alice acct whoami           # mssh through msshd (Phase 2)"
echo "  ssh_as alice acct whoami            # plain ssh (Phase 0, always works)"
echo "  flip_to_fallback                    # all servers → msshd fallback mode"
echo "  flip_to_enforce                     # all servers → msshd enforce + long-lived inner (default)"
echo "  flip_to_per_connection              # all servers → msshd enforce + per-connection inner"
'''
    path.write_text(phase0_header + body)


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

def test_setup_adhoc_msshd_journey(request, tmp_path_factory):
    invocation_cwd = Path(os.getcwd()).resolve()
    artifacts_dir  = invocation_cwd / 'adhoc-keys'
    artifacts_dir.mkdir(exist_ok=True)
    ca_creds_dir   = invocation_cwd / 'adhoc-ca-creds'
    ca_creds_dir.mkdir(exist_ok=True)

    # --phase N: 0 = containers + CA + source pushed (manual-setup
    # starting point); 1 = + vanilla sshd; 2 = + msshd fallback;
    # 3 (default) = + msshd enforce. See conftest.py.
    stop_at_phase = int(request.config.getoption('--phase'))

    # --lxc-prefix overrides the default `mssh-adhoc-*` container names so
    # multiple operators can run parallel labs on the same host without
    # collisions. Mutate module-level constants in-place — the constants
    # are referenced from many helper functions defined above; this keeps
    # the diff small.
    prefix = request.config.getoption('--lxc-prefix') or 'mssh'
    global CA_NAME, ACCT_NAME, SALES_NAME, HR_NAME, ENG_NAME
    global SSH_CONTAINERS, ALL_CONTAINERS, SERVERS
    CA_NAME    = f'{prefix}-adhoc-ca'
    ACCT_NAME  = f'{prefix}-adhoc-acct'
    SALES_NAME = f'{prefix}-adhoc-sales'
    HR_NAME    = f'{prefix}-adhoc-hr'
    ENG_NAME   = f'{prefix}-adhoc-eng'
    SSH_CONTAINERS = [ACCT_NAME, SALES_NAME, HR_NAME, ENG_NAME]
    ALL_CONTAINERS = [CA_NAME] + SSH_CONTAINERS
    SERVERS = [
        _Server(ACCT_NAME,  'srv-acct',  UBUNTU_IMAGE, 'accounting'),
        _Server(SALES_NAME, 'srv-sales', UBUNTU_IMAGE, 'sales'),
        _Server(HR_NAME,    'srv-hr',    UBUNTU_IMAGE, 'hr'),
        _Server(ENG_NAME,   'srv-eng',   ALPINE_IMAGE, 'engineering'),
    ]

    banner(f'msshd adhoc lab — prefix={prefix!r} Phase 0 → ... → {stop_at_phase}')

    # Build the local mssh-ubuntu-fixed / mssh-alpine-fixed images on first
    # run. Subsequent runs reuse the local aliases and skip cloud-init's
    # apt-daily churn. Rebuild with MSSH_REBUILD_FIXED=1 to pick up edits.
    section('Ensuring local fixed base images')
    ensure_fixed_images()

    # ---- 0. Tear down + launch fresh -----------------------------------
    section('Deleting any pre-existing adhoc containers')
    for c in ALL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    section('Launching containers')
    for s in SERVERS:
        lxc('launch', s.image, s.container,
            '--config', 'security.privileged=true', timeout=300)
    lxc('launch', UBUNTU_IMAGE, CA_NAME,
        '--config', 'security.privileged=true', timeout=300)

    # Capture log + state snapshots from every container at teardown,
    # whether the test passes or fails. Setup-only tests leave the lab
    # running, so this is useful in both cases: on failure for postmortem,
    # on success as a baseline for comparing against later interactive runs.
    def _capture_diagnostics() -> None:
        diag_dir = invocation_cwd / 'adhoc-diagnostics'
        pull_diagnostics(ALL_CONTAINERS, diag_dir)
        print(f'\n  Diagnostics snapshot in {diag_dir}/\n',
              file=sys.stderr, flush=True)
    request.addfinalizer(_capture_diagnostics)

    ips = {c: get_ip(c) for c in ALL_CONTAINERS}
    section('Container IPs')
    for c, ip in ips.items():
        print(f'  {c:24s} {ip}', file=sys.stderr, flush=True)

    # ---- 1. Install deps + push source --------------------------------
    app_root = Path(__file__).resolve().parent.parent.parent.parent
    ubuntu_pkgs = ['python3', 'python3-cryptography', 'python3-flask',
                   'python3-yaml', 'python3-click', 'python3-requests',
                   'python3-asyncssh', 'openssh-server', 'openssh-client']
    alpine_pkgs = ['python3', 'py3-cryptography', 'py3-flask', 'py3-yaml',
                   'py3-click', 'py3-requests', 'py3-asyncssh',
                   'openssh', 'openssh-server',
                   'dropbear', 'dropbear-convert', 'dropbear-dbclient']

    section('Installing deps (Ubuntu)')
    for c in [CA_NAME, ACCT_NAME, SALES_NAME, HR_NAME]:
        print(f'  {c}', file=sys.stderr, flush=True)
        wait_for_apt_quiescent(c, max_wait=120)
        lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
        lxc_exec(c, 'apt-get', 'install', '-y', '-q',
                 '--no-install-recommends', *ubuntu_pkgs, timeout=600)
        lxc_exec(c, 'apt-get', 'clean')
        push_source(c, app_root)

    section('Installing deps (Alpine)')
    lxc_exec(ENG_NAME, 'apk', 'add', '--no-cache', *alpine_pkgs, timeout=600)
    push_source(ENG_NAME, app_root)

    # ---- 2. Bootstrap CA (Phase 2 prerequisite; harmless in Phase 0/1) -
    section('Bootstrapping CA')
    lxc_exec(CA_NAME, 'sh', '-c',
             'PYTHONPATH=/app/src python3 -c "'
             'from mssh.ca.cert_minter import bootstrap_ca; '
             f"bootstrap_ca('/etc/mssh/ca', "
             f"tls_server_sans=['DNS:localhost','IP:127.0.0.1',"
             f"'IP:{ips[CA_NAME]}'])\"", timeout=120)
    lxc_exec(CA_NAME, 'sh', '-c',
             'python3 -c "import yaml; '
             "open('/etc/mssh/ca/enrollment.yaml','w').write("
             "yaml.safe_dump({'admins': {'bootstrap-admin': "
             "{'role':'superuser','mtls_subject':'CN=bootstrap-admin',"
             "'enrolled_at':'','enrolled_by':'init'}}}))\"")
    push_text(CA_NAME,
              f'listen: 0.0.0.0:{CA_PORT}\n'
              'signing_key: /etc/mssh/ca/signing-key.pem\n'
              'signing_cert: /etc/mssh/ca/signing-cert.pem\n'
              'tls_cert: /etc/mssh/ca/tls-server-cert.pem\n'
              'tls_key:  /etc/mssh/ca/tls-server-key.pem\n'
              'client_ca_cert: /etc/mssh/ca/tls-ca-cert.pem\n'
              'identity_trust_roots: []\n'
              'enrollment: {path: /etc/mssh/ca/enrollment.yaml}\n'
              'audit: {path: /var/log/mssh/audit.jsonl}\n'
              'defaults: {max_cert_validity_seconds: 3600, '
              'timestamp_drift_seconds: 600}\n'
              'cert_generation: {key_type: ec, '
              'server_cert_validity_days: 30, '
              'admin_cert_validity_days: 30}\n',
              '/etc/mssh/ca-config.yaml')
    push_text(CA_NAME,
              '[Unit]\nDescription=mssh CA\nAfter=network.target\n'
              '[Service]\nWorkingDirectory=/app\nEnvironment="PYTHONPATH=/app/src"\n'
              'ExecStart=/usr/bin/python3 -m mssh.ca.server --config '
              '/etc/mssh/ca-config.yaml\nRestart=on-failure\n'
              '[Install]\nWantedBy=multi-user.target\n',
              '/etc/systemd/system/mssh-ca.service')
    lxc_exec(CA_NAME, 'mkdir', '-p', '/var/log/mssh')
    lxc_exec(CA_NAME, 'systemctl', 'daemon-reload')
    lxc_exec(CA_NAME, 'systemctl', 'start', 'mssh-ca')
    wait_for_port(CA_NAME, CA_PORT, max_wait=60)

    # Pull admin creds + build a CAClient for enrollment.
    for n in ('bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
              'tls-ca-cert.pem', 'signing-cert.pem'):
        subprocess.run(['lxc', 'file', 'pull',
                        f'{CA_NAME}/etc/mssh/ca/{n}',
                        str(ca_creds_dir / n)],
                       check=True, capture_output=True)
    os.chmod(ca_creds_dir / 'bootstrap-admin-key.pem', 0o600)
    from mssh.admin.client import CAClient
    admin = CAClient(
        base_url=f'https://{ips[CA_NAME]}:{CA_PORT}',
        admin_cert=str(ca_creds_dir / 'bootstrap-admin-cert.pem'),
        admin_key=str(ca_creds_dir / 'bootstrap-admin-key.pem'),
        ca_cert=str(ca_creds_dir / 'tls-ca-cert.pem'))

    # ---- ansible scaffolding ----------------------------------------
    # Render the ansible-project skeleton against the live lab + install
    # ansible-core on the CA + set up CA→other-container SSH-as-root
    # access so an operator can `ansible all -m ping` immediately.
    # Lives on the host at ./ansible-project/ and on the CA at
    # /root/ansible-project/. Available at every phase (>=0).
    section('Bootstrapping ansible-project on host + CA')
    ansible_host_dir = invocation_cwd / 'ansible-project'
    _write_ansible_project(ansible_host_dir, ips, prefix)
    _setup_ansible_on_ca(ips, prefix, ansible_host_dir)

    # ---- --phase 0 stopping point -----------------------------------
    # Blank-slate: containers up, CA running, source pushed, admin creds
    # pulled to ca_creds_dir/. From here an operator drives the rest by
    # hand with `mssh-admin status` / `mssh-admin next`.
    if stop_at_phase < 1:
        _finalize_adhoc_artifacts(
            stop_at_phase=0, invocation_cwd=invocation_cwd,
            ips=ips, artifacts_dir=artifacts_dir, keys_generated=False)
        section('SUCCESS — msshd adhoc lab stopped at Phase 0 (blank slate)')
        print(
            f'\n  CA at https://{ips[CA_NAME]}:{CA_PORT}\n'
            f'  admin creds: {ca_creds_dir}/\n'
            f'  /root/README.md on each container has manual-setup notes.\n'
            f'  Try: mssh-admin --ca-url https://{ips[CA_NAME]}:{CA_PORT} '
            f'\\\n         --admin-cert {ca_creds_dir}/bootstrap-admin-cert.pem '
            f'\\\n         --admin-key  {ca_creds_dir}/bootstrap-admin-key.pem '
            f'\\\n         --ca-cert    {ca_creds_dir}/tls-ca-cert.pem '
            f'next\n',
            file=sys.stderr, flush=True)
        return

    # =====================================================================
    # Phase 0 — vanilla sshd + ssh keypairs + authorized_keys
    # =====================================================================
    section('PHASE 0: provisioning vanilla sshd on every server')
    for s in SERVERS:
        _provision_vanilla_sshd(s)
        try:
            wait_for_port(s.container, VANILLA_SSHD_PORT, max_wait=30)
        except Exception:
            print(f'  warning: sshd port {VANILLA_SSHD_PORT} not ready on '
                  f'{s.container} — continuing', file=sys.stderr)

    section('PHASE 0: keygen per user (in their primary container)')
    user_keys: dict[str, dict] = {}
    for u in USERS:
        primary = _primary_container_for(u)
        print(f'  {u.username} on {primary}', file=sys.stderr, flush=True)
        user_keys[u.username] = _keygen_in_container(
            primary, u.username, artifacts_dir)

    section('PHASE 0: distribute authorized_keys to every server')
    for s in SERVERS:
        _push_authorized_keys(s, user_keys)

    # Validate ssh from the CA host (it has openssh-client installed
    # and is the easiest "neutral" launchpad — not the user's primary).
    # We need to push the user's private key to the CA host first.
    section('PHASE 0 validation: ssh user@host:22 works')
    lxc_exec(CA_NAME, 'mkdir', '-p', '/root/.ssh')
    lxc_exec(CA_NAME, 'chmod', '700', '/root/.ssh')
    ca_keydir = '/root/adhoc-keys'
    lxc_exec(CA_NAME, 'mkdir', '-p', ca_keydir)
    for u in USERS:
        push_file(CA_NAME, str(artifacts_dir / u.username),
                  f'{ca_keydir}/{u.username}', mode='600')
    for u in USERS:
        for s in _allowed_servers_for(u):
            _verify_ssh(from_container=CA_NAME,
                        key_path=f'{ca_keydir}/{u.username}',
                        user=u.username, target_ip=ips[s.container],
                        target_port=VANILLA_SSHD_PORT,
                        expected_substr=u.username)
        print(f'  {u.username}: {len(_allowed_servers_for(u))} hosts OK',
              file=sys.stderr, flush=True)

    # ---- --phase 1 stopping point -----------------------------------
    # Vanilla sshd works. msshd not installed yet. The operator can use
    # env.sh's ssh_as helper and walk the "drop msshd in front" step
    # from /root/README.md manually.
    if stop_at_phase < 2:
        _finalize_adhoc_artifacts(
            stop_at_phase=1, invocation_cwd=invocation_cwd,
            ips=ips, artifacts_dir=artifacts_dir, keys_generated=True)
        section('SUCCESS — msshd adhoc lab stopped at Phase 1 (vanilla sshd)')
        print(
            f'\n  source ./adhoc-env.sh    # exports ips, keys, helpers\n'
            f'  ssh_as alice acct whoami # works\n'
            f'  cat ./ADHOC_TEST_ENV.md  # overview\n'
            f'\n  Next manual step: install msshd in fallback mode on a '
            f'server.\n  See /root/README.md inside the container.\n',
            file=sys.stderr, flush=True)
        return

    # =====================================================================
    # Phase 1 — msshd in fallback in front of sshd
    # =====================================================================
    section('PHASE 1: dropping msshd in fallback on every server')
    for s in SERVERS:
        _install_msshd(s.container, mode='fallback')

    section('PHASE 1 validation: ssh -p 2200 still works (proxied)')
    for u in USERS:
        for s in _allowed_servers_for(u):
            _verify_ssh(from_container=CA_NAME,
                        key_path=f'{ca_keydir}/{u.username}',
                        user=u.username, target_ip=ips[s.container],
                        target_port=MSSHD_PORT,
                        expected_substr=u.username)
        print(f'  {u.username}: ok through msshd:2200', file=sys.stderr,
              flush=True)

    # (No early-return between fallback and enforce — the operator can
    # always reach fallback by flipping wrapper.yaml after the lab is up.)

    # =====================================================================
    # Final setup — gen mTLS, enroll, flip msshd to enforce
    # =====================================================================
    section('PHASE 2: generating wrapper user-CA + per-user mTLS certs')
    pki_dir = tmp_path_factory.mktemp('msshd-pki')
    pki = _gen_user_ca_and_mtls_certs(
        pki_dir,
        wrapper_host_sans={s.container: ips[s.container] for s in SERVERS},
        user_principals=[u.username for u in USERS])
    # Wrapper user-CA (signs ephemeral OpenSSH inner certs).
    wrapper_user_ca_dir = tmp_path_factory.mktemp('wrapper-user-ca')
    w_ca_priv, w_ca_pub = _gen_wrapper_user_ca(wrapper_user_ca_dir)

    # Copy mTLS material into the host adhoc-keys/ dir for operator use.
    for u in USERS:
        for ext in ('crt', 'key'):
            shutil.copy(pki_dir / f'{u.username}.{ext}',
                        artifacts_dir / f'{u.username}.{ext}')
        os.chmod(artifacts_dir / f'{u.username}.key', 0o600)
    shutil.copy(pki_dir / 'user-ca.crt', artifacts_dir / 'user-ca.crt')

    section('PHASE 2: enrolling servers at the CA (mTLS creds for wrapper)')
    server_creds = {}
    for s in SERVERS:
        resp = admin.server_add(s.canonical, groups=[s.group])
        server_creds[s.canonical] = resp['credentials']
        (ca_creds_dir / f'{s.canonical}-mtls.crt').write_text(
            resp['credentials']['cert_pem'])
        (ca_creds_dir / f'{s.canonical}-mtls.key').write_text(
            resp['credentials']['key_pem'])
        os.chmod(ca_creds_dir / f'{s.canonical}-mtls.key', 0o600)

    section('PHASE 2: enrolling users + keys + policies at the CA')
    for u in USERS:
        admin.user_add(u.username)
        admin.user_key_add(u.username, 'pubkey',
                           base64.b64encode(
                               pki['clients'][u.username]['ssh_pubkey_blob']
                           ).decode('ascii'))
        admin.policy_add(u.username, {
            'server_groups': list(u.allowed_groups),
            'channels': ['session'],
            'max_cert_validity_seconds': 600,
        })

    section('PHASE 2: pushing wrapper cert material + flipping to enforce')
    for s in SERVERS:
        _push_msshd_cert_material(
            s,
            wrapper_cert=pki['wrapper_certs'][s.container]['cert'],
            wrapper_key=pki['wrapper_certs'][s.container]['key'],
            user_ca_pub=pki['user_ca_path'],
            wrapper_mtls_cert=ca_creds_dir / f'{s.canonical}-mtls.crt',
            wrapper_mtls_key=ca_creds_dir / f'{s.canonical}-mtls.key',
            ca_tls_root=ca_creds_dir / 'tls-ca-cert.pem',
            wrapper_user_ca_priv=w_ca_priv,
            wrapper_user_ca_pub=w_ca_pub)
        _install_msshd(s.container, mode='enforce', ca_ip=ips[CA_NAME])

    # CA host needs sshd + root-admin's authorized_keys so the host's
    # `flip_to_enforce`/`flip_to_fallback` helpers can ssh in.
    section('PHASE 2: enabling sshd on CA + root-admin authorized_keys')
    lxc_exec(CA_NAME, 'systemctl', 'enable', '--now', 'ssh', check=False)
    try:
        wait_for_port(CA_NAME, VANILLA_SSHD_PORT, max_wait=30)
    except Exception:
        print(f'  warning: CA sshd port {VANILLA_SSHD_PORT} not ready',
              file=sys.stderr, flush=True)
    _ensure_unix_account(CA_NAME, SUPERUSER.username)
    push_text(CA_NAME, user_keys[SUPERUSER.username]['pub_line'] + '\n',
              f'/home/{SUPERUSER.username}/.ssh/authorized_keys', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')

    section('PHASE 2: per-user mssh material + /usr/local/bin/mssh wrapper')
    for s in SERVERS:
        if not _is_alpine(s.container):
            _install_mssh_wrapper(s.container)
            for u in USERS:
                if s.group in u.allowed_groups:
                    _push_mssh_per_user(s, u, pki)
    # Also drop the superuser's material onto the CA host (their primary).
    _install_mssh_wrapper(CA_NAME)
    _push_mssh_per_user(SERVERS[0], SUPERUSER, pki)  # ensure account exists
    _ensure_unix_account(CA_NAME, SUPERUSER.username)
    home_mssh = f'/home/{SUPERUSER.username}/.mssh'
    lxc_exec(CA_NAME, 'sh', '-c',
             f'mkdir -p {home_mssh} && chmod 700 {home_mssh} && '
             f'chown -R {SUPERUSER.username}:{SUPERUSER.username} {home_mssh}')
    push_file(CA_NAME, pki['clients'][SUPERUSER.username]['cert'],
              f'{home_mssh}/cert.pem', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')
    push_file(CA_NAME, pki['clients'][SUPERUSER.username]['key'],
              f'{home_mssh}/key.pem', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')
    push_file(CA_NAME, pki['user_ca_path'],
              f'{home_mssh}/ca.pem', mode='644',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')

    section('PHASE 2 validation: mssh user@host:2200 works')
    # Use the CA host as the "from" since it has Python deps + source.
    for u in USERS:
        for s in _allowed_servers_for(u):
            # Run mssh from the CA host using the user's mTLS material
            # pushed to that user's /home/<u>/.mssh on the CA host …
            # but only the superuser lives on CA_NAME. For others we
            # invoke mssh directly via env vars + host PKI material.
            cmd = (
                f'MSSH_CERT={pki_dir}/{u.username}.crt '
                f'MSSH_KEY={pki_dir}/{u.username}.key '
                f'MSSH_CA={pki_dir}/user-ca.crt '
                f'PYTHONPATH={app_root}/python/src '
                f'python3 -m mssh.client '
                f'{u.username}@{ips[s.container]}:{MSSHD_PORT} -- whoami'
            )
            r = subprocess.run(['sh', '-c', cmd], capture_output=True,
                               text=True, timeout=30)
            assert r.returncode == 0, (
                f'mssh {u.username}@{s.canonical} failed: rc={r.returncode} '
                f'stdout={r.stdout!r} stderr={r.stderr!r}')
            assert u.username in r.stdout, (
                f'mssh {u.username}@{s.canonical}: expected username in '
                f'stdout, got {r.stdout!r}')
        print(f'  {u.username}: mssh OK on {len(_allowed_servers_for(u))} '
              f'host(s)', file=sys.stderr, flush=True)

    # =====================================================================
    # adhoc artifacts
    # =====================================================================
    section('Writing adhoc artifacts (cleanup, env, README)')
    _finalize_adhoc_artifacts(
        stop_at_phase=2, invocation_cwd=invocation_cwd,
        ips=ips, artifacts_dir=artifacts_dir, keys_generated=True)

    section('Pushing operator-grade flip scripts to /home/root-admin/ on CA')
    _push_flip_scripts_to_ca(ips, ips[CA_NAME])

    section('SUCCESS — msshd adhoc lab is up at Phase 2 (enforce)')
    print(
        f'\n  source ./adhoc-env.sh    # exports ips, ports, key paths\n'
        f'  cat ./ADHOC_TEST_ENV.md  # full overview + examples\n'
        f'\n  # Flip scripts live ON the CA container — operator workflow.\n'
        f'  # Drive them via lxc exec (no setup required) or by ssh-ing\n'
        f'  # to the CA first if you want the realistic experience.\n'
        f'\n  lxc exec {CA_NAME} -- su - root-admin -c ./flip-to-fallback.sh\n'
        f'  lxc exec {CA_NAME} -- su - root-admin -c ./flip-to-enforce.sh\n'
        f'\n  ./cleanup_containers.sh  # tear it all down\n',
        file=sys.stderr, flush=True)
