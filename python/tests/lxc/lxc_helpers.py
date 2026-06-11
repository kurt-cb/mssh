"""LXC container helpers for mssh integration tests.

Topology (4 SSH machines + 1 CA, modeled on the user-confirmed plan):

  CA_HOST       Ubuntu 22.04 — Flask CA + mssh-admin
  SSHRT_U1      Ubuntu 22.04 — sshd + Python shim
  SSHRT_U2      Ubuntu 22.04 — sshd + Python shim
  SSHRT_U3      Ubuntu 22.04 — sshd + Python shim
  SSHRT_ALPINE  Alpine 3     — sshd + Python shim   (cross-distro coverage)

All SSH hosts have Unix accounts for the full user matrix so the auth result
is governed by mssh's policy, not by a missing-account error. The user
matrix is built by ``tests/lxc/randomized.py`` from a deterministic seed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


# Container names.
CA_HOST       = 'mssh-lxc-ca'
SSHRT_U1      = 'mssh-lxc-u1'
SSHRT_U2      = 'mssh-lxc-u2'
SSHRT_U3      = 'mssh-lxc-u3'
SSHRT_ALPINE  = 'mssh-lxc-alpine'

ALL_SSH_HOSTS = [SSHRT_U1, SSHRT_U2, SSHRT_U3, SSHRT_ALPINE]
ALL_CONTAINERS = [CA_HOST] + ALL_SSH_HOSTS


# ---------------------------------------------------------------------------
# Container CLI binary auto-detection (incus vs lxc)
# ---------------------------------------------------------------------------
#
# Both incus and LXD ship a CLI with the same surface (`init`, `launch`,
# `exec`, `file push`, `delete`, `publish`, `image info`, ...). LXD's
# public version is EOL; new installs are increasingly incus. On some
# hosts `lxc` is aliased to `incus`; on others both are present;
# on others only one is.
#
# `_resolve_cli_bin()` picks whichever binary `which` finds first:
#   1. `incus` (preferred — LXD public is EOL).
#   2. `lxc` (works as either the LXD CLI or an incus alias).
# If neither is in $PATH the test will fail at first invocation with a
# clean FileNotFoundError.
import shutil as _shutil


def _resolve_cli_bin() -> str:
    """Return the container-CLI binary name to invoke."""
    if _shutil.which('incus'):
        return 'incus'
    if _shutil.which('lxc'):
        return 'lxc'
    # Fall back to 'lxc' so subprocess.run produces a clean
    # FileNotFoundError downstream rather than crashing module import.
    return 'lxc'


CLI_BIN: str = _resolve_cli_bin()


# Upstream image sources used by ensure_fixed_images() to build the local
# `mssh-*-fixed` aliases. The Ubuntu jammy image runs cloud-init +
# apt-daily.timer + unattended-upgrades on first boot and is the reason a
# fresh container can fail wait_for_apt_quiescent. The local fixed image is
# prebaked with those services disabled.
#
# Image-path note (2026-05-22): the upstream image references differ
# between LXD and incus deployments:
#   - LXD ships an `ubuntu:` remote pointing at
#     cloud-images.ubuntu.com; `ubuntu:22.04` resolves there.
#   - Incus does NOT configure `ubuntu:` by default, but both LXD and
#     incus ship the `images:` remote (images.linuxcontainers.org)
#     where the same image lives at `images:ubuntu/22.04`.
# `_resolve_upstream_image()` probes each candidate via `lxc image info`
# and caches the first one that works, so test code stays portable
# without depending on which container backend the host has.
_UBUNTU_CANDIDATES = ('images:ubuntu/22.04', 'ubuntu:22.04')
_ALPINE_CANDIDATES = ('images:alpine/3.21',)


def _resolve_upstream_image(candidates: tuple[str, ...]) -> str:
    """Probe candidate image paths and return the first that resolves.

    Falls back to the first candidate if none probe positive (callers
    will get a clean error from `lxc launch` rather than a stale-
    candidate cache).
    """
    for cand in candidates:
        r = subprocess.run([CLI_BIN, 'image', 'info', cand],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return cand
    return candidates[0]


_UBUNTU_IMAGE_UPSTREAM_CACHED: str | None = None
_ALPINE_IMAGE_UPSTREAM_CACHED: str | None = None


def _ubuntu_upstream() -> str:
    global _UBUNTU_IMAGE_UPSTREAM_CACHED
    if _UBUNTU_IMAGE_UPSTREAM_CACHED is None:
        _UBUNTU_IMAGE_UPSTREAM_CACHED = _resolve_upstream_image(_UBUNTU_CANDIDATES)
    return _UBUNTU_IMAGE_UPSTREAM_CACHED


def _alpine_upstream() -> str:
    global _ALPINE_IMAGE_UPSTREAM_CACHED
    if _ALPINE_IMAGE_UPSTREAM_CACHED is None:
        _ALPINE_IMAGE_UPSTREAM_CACHED = _resolve_upstream_image(_ALPINE_CANDIDATES)
    return _ALPINE_IMAGE_UPSTREAM_CACHED


# Backward-compat string constants. Eagerly resolved at import time so
# old callers that pulled the value at module load still see the right
# string. If neither `lxc` nor `incus` is installed the resolution is a
# no-op and the constants hold the first candidate (which will fail at
# `lxc launch` time with a clear error).
def _safe_resolve(cands: tuple[str, ...]) -> str:
    try:
        return _resolve_upstream_image(cands)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return cands[0]


UBUNTU_IMAGE_UPSTREAM = _safe_resolve(_UBUNTU_CANDIDATES)
ALPINE_IMAGE_UPSTREAM = _safe_resolve(_ALPINE_CANDIDATES)

# Local image aliases the tests reference. Built once by ensure_fixed_images()
# and reused across runs. Rebuild with MSSH_REBUILD_FIXED=1 in the env.
UBUNTU_FIXED_ALIAS = 'mssh-ubuntu-fixed'
ALPINE_FIXED_ALIAS = 'mssh-alpine-fixed'

UBUNTU_IMAGE = UBUNTU_FIXED_ALIAS
ALPINE_IMAGE = ALPINE_FIXED_ALIAS

CA_PORT = 8443


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def lxc(*args: str, timeout: int = 180,
        check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [CLI_BIN, *args], check=check, capture_output=True,
        text=True, timeout=timeout,
    )


def lxc_exec(container: str, *cmd: str, check: bool = True,
             timeout: int = 120,
             input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [CLI_BIN, 'exec', container, '--', *cmd],
        check=check, capture_output=True, text=True,
        timeout=timeout, input=input_text,
    )


def push_text(container: str, content: str, remote_path: str,
              mode: str | None = None, owner: str | None = None) -> None:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
        f.write(content)
        local = f.name
    try:
        # --create-dirs: incus on a stopped container fails the push
        # when the parent dir doesn't exist (different from LXD's
        # default behavior). The flag is a no-op when the dir does
        # exist, so it's safe to always pass.
        subprocess.run([CLI_BIN, 'file', 'push', '--create-dirs', local,
                        f'{container}{remote_path}'],
                       check=True, capture_output=True)
    finally:
        os.unlink(local)
    if mode:
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def push_file(container: str, local_path: str | Path, remote_path: str,
              mode: str | None = None, owner: str | None = None) -> None:
    subprocess.run([CLI_BIN, 'file', 'push', '--create-dirs',
                    str(local_path),
                    f'{container}{remote_path}'],
                   check=True, capture_output=True)
    if mode:
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def pull_file(container: str, remote_path: str,
              local_path: str | Path) -> None:
    subprocess.run([CLI_BIN, 'file', 'pull',
                    f'{container}{remote_path}', str(local_path)],
                   check=True, capture_output=True)


def get_ip(container: str, max_wait: int = 120) -> str:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = subprocess.run([CLI_BIN, 'list', container, '--format', 'json'],
                           capture_output=True, text=True)
        data = json.loads(r.stdout or '[]')
        if data:
            net = (data[0].get('state') or {}).get('network') or {}
            for iface in net.values():
                for addr in iface.get('addresses') or []:
                    if (addr.get('family') == 'inet'
                            and not addr['address'].startswith('127.')):
                        return addr['address']
        time.sleep(2)
    raise RuntimeError(f'{container}: no IPv4 within {max_wait}s')


def wait_for_apt_quiescent(container: str, max_wait: int = 120) -> None:
    """Disable Ubuntu's background apt automation so our installs are
    deterministic, then wait for any in-flight apt-daily or
    unattended-upgrades to finish (so we can take the dpkg lock cleanly).

    Fresh Ubuntu cloud containers run `apt-daily.timer`,
    `apt-daily-upgrade.timer`, `unattended-upgrades`, `apport`, and
    `ubuntu-report` on first boot. Racing them produces exit 100
    ('Could not get lock /var/lib/dpkg/lock-frontend').

    Containers launched from ``mssh-ubuntu-fixed`` (the prebaked alias
    built by ensure_fixed_images()) already have these services masked,
    so this function returns near-instantly. The disable-and-wait logic
    below remains as a safety net for callers that target the upstream
    image directly.

    Idempotent: re-running on a prepared container is harmless.
    """
    # 1. Disable the timers so they won't kick off NEW apt jobs after we
    #    finish waiting. Best-effort: ignore failures from services that
    #    don't exist on minimal images.
    lxc_exec(container, 'sh', '-c', """
        systemctl stop  apt-daily.timer         apt-daily-upgrade.timer \
                       apport.service           2>/dev/null || true
        systemctl disable apt-daily.timer       apt-daily-upgrade.timer \
                       apport.service           2>/dev/null || true
        systemctl mask apt-daily.service        apt-daily-upgrade.service \
                       2>/dev/null || true
        ubuntu-report -f send no                2>/dev/null || true
    """, check=False, timeout=30)

    # 2. Wait for any in-flight apt/dpkg job to finish so we get the lock.
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
            container, 'sh', '-c',
            'pgrep -fa "apt-get|unattended-upgr|dpkg|aptd" 2>/dev/null '
            '| grep -v pgrep || echo CLEAR',
            check=False,
        )
        if 'CLEAR' in (r.stdout or ''):
            break
        time.sleep(2)
    else:
        raise RuntimeError(
            f'{container}: apt did not become quiescent in {max_wait}s')

    # 3. Purge unattended-upgrades so it can't be re-triggered. Done
    #    AFTER the wait, when we know we hold the lock.
    lxc_exec(container, 'sh', '-c',
             'DEBIAN_FRONTEND=noninteractive apt-get purge -y -q '
             'unattended-upgrades 2>/dev/null || true',
             check=False, timeout=60)


def wait_for_port(container: str, port: int, max_wait: int = 60) -> None:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
            container, 'python3', '-c',
            f'import socket; s=socket.socket(); s.settimeout(2); '
            f's.connect(("127.0.0.1",{port})); s.close(); print("ok")',
            check=False,
        )
        if 'ok' in r.stdout:
            return
        time.sleep(2)
    raise RuntimeError(f'{container}: port {port} not ready')


def install_wheels(container: str, app_root: Path) -> None:
    """Build wheels via `make pkg` (if not already built), push to the
    container, and ``pip install`` them.

    Replaces the old push_source() approach where we mounted the
    repo source tree at /app/src and ran via PYTHONPATH. That bypassed
    the install path users actually hit (apt / pip install) and made
    install-time issues invisible. See design/notes-installer-and-versioning.md.

    Installs ALL 5 mssh wheels on every container — the lab doesn't
    optimize for "minimum install per role" today. Production deployments
    would split: client-only on workstations, msshd on servers, mssh-ca
    + mssh-admin on the CA host.

    Language-neutral configs (config/, scripts/, systemd/) are still
    pushed under /app/ since they're not part of any wheel.
    """
    dist_dir = app_root / 'dist'
    wheels = sorted(dist_dir.glob('*.whl')) if dist_dir.exists() else []
    if not wheels:
        # Build them now. Idempotent — Make rebuilds only what changed.
        subprocess.run(['make', '-C', str(app_root), 'pkg',
                        f'PYTHON={sys.executable}'],
                       check=True)
        wheels = sorted(dist_dir.glob('*.whl'))
    if not wheels:
        raise RuntimeError(f'no wheels in {dist_dir} after `make pkg`')

    # Push the wheels to /tmp/mssh-wheels/ on the container.
    lxc_exec(container, 'mkdir', '-p', '/tmp/mssh-wheels')
    for w in wheels:
        push_file(container, str(w), f'/tmp/mssh-wheels/{w.name}')

    # Install via pip. Use file paths (not names) so we never hit the
    # PyPI namespace collision with the unrelated 'mssh' package there.
    # --force-reinstall lets `make redeploy` overwrite a prior install.
    #
    # PEP 668 (EXTERNALLY-MANAGED marker) gates system-wide pip on
    # newer distros (Ubuntu 24.04+, Alpine 3.19+). Older pip (Ubuntu
    # 22.04) doesn't know --break-system-packages so we conditionally
    # pass it only when the marker is present.
    has_marker = lxc_exec(
        container, 'sh', '-c',
        'find /usr/lib -name EXTERNALLY-MANAGED 2>/dev/null | head -1',
        check=False).stdout.strip()
    pip_flags = ['--quiet', '--force-reinstall', '--no-deps']
    if has_marker:
        pip_flags.append('--break-system-packages')
    install_cmd = ['pip', 'install', *pip_flags]
    install_cmd += [f'/tmp/mssh-wheels/{w.name}' for w in wheels]
    lxc_exec(container, *install_cmd, timeout=120)
    # External deps separately (pip will skip already-satisfied ones).
    dep_flags = ['--quiet']
    if has_marker:
        dep_flags.append('--break-system-packages')
    lxc_exec(container, 'pip', 'install', *dep_flags,
             'asyncssh>=2.14', 'cryptography>=41.0', 'flask>=3.0',
             'pyyaml>=6.0', 'click>=8.0', 'requests>=2.31',
             timeout=300)

    # Push language-neutral configs/scripts that live at the repo root.
    # These aren't part of any wheel — sshd_config.template etc.
    for top in ('config', 'scripts', 'systemd'):
        top_path = app_root / top
        if not top_path.exists():
            continue
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f2:
            extra_tar = f2.name
        subprocess.run(
            ['tar', '-C', str(app_root), '-czf', extra_tar, top],
            check=True, capture_output=True,
        )
        try:
            lxc_exec(container, 'mkdir', '-p', '/app')
            push_file(container, extra_tar, f'/tmp/{top}.tar.gz')
            lxc_exec(container, 'tar', '-xzf',
                     f'/tmp/{top}.tar.gz', '-C', '/app')
        finally:
            os.unlink(extra_tar)

    # msshd searches /etc/mssh/sshd_config.template as its first
    # candidate. With wheels installed system-wide, __file__-relative
    # search doesn't find /app/config/, so we mirror the template into
    # /etc/mssh/ explicitly. Same place a future apt/.deb package would
    # land it.
    template_src = app_root / 'config' / 'sshd_config.template'
    if template_src.exists():
        lxc_exec(container, 'mkdir', '-p', '/etc/mssh')
        push_file(container, str(template_src),
                  '/etc/mssh/sshd_config.template', mode='644')


# Backwards-compatible alias — kept so any caller still using the old
# name keeps working. New code should use install_wheels.
def push_source(container: str, app_root: Path) -> None:
    install_wheels(container, app_root)


def lxc_available() -> bool:
    try:
        r = subprocess.run([CLI_BIN, 'version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Preflight: catch developer-environment gotchas BEFORE the session-scoped
# fixture spends 4 minutes provisioning containers only to fail.
# ---------------------------------------------------------------------------
#
# These checks address the "lxc/incus is installed but the host is
# configured in a way that breaks container DHCP / networking" class of
# problems. Examples:
#
#   - On Fedora/RHEL: firewalld's default zone has `lxdbr0` outside its
#     known-interfaces list, so the trailing `reject with icmpx
#     admin-prohibited` blocks UDP/67 DHCP DISCOVER from the container
#     to the host's dnsmasq. Containers boot with IPv6 only, no IPv4,
#     and `get_ip()` times out 4 minutes into the fixture.
#   - The `lxc` binary is present but unconfigured (no `incus admin init`
#     / `lxd init` run), so launches fail with "no storage pool".
#
# None of these are mssh runtime concerns — they only affect developers
# running the integration suite. So the preflight surfaces a clear
# remediation message and skips the lxc-marked tests cleanly, rather
# than burning fixture time on a doomed run.


@dataclass
class _PreflightIssue:
    """One LXC-setup issue surfaced by `lxc_preflight()`."""
    title: str
    detail: str
    remediation: str

    def render(self) -> str:
        return (f'  • {self.title}\n'
                f'    Why: {self.detail}\n'
                f'    Fix: {self.remediation}\n')


def _preflight_cli_binary() -> _PreflightIssue | None:
    if _shutil.which(CLI_BIN) is None:
        return _PreflightIssue(
            title=f'{CLI_BIN!r} not found in PATH',
            detail='LXC tests need either the `incus` or `lxc` CLI '
                   '(incus preferred; LXD public is EOL).',
            remediation='Fedora:  sudo dnf install incus      and    '
                        'sudo systemctl enable --now incus\n'
                        '    Debian:  sudo apt install incus\n'
                        '    Or set MSSH_CONTAINER_CLI=<bin> to override.')
    return None


def _preflight_cli_init() -> _PreflightIssue | None:
    """`incus admin init` (or `lxd init`) populated a storage pool +
    default profile + lxdbr0 bridge. Without it, `lxc launch` fails."""
    try:
        r = subprocess.run([CLI_BIN, 'network', 'show', 'lxdbr0'],
                           capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None                  # _preflight_cli_binary covers this
    if r.returncode != 0:
        return _PreflightIssue(
            title='Default bridge `lxdbr0` is not present',
            detail=f'{CLI_BIN} network show lxdbr0 → exit {r.returncode}.',
            remediation=f'Run:  sudo {CLI_BIN} admin init      '
                        f'(accept defaults).')
    return None


def _preflight_dhcp_on_bridge(probe_timeout: int = 20) -> _PreflightIssue | None:
    """Launch a throwaway container and confirm it gets an IPv4 address
    within `probe_timeout` seconds. Catches the firewalld-on-Fedora
    case where UDP/67 DHCP is blocked on lxdbr0.

    Returns None on success; otherwise a clear remediation message.
    """
    probe = 'mssh-preflight-dhcp'
    # Best-effort cleanup of any stale probe container.
    subprocess.run([CLI_BIN, 'delete', '--force', probe],
                   capture_output=True)
    try:
        r = subprocess.run(
            [CLI_BIN, 'launch', UBUNTU_IMAGE_UPSTREAM, probe,
             '--config', 'security.privileged=true'],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return _PreflightIssue(
                title=f'{CLI_BIN} launch failed during preflight',
                detail=r.stderr.strip() or r.stdout.strip(),
                remediation='Verify storage pool / profile config: '
                            f'`{CLI_BIN} profile show default`.')
        # Poll for an IPv4 address.
        import time as _time
        deadline = _time.time() + probe_timeout
        last_state = ''
        while _time.time() < deadline:
            j = subprocess.run(
                [CLI_BIN, 'list', probe, '--format', 'json'],
                capture_output=True, text=True, timeout=10)
            if j.returncode == 0:
                try:
                    info = json.loads(j.stdout)
                    if info and info[0].get('state'):
                        net = info[0]['state'].get('network') or {}
                        for _ifname, nif in net.items():
                            for addr in nif.get('addresses') or []:
                                if (addr.get('family') == 'inet'
                                        and addr.get('scope') == 'global'):
                                    return None  # ✓ DHCP works
                        last_state = (info[0]['state'].get('status') or '')
                except (ValueError, KeyError):
                    pass
            _time.sleep(1)
        # Timed out without an IPv4 — likely firewalld on Fedora.
        is_fedora = Path('/etc/fedora-release').exists()
        if is_fedora:
            fix = ('Fedora / firewalld is blocking UDP/67 (DHCP DISCOVER) '
                   'on lxdbr0:\n'
                   '      sudo firewall-cmd --zone=trusted '
                   '--change-interface=lxdbr0 --permanent\n'
                   '      sudo firewall-cmd --reload\n'
                   '    Or, more narrowly, allow DHCP on the bridge:\n'
                   "      sudo firewall-cmd --permanent --zone=public "
                   "--add-rich-rule='rule family=\"ipv4\" source "
                   "address=\"10.31.237.0/24\" port port=\"67\" "
                   "protocol=\"udp\" accept'")
        else:
            fix = ('Check your firewall / nftables config — DHCP '
                   '(UDP/67) traffic to the host on lxdbr0 must reach '
                   'the bridge\'s dnsmasq.')
        return _PreflightIssue(
            title=f'Probe container booted but never got an IPv4 '
                  f'(waited {probe_timeout}s, last_state={last_state!r})',
            detail='IPv6 SLAAC typically works (multicast, not routed). '
                   'IPv4 needs DHCP DISCOVER → dnsmasq on the host. The '
                   'host firewall is the usual culprit.',
            remediation=fix)
    finally:
        subprocess.run([CLI_BIN, 'delete', '--force', probe],
                       capture_output=True)


def lxc_preflight(skip_dhcp_probe: bool = False) -> list[_PreflightIssue]:
    """Return a list of LXC-setup issues that would break the test
    fixture. Empty list = environment looks healthy. Each issue carries
    a clear remediation string.

    `skip_dhcp_probe`: set True to skip the (~20s) container launch
    used to test DHCP. Useful when the caller already knows DHCP works
    or doesn't want to spend the time.
    """
    issues: list[_PreflightIssue] = []
    if (bin_issue := _preflight_cli_binary()):
        issues.append(bin_issue)
        return issues                # everything else depends on the CLI
    if (init_issue := _preflight_cli_init()):
        issues.append(init_issue)
        # don't return — DHCP probe may also have something to say
    if not skip_dhcp_probe and not issues:
        if (dhcp_issue := _preflight_dhcp_on_bridge()):
            issues.append(dhcp_issue)
    return issues


def render_preflight_banner(issues: list[_PreflightIssue]) -> str:
    """Format preflight issues as a single banner string for skip
    messages / fixture errors.
    """
    if not issues:
        return ''
    lines = [
        '',
        '─' * 70,
        f'  LXC test preflight detected {len(issues)} issue(s):',
        '',
    ]
    for issue in issues:
        lines.append(issue.render())
    lines.append('─' * 70)
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Fixed base images: prebake Ubuntu + Alpine into local aliases
# ---------------------------------------------------------------------------
#
# The Ubuntu jammy cloud image runs cloud-init on first boot, which in
# turn fires apt-get update, writes netplan config, sets up the default
# `ubuntu` user, and triggers unattended-upgrades. None of that is
# load-bearing for these test containers — LXD/incus provides networking,
# we never log in as `ubuntu`, and we run our own apt-get. But
# cloud-init's first-boot apt activity is what races wait_for_apt_quiescent.
#
# The fix: `lxc init` (not `launch`) so the container exists but isn't
# started, push `/etc/cloud/cloud-init.disabled` into the rootfs along
# with a minimal netplan config, then `lxc start`. cloud-init sees the
# disable marker and exits immediately; no first-boot apt-get happens.
# We then mask apt-daily / unattended-upgrades / apport / motd-news to
# defang the periodic timers, pre-warm the apt cache, and publish.
# Subsequent test containers launched from the alias are quiescent from
# boot.
#
# Alpine is staged the same way (`mssh-alpine-fixed`) even though it has
# no cloud-init or apt-daily equivalent — the local alias gives operators
# a stable starting point they can edit (add test tools, patch configs)
# and republish without changing test code.


def _image_exists(alias: str) -> bool:
    """Return True if a local image with the given alias is present."""
    r = subprocess.run([CLI_BIN, 'image', 'info', alias],
                       capture_output=True, text=True)
    return r.returncode == 0


def _build_ubuntu_fixed() -> None:
    """Prebake `mssh-ubuntu-fixed` from `images:ubuntu/22.04` (LXD/incus portable).

    Disables cloud-init *in the rootfs before first start* so first-boot
    apt-get activity never happens. Then masks the remaining periodic
    services (apt-daily, unattended-upgrades, apport) for good measure.
    ~1 minute one-time cost — the cloud-init wait is gone.
    """
    tmp = 'mssh-prebake-ubuntu'
    subprocess.run([CLI_BIN, 'delete', '--force', tmp], capture_output=True)

    # `lxc init` creates the container without starting it. We modify the
    # rootfs before any service can run, so cloud-init never fires its
    # first-boot apt-get + netplan write. Avoids the race that motivated
    # wait_for_apt_quiescent in the first place.
    print(f'  initializing {UBUNTU_IMAGE_UPSTREAM} as {tmp}',
          file=sys.stderr, flush=True)
    lxc('init', UBUNTU_IMAGE_UPSTREAM, tmp,
        '--config', 'security.privileged=true', timeout=300)

    try:
        # cloud-init does nothing load-bearing on these test containers:
        # LXD provides the network interface; we don't pass user-data; the
        # default `ubuntu` user is never used; and we run our own apt-get
        # update in the prebake. The empty `/etc/cloud/cloud-init.disabled`
        # marker is cloud-init's official "skip every stage" signal.
        # https://cloudinit.readthedocs.io/en/latest/howto/disable_cloud_init.html
        print('  disabling cloud-init in the rootfs',
              file=sys.stderr, flush=True)
        push_text(tmp, '', '/etc/cloud/cloud-init.disabled')

        # With cloud-init off, nothing writes /etc/netplan/50-cloud-init.yaml,
        # so we drop in a minimal netplan ourselves so eth0 still gets a
        # DHCP lease from the LXD bridge on first boot.
        push_text(tmp,
                  'network:\n'
                  '  version: 2\n'
                  '  ethernets:\n'
                  '    eth0:\n'
                  '      dhcp4: true\n',
                  '/etc/netplan/01-mssh-prebake.yaml')

        print('  starting container', file=sys.stderr, flush=True)
        lxc('start', tmp, timeout=120)
        # Networking only — no cloud-init to wait on.
        get_ip(tmp)

        print('  waiting for systemd to settle before purge',
              file=sys.stderr, flush=True)
        # Block until systemd has finished bringing the system up.
        # Without this wait, snapd may still be mid-startup when we
        # try to stop/purge it — the apt-get purge then silently
        # appears to succeed but leaves snapd installed (snapd's
        # postrm bails because the daemon is still active). Empirical
        # finding from a prior prebake that left snapd intact in the
        # published image despite running the purge commands.
        lxc_exec(tmp, 'sh', '-c',
                 'systemctl is-system-running --wait || true',
                 check=False, timeout=120)

        print('  masking apt-daily / unattended-upgrades / apport / motd-news, '
              'purging snapd',
              file=sys.stderr, flush=True)
        lxc_exec(tmp, 'sh', '-c', r"""
            set +e
            systemctl stop  apt-daily.timer apt-daily-upgrade.timer \
                           apt-daily.service apt-daily-upgrade.service \
                           unattended-upgrades.service apport.service \
                           motd-news.timer motd-news.service
            systemctl mask apt-daily.timer apt-daily-upgrade.timer \
                           apt-daily.service apt-daily-upgrade.service \
                           unattended-upgrades.service \
                           apport.service \
                           motd-news.timer motd-news.service

            # ---- snapd removal ----------------------------------------
            # snapd inside an LXC container is pure overhead: the test
            # containers never run snap packages, but the daemon still
            # mounts squashfs images (lxcfs / snap-confine), kicks off
            # periodic refresh.timer / autoimport.service work, and
            # spawns helper processes that eat CPU + memory on
            # already-resource-pressured hosts. Stop + mask + purge it
            # at prebake time so the published image is snapd-free.
            #
            # Stop FIRST so the package's postrm scripts see the
            # daemon as down; otherwise apt-get purge may leave snapd
            # half-installed.
            systemctl stop  snapd.service snapd.socket snapd.seeded.service \
                           snapd.system-shutdown.service snapd.apparmor.service
            systemctl mask snapd.service snapd.socket snapd.seeded.service \
                           snapd.system-shutdown.service snapd.apparmor.service \
                           snapd.failure.service snapd.mounts.target \
                           snapd.mounts-pre.target snapd.recovery-chooser-trigger.service
            # Purge the package + the seed/cache directories. apt-mark
            # hold prevents accidental reinstall on a future apt-get
            # dist-upgrade (Ubuntu's metapackages occasionally pull
            # snapd back in as a recommended dep).
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -q snapd
            apt-mark hold snapd
            rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd \
                   /root/snap /home/*/snap

            # Pin to keep apt from offering it back if a future
            # release recommends it.
            mkdir -p /etc/apt/preferences.d
            cat > /etc/apt/preferences.d/no-snap <<'PREF'
Package: snapd
Pin: release a=*
Pin-Priority: -10
PREF

            DEBIAN_FRONTEND=noninteractive apt-get purge -y -q \
                           unattended-upgrades apport
            # Pre-warm the apt cache so per-test package installs don't fetch.
            DEBIAN_FRONTEND=noninteractive apt-get update -q
            # Enable verbose sshd logging so /var/log/auth.log captures
            # enough detail to diagnose authentication failures during the
            # test phases.
            if [ -f /etc/ssh/sshd_config ]; then
                sed -i 's/^#*LogLevel .*/LogLevel VERBOSE/' /etc/ssh/sshd_config
            fi
            # Verify snapd is gone; fail loudly if not (the publish
            # would otherwise bake a snapd-still-installed image).
            if dpkg -l snapd 2>/dev/null | grep -q '^ii'; then
                echo "FATAL: snapd still installed after purge" >&2
                exit 1
            fi
            exit 0
        """, check=True, timeout=600)

        print('  stopping container', file=sys.stderr, flush=True)
        lxc('stop', tmp, timeout=120)
        print(f'  publishing as {UBUNTU_FIXED_ALIAS}',
              file=sys.stderr, flush=True)
        # Publish can take several minutes on a memory-pressured host —
        # the working image is ~1.2 GB before compression, and ZFS-on-
        # loop-on-ext4 slows the pack. 20-minute ceiling is generous.
        lxc('publish', tmp, '--alias', UBUNTU_FIXED_ALIAS, timeout=1200)
    finally:
        subprocess.run([CLI_BIN, 'delete', '--force', tmp], capture_output=True)


def _build_alpine_fixed() -> None:
    """Prebake `mssh-alpine-fixed` from the upstream Alpine image.

    Alpine has no apt-daily equivalent; the prebake just refreshes the apk
    cache and provides a local alias the operator can edit-and-republish to
    bake in test tools.
    """
    tmp = 'mssh-prebake-alpine'
    subprocess.run([CLI_BIN, 'delete', '--force', tmp], capture_output=True)

    print(f'  launching {ALPINE_IMAGE_UPSTREAM} as {tmp}',
          file=sys.stderr, flush=True)
    lxc('launch', ALPINE_IMAGE_UPSTREAM, tmp,
        '--config', 'security.privileged=true', timeout=300)

    try:
        get_ip(tmp)
        print('  refreshing apk cache', file=sys.stderr, flush=True)
        lxc_exec(tmp, 'apk', 'update', check=False, timeout=120)
        # Enable verbose sshd logging if openssh is present; harmless if not.
        lxc_exec(tmp, 'sh', '-c',
                 "if [ -f /etc/ssh/sshd_config ]; then "
                 "sed -i 's/^#*LogLevel .*/LogLevel VERBOSE/' "
                 "/etc/ssh/sshd_config; fi",
                 check=False, timeout=30)

        print('  stopping container', file=sys.stderr, flush=True)
        lxc('stop', tmp, timeout=120)
        print(f'  publishing as {ALPINE_FIXED_ALIAS}',
              file=sys.stderr, flush=True)
        lxc('publish', tmp, '--alias', ALPINE_FIXED_ALIAS, timeout=600)
    finally:
        subprocess.run([CLI_BIN, 'delete', '--force', tmp], capture_output=True)


def ensure_fixed_images(rebuild: bool = False) -> None:
    """Build local `mssh-ubuntu-fixed` and `mssh-alpine-fixed` if missing.

    Idempotent: subsequent calls are near-zero cost once both aliases exist.
    Pass ``rebuild=True`` (or set ``MSSH_REBUILD_FIXED=1`` in the env) to
    delete and rebuild both — useful after editing the prebake recipe or
    after manually patching either local image and wanting to start clean.
    """
    if rebuild or os.environ.get('MSSH_REBUILD_FIXED') == '1':
        for alias in (UBUNTU_FIXED_ALIAS, ALPINE_FIXED_ALIAS):
            subprocess.run([CLI_BIN, 'image', 'delete', alias],
                           capture_output=True)

    if not _image_exists(UBUNTU_FIXED_ALIAS):
        print(f'Building {UBUNTU_FIXED_ALIAS} (one-time prebake, ~2 min)',
              file=sys.stderr, flush=True)
        _build_ubuntu_fixed()
    if not _image_exists(ALPINE_FIXED_ALIAS):
        print(f'Building {ALPINE_FIXED_ALIAS} (one-time prebake, ~1 min)',
              file=sys.stderr, flush=True)
        _build_alpine_fixed()


# ---------------------------------------------------------------------------
# pull_diagnostics: snapshot useful log files out of each container
# ---------------------------------------------------------------------------


DIAGNOSTICS_DIR_DEFAULT = 'adhoc-diagnostics'

# Log files we try to pull from every container. Missing files are skipped
# silently — Ubuntu containers have auth.log/syslog, Alpine has messages,
# only some containers have mssh-debug-sshd.log or snoopy.log.
_DIAGNOSTIC_LOG_PATHS = [
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/log/messages',
    '/var/log/mssh-server.log',
    '/var/log/mssh/msshd.log',
    '/root/systemlogs/snoopy.log',
]


def pull_diagnostics(containers: list[str],
                     dest_dir: Path | str | None = None) -> Path:
    """Snapshot log files from each container into a local directory.

    For each container, fetches journalctl output + well-known log files
    into ``<dest_dir>/<container>/``. Best-effort: silently skips containers
    that no longer exist and log files that aren't present.

    Returns the destination directory path so callers can print it.
    """
    if dest_dir is None:
        dest_dir = Path(os.getcwd()) / DIAGNOSTICS_DIR_DEFAULT
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    for container in containers:
        # Skip containers that aren't running (e.g. failed before launch).
        r = subprocess.run([CLI_BIN, 'info', container],
                           capture_output=True, text=True)
        if r.returncode != 0:
            continue

        cdir = dest_dir / container
        cdir.mkdir(parents=True, exist_ok=True)

        # journalctl: capture sshd + msshd + mssh-* units when
        # available. Alpine images without systemd just write empty.
        r = lxc_exec(container, 'sh', '-c',
                     'command -v journalctl >/dev/null 2>&1 && '
                     'journalctl --no-pager '
                     '-u ssh -u sshd -u msshd '
                     '-u mssh-ca -u mssh-debug-sshd '
                     '2>/dev/null || true',
                     check=False, timeout=60)
        (cdir / 'journalctl.log').write_text(r.stdout or '')

        # Process list snapshot (helps diagnose "is sshd even running").
        r = lxc_exec(container, 'sh', '-c',
                     'ps auxf 2>/dev/null || ps -ef 2>/dev/null || true',
                     check=False, timeout=10)
        (cdir / 'processes.txt').write_text(r.stdout or '')

        # Well-known log files. Best-effort pull; missing files just skip.
        for remote in _DIAGNOSTIC_LOG_PATHS:
            try:
                pull_file(container, remote, cdir / Path(remote).name)
            except subprocess.CalledProcessError:
                pass

    return dest_dir


# ---------------------------------------------------------------------------
# Snoopy: opt-in command-execution logger for test diagnostics
# ---------------------------------------------------------------------------
#
# Snoopy is a small library that hooks `execve()` via /etc/ld.so.preload and
# writes every command (with uid, tty, cwd, full argv) to a log. When testing
# the full deployment, having a per-container log of every exec call is
# invaluable for diagnosing "why didn't this connection work" or "what did the
# shim actually try to run".
#
# Only installs on Ubuntu (apt package `snoopy` 2.4.15 in universe). Alpine
# uses musl libc; the upstream snoopy requires a custom musl build that is
# out of scope for the PoC.


SNOOPY_LOG_DIR  = '/root/systemlogs'
SNOOPY_LOG_FILE = f'{SNOOPY_LOG_DIR}/snoopy.log'


def install_snoopy(container: str) -> bool:
    """Install + configure snoopy on ``container``. Returns True on success.

    Side effects:
      - On Ubuntu: ``apt install snoopy`` + writes ``/etc/snoopy.ini`` + adds
        the library path to ``/etc/ld.so.preload`` so every future process
        is hooked (existing processes inside the container are NOT
        retroactively hooked — restart them if you want their commands too).
      - On Alpine: prints a notice and returns False (musl build out of scope).
    """
    if container.endswith('alpine'):
        print(f'  snoopy: Alpine container {container} skipped '
              '(needs musl source build — not packaged in apk)',
              file=sys.stderr, flush=True)
        return False
    r = lxc_exec(
        container, 'sh', '-c',
        'DEBIAN_FRONTEND=noninteractive apt-get install -y -q snoopy 2>&1',
        check=False, timeout=180,
    )
    if r.returncode != 0:
        print(f'  snoopy: apt install failed on {container}; tail:\n'
              f'{(r.stdout or r.stderr)[-300:]}',
              file=sys.stderr, flush=True)
        return False
    # Create log directory.
    lxc_exec(container, 'mkdir', '-p', SNOOPY_LOG_DIR)
    lxc_exec(container, 'sh', '-c',
             f': > {SNOOPY_LOG_FILE} && chmod 644 {SNOOPY_LOG_FILE}')
    # Configure snoopy output destination.
    ini = (
        '# Generated by tests/lxc/lxc_helpers.py:install_snoopy()\n'
        '[snoopy]\n'
        f'output = file:{SNOOPY_LOG_FILE}\n'
        'message_format = '
        '"%{datetime}|uid=%{uid}|pid=%{pid}|tty=%{tty}|cwd=%{cwd}|'
        'cmd=%{cmdline}"\n'
    )
    push_text(container, ini, '/etc/snoopy.ini', mode='644')
    # Locate libsnoopy.so (on Ubuntu it lives under /lib/<triplet>/ not /usr).
    r = lxc_exec(container, 'sh', '-c',
                 'for d in /lib /usr/lib /usr/lib64 /lib64; do '
                 '  find "$d" -name "libsnoopy.so" 2>/dev/null; '
                 'done | head -1',
                 check=False)
    so_path = (r.stdout or '').strip().splitlines()[0] if r.stdout else ''
    if not so_path:
        print(f'  snoopy: libsnoopy.so not found on {container}',
              file=sys.stderr, flush=True)
        return False
    # Idempotent preload registration.
    lxc_exec(container, 'sh', '-c',
             f'grep -q "{so_path}" /etc/ld.so.preload 2>/dev/null || '
             f'echo "{so_path}" >> /etc/ld.so.preload')
    print(f'  snoopy: installed on {container} → {SNOOPY_LOG_FILE} '
          f'(preload {so_path})', file=sys.stderr, flush=True)
    return True


def install_snoopy_on_all(containers: list[str]) -> dict[str, bool]:
    """Apply install_snoopy to a list of containers; return per-container result."""
    return {c: install_snoopy(c) for c in containers}
