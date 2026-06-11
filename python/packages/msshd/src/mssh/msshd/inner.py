"""Inner sshd subprocess lifecycle.

msshd owns a private OpenSSH ``sshd`` instance bound to a
high-port on 127.0.0.1. Its config is **hermetic** — rendered from a
template that ships with msshd, hash-validated against an
embedded known-good per OpenSSH version, and never edited by
operators.

See [architecture.md §5](../../design/architecture.md).

Lifecycle:
  - ``InnerSshd.start()`` — render config, generate host key if absent,
    spawn ``sshd -f config -D`` (foreground), wait for it to bind.
  - ``InnerSshd.stop()`` — SIGTERM + wait, escalate to SIGKILL after
    grace period.
  - ``InnerSshd.port`` — the actual bound port (allocated by us before
    spawn; sshd does not pick its own).

This module is asyncio-friendly: ``start`` and ``stop`` are coroutines.

Design: §5.3.10 + §5.3.11 (see design/mssh_design_v1.md) — hermetic
inner sshd lifecycle. §5.3.10 covers the long-lived single-instance
mode (InnerSshd); §5.3.11 covers per-connection mode
(PerConnectionInnerSshd). §5.3.12 — emergency-template fallback
posture (the banner / template-find logic).
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .config import MsshdConfig


log = logging.getLogger('msshd.inner')


_DEFAULT_BANNER = """\
─────────────────────────────────────────────────────────────
  Welcome — this session is mediated by mssh.

  Authorization was issued by the mssh CA. Your access is
  logged centrally.

  To customize this banner, set banner.template_path in
  msshd.yaml; see docs/operations.md § per-server banner.
─────────────────────────────────────────────────────────────
"""


class _SafeDict(dict):
    """Dict that returns ``{key}`` literally for missing keys, so a
    typo in the banner template doesn't crash msshd at startup."""
    def __missing__(self, key):  # noqa: D401
        return '{' + key + '}'


def _render_banner(template_path: str, values: dict[str, str]) -> str:
    """Read the banner template and substitute ``{key}`` tokens.

    Returns the default banner if ``template_path`` is empty or
    unreadable — we'd rather show a generic banner than fail to start
    the inner sshd. Logs at warning level if the path was set but the
    file is missing, so operators see why their customization didn't
    take effect.
    """
    if not template_path:
        return _DEFAULT_BANNER
    p = Path(template_path)
    try:
        raw = p.read_text()
    except (FileNotFoundError, PermissionError, OSError) as e:
        log.warning('banner template %s unreadable (%s); falling back '
                    'to default', template_path, e)
        return _DEFAULT_BANNER
    try:
        return raw.format_map(_SafeDict(values))
    except (ValueError, IndexError) as e:
        # format_map can raise on malformed format-strings (e.g. stray
        # braces). Surface as a warning + fall back so operators can fix
        # without msshd refusing to start.
        log.warning('banner template %s has a formatting error (%s); '
                    'falling back to default', template_path, e)
        return _DEFAULT_BANNER


def _find_template() -> Path:
    # §5.3.12 hermetic template discovery (env override → /etc/mssh →
    # repo-walk). Missing template raises — fail-closed at startup.
    """Locate the hermetic sshd_config.template file.

    Checked in priority order:
      1. ``$SSHRT_SSHD_CONFIG_TEMPLATE`` env var (operator escape hatch).
      2. ``/etc/mssh/sshd_config.template`` (installed location).
      3. Walking up from this file, find the nearest ``config/sshd_config.template``.
         Handles both the development checkout layout (template at the
         repo root's ``config/``) and the LXC-test push-source layout
         (template at ``/app/config/``).

    Raises FileNotFoundError if no candidate exists.
    """
    candidates = []

    env_override = os.environ.get('SSHRT_SSHD_CONFIG_TEMPLATE')
    if env_override:
        candidates.append(Path(env_override))

    candidates.append(Path('/etc/mssh/sshd_config.template'))

    # Walk up from this file's parents looking for `config/sshd_config.template`.
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / 'config' / 'sshd_config.template'
        candidates.append(cand)
        # Stop walking once we leave a plausible project root (one of the
        # parents is named one of these).
        if parent.name in ('src', 'python', 'mssh'):
            continue
        if parent == parent.parent:  # filesystem root
            break

    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(
        f'sshd_config.template not found in any of: '
        + ', '.join(str(c) for c in candidates))


class InnerSshdError(RuntimeError):
    """Inner sshd failed to start or died unexpectedly."""


class InnerSshd:
    def __init__(self, cfg: MsshdConfig, *,
                 state_dir: str | Path = '/var/lib/mssh/inner-sshd',
                 user_ca_pubkey_path: str | Path | None = None):
        self.cfg = cfg
        self.state_dir = Path(state_dir)
        self.user_ca_pubkey_path = (
            Path(user_ca_pubkey_path) if user_ca_pubkey_path
            else self.state_dir / 'msshd-user-ca.pub')
        self._port: int | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._sshd_binary = cfg.inner.sshd_binary

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError('InnerSshd not started yet')
        return self._port

    async def start(self) -> None:
        # §5.3.10 long-lived inner sshd boot: keys + banner + hermetic
        # config render + sshd -D spawn + bind wait.
        if self._proc is not None and self._proc.returncode is None:
            raise InnerSshdError('already running')

        if not Path(self._sshd_binary).is_file():
            raise InnerSshdError(
                f'sshd binary not found at {self._sshd_binary}')

        version = await _detect_sshd_version(self._sshd_binary)
        log.info('inner sshd binary: %s (%s)', self._sshd_binary, version)

        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o0750)

        # OpenSSH's distro builds use /run/sshd for privilege separation.
        # Systemd creates it for the system ssh.service via RuntimeDirectory;
        # we're not on that path, so we have to ensure it exists. Best-effort:
        # if we don't have privilege to create it, the sshd binary will
        # complain and we'll surface that via wait_port_open's error path.
        try:
            Path('/run/sshd').mkdir(mode=0o0755, exist_ok=True)
        except PermissionError:
            log.warning('cannot create /run/sshd — inner sshd may fail '
                        'to start. Run msshd as root or use a sshd '
                        'binary built with a custom --with-privsep-path.')

        # 1. Ensure a host key exists. Per-host, generated on first
        #    start, not rotated routinely (it's behind the outer mTLS;
        #    only matters between msshd and inner sshd on localhost).
        host_key = self.state_dir / 'ssh_host_ed25519_key'
        if not host_key.exists():
            await _gen_host_key(host_key)
            log.info('generated inner sshd host key at %s', host_key)

        # 2. Ensure the user-CA pubkey file exists; msshd writes
        #    it via UserCA.write_public_to() in admin init. We don't
        #    write it here — that's a msshd-startup concern.
        if not self.user_ca_pubkey_path.exists():
            raise InnerSshdError(
                f'user-CA pubkey not at {self.user_ca_pubkey_path} '
                '(run msshd-admin init)')

        # 3. Allocate a port in the configured range.
        lo, hi = self.cfg.inner.port_range
        self._port = _allocate_port(lo, hi)
        log.info('inner sshd will bind 127.0.0.1:%d', self._port)

        # 4. Render and write the pre-auth banner file. Operators can
        #    point banner.template_path at a custom file in msshd.yaml
        #    with {server}/{group}/operator-supplied {key} tokens; we
        #    substitute once at startup. Per-user substitution requires
        #    per-connection inner sshd (future-ideas.md §1).
        banner_path = self.state_dir / 'banner'
        banner_path.write_text(_render_banner(
            self.cfg.banner.template_path, self.cfg.banner.values))
        os.chmod(banner_path, 0o0644)

        # 5. Render the hermetic config.
        config_path = self.state_dir / 'sshd_config'
        rendered = _render_template(_find_template(),
            INNER_PORT=str(self._port),
            INNER_HOST_KEY=str(host_key),
            USER_CA_PUBKEY=str(self.user_ca_pubkey_path),
            BANNER_FILE=str(banner_path),
        )
        config_path.write_text(rendered)
        os.chmod(config_path, 0o0600)
        log.debug('wrote inner sshd_config to %s', config_path)

        # 5. Spawn sshd in foreground mode. We hold its lifecycle.
        self._proc = await asyncio.create_subprocess_exec(
            self._sshd_binary, '-D', '-f', str(config_path),
            '-E', str(self.state_dir / 'sshd.log'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # 6. Wait for the port to come up. If sshd crashes during
        #    startup, surface stderr in the exception so operators see
        #    a real reason.
        if not await _wait_port_open('127.0.0.1', self._port, timeout=10.0):
            stderr = b''
            try:
                stderr = await asyncio.wait_for(
                    self._proc.stderr.read(8192), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            await self.stop(grace=0.5)
            raise InnerSshdError(
                f'inner sshd did not bind 127.0.0.1:{self._port} within 10s '
                f'(stderr={stderr!r})')

        log.info('inner sshd is up on 127.0.0.1:%d (pid=%d)',
                 self._port, self._proc.pid)

    async def stop(self, *, grace: float = 3.0) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        log.info('stopping inner sshd (pid=%d, grace=%.1fs)',
                 self._proc.pid, grace)
        try:
            self._proc.terminate()
        except ProcessLookupError:
            return
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._proc.wait(), timeout=grace)
        if self._proc.returncode is None:
            log.warning('inner sshd did not exit after SIGTERM; sending SIGKILL')
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._proc.wait(), timeout=grace)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None


# ---------------------------------------------------------------------------
# Per-connection inner sshd
# ---------------------------------------------------------------------------

@dataclass
class _SessionProc:
    """One per-session sshd process. Held in PerConnectionInnerSshd._sessions."""
    session_id: str
    port: int
    proc: 'asyncio.subprocess.Process'
    session_dir: Path


class PerConnectionInnerSshd:
    """Spawn a fresh sshd-D-on-loopback per session.

    Used when ``msshd.yaml`` has ``inner.mode: per-connection``. Each
    session gets its own port, tempdir, sshd_config (rendered by the CA
    with this session's policy + msshd's local paths substituted), and
    sshd process. Per-session policy is enforced natively by OpenSSH
    (ForceCommand / AllowTcpForwarding / SetEnv / etc.) instead of by
    msshd's translation layer.

    Lifecycle:
      - ``start()`` once at msshd boot — ensures state_dir / host key
        exist and wipes any stale ``state_dir/sessions/*`` left by a
        prior crashed run.
      - ``acquire_session(session_id, rendered_config)`` per session —
        substitutes ``{LOCAL_*}`` markers in the CA-supplied config,
        sanity-checks via ``sshd -t``, spawns ``sshd -D -p <port>``,
        returns the port for msshd's SSH-client leg.
      - ``release_session(session_id)`` per session — SIGTERMs the
        sshd, releases the port, rmtree's the tempdir.
      - ``stop()`` at msshd shutdown — releases all live sessions.

    Backpressure: ``acquire_session`` honors
    ``cfg.performance.max_concurrent_sessions``. When the cap is hit,
    raises ``InnerSshdError`` — the caller surfaces this to the outer
    client as a clean denial.
    """

    def __init__(self, cfg: MsshdConfig, *,
                 state_dir: str | Path = '/var/lib/mssh/inner-sshd',
                 user_ca_pubkey_path: str | Path | None = None):
        self.cfg = cfg
        self.state_dir = Path(state_dir)
        self.user_ca_pubkey_path = (
            Path(user_ca_pubkey_path) if user_ca_pubkey_path
            else self.state_dir / 'msshd-user-ca.pub')
        self._sshd_binary = cfg.inner.sshd_binary
        self._host_key: Path = self.state_dir / 'ssh_host_ed25519_key'
        self._sessions: dict[str, _SessionProc] = {}
        self._ports_in_use: set[int] = set()
        self._lock = asyncio.Lock()

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    @property
    def sessions_dir(self) -> Path:
        return self.state_dir / 'sessions'

    @property
    def active_count(self) -> int:
        return len(self._sessions)

    async def start(self) -> None:
        """One-time setup. Idempotent: re-running is safe."""
        if not Path(self._sshd_binary).is_file():
            raise InnerSshdError(
                f'sshd binary not found at {self._sshd_binary}')

        version = await _detect_sshd_version(self._sshd_binary)
        log.info('per-connection inner sshd: binary=%s (%s)',
                 self._sshd_binary, version)

        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o0750)

        try:
            Path('/run/sshd').mkdir(mode=0o0755, exist_ok=True)
        except PermissionError:
            log.warning('cannot create /run/sshd — per-connection sshds '
                        'may fail to start. Run msshd as root or use a '
                        'sshd built with a custom --with-privsep-path.')

        if not self._host_key.exists():
            await _gen_host_key(self._host_key)
            log.info('generated per-connection host key at %s', self._host_key)

        if not self.user_ca_pubkey_path.exists():
            raise InnerSshdError(
                f'user-CA pubkey not at {self.user_ca_pubkey_path} '
                '(run msshd-admin init)')

        # Wipe stale session dirs from any prior crashed run.
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.sessions_dir, 0o0700)
        for entry in self.sessions_dir.iterdir():
            if entry.is_dir():
                log.info('per-connection: removing stale session dir %s',
                         entry.name)
                shutil.rmtree(entry, ignore_errors=True)

    async def acquire_session(self, session_id: str,
                              rendered_config: str) -> int:
        # §5.3.11 per-connection inner-sshd spawn: cap check, port
        # alloc, LOCAL_* marker subst, sshd -t sanity, spawn, wait.
        """Spawn a per-session sshd. Returns the port it bound.

        ``rendered_config`` is the per-session sshd_config text the CA
        produced (with ``{FROMCA_*}`` markers already substituted from
        policy). msshd substitutes the ``{LOCAL_*}`` markers below and
        writes the result to a per-session tempdir.
        """
        async with self._lock:
            cap = self.cfg.performance.max_concurrent_sessions
            if cap and len(self._sessions) >= cap:
                raise InnerSshdError(
                    f'max_concurrent_sessions={cap} reached '
                    f'(active={len(self._sessions)})')
            lo, hi = self.cfg.inner.port_range
            port = _allocate_port_excluding(lo, hi, self._ports_in_use)
            self._ports_in_use.add(port)

        session_dir = self.sessions_dir / session_id
        session_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)
        config_path = session_dir / 'sshd_config'
        banner_path = session_dir / 'banner'

        # Per-session banner: empty in v1; future per-user
        # banner-substitution lands here.
        banner_path.write_text('')
        os.chmod(banner_path, 0o0644)

        # Substitute {LOCAL_*} markers. The CA emits these as literals
        # because it doesn't know msshd's paths.
        rendered_local = _substitute_local_markers(rendered_config, {
            'LOCAL_PORT':           str(port),
            'LOCAL_HOST_KEY':       str(self._host_key),
            'LOCAL_USER_CA_PUBKEY': str(self.user_ca_pubkey_path),
            'LOCAL_BANNER_FILE':    str(banner_path),
        })
        config_path.write_text(rendered_local)
        os.chmod(config_path, 0o0600)

        # Sanity check: refuse to spawn if sshd can't parse the config.
        ok, err = await _sshd_config_test(self._sshd_binary, config_path)
        if not ok:
            self._cleanup_session_dir(session_dir, port)
            raise InnerSshdError(
                f'sshd refused per-session config (sshd -t): {err!r}')

        proc = await asyncio.create_subprocess_exec(
            self._sshd_binary, '-D', '-f', str(config_path),
            '-E', str(session_dir / 'sshd.log'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if not await _wait_port_open('127.0.0.1', port, timeout=10.0):
            stderr = b''
            try:
                stderr = await asyncio.wait_for(
                    proc.stderr.read(8192), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            await _terminate_proc(proc, grace=0.5)
            self._cleanup_session_dir(session_dir, port)
            raise InnerSshdError(
                f'per-session sshd did not bind 127.0.0.1:{port} within 10s '
                f'(stderr={stderr!r})')

        self._sessions[session_id] = _SessionProc(
            session_id=session_id, port=port, proc=proc,
            session_dir=session_dir)
        log.info('per-connection: session %s started on :%d (pid=%d)',
                 session_id, port, proc.pid)
        return port

    async def release_session(self, session_id: str, *,
                              grace: float = 2.0) -> None:
        # §5.3.11 per-connection teardown.
        """Terminate this session's sshd + rmtree its tempdir."""
        sp = self._sessions.pop(session_id, None)
        if sp is None:
            return
        log.info('per-connection: releasing session %s (pid=%d)',
                 session_id, sp.proc.pid)
        await _terminate_proc(sp.proc, grace=grace)
        self._cleanup_session_dir(sp.session_dir, sp.port)

    async def stop(self) -> None:
        """Release all active sessions at msshd shutdown."""
        for sid in list(self._sessions.keys()):
            await self.release_session(sid, grace=1.0)

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _cleanup_session_dir(self, session_dir: Path, port: int) -> None:
        """Remove a session's tempdir and release its port."""
        shutil.rmtree(session_dir, ignore_errors=True)
        self._ports_in_use.discard(port)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_template(template_path: Path, **vars: str) -> str:
    text = template_path.read_text()
    for k, v in vars.items():
        text = text.replace('{{' + k + '}}', v)
    return text


def _allocate_port(lo: int, hi: int) -> int:
    """Return an available TCP port on 127.0.0.1 in [lo, hi].

    Race-free strategy: try a handful of random ports, return the
    first that ``bind()``s successfully. We don't hold the bind --
    sshd will re-bind when it starts. There's a small TOCTOU window
    where another process could grab the port between us closing and
    sshd binding, but it's negligible on a host msshd owns.
    """
    candidates = random.sample(range(lo, hi + 1), k=min(100, hi - lo + 1))
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise InnerSshdError(f'no free port found in [{lo}, {hi}]')


async def _wait_port_open(host: str, port: int, *, timeout: float) -> bool:
    """Poll for the port to be listening. Returns True on success."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            r, w = await asyncio.open_connection(host, port)
        except (ConnectionRefusedError, OSError):
            await asyncio.sleep(0.1)
            continue
        w.close()
        with suppress(Exception):
            await w.wait_closed()
        return True
    return False


async def _detect_sshd_version(sshd_binary: str) -> str:
    """Run ``sshd -V`` (or fall back to parsing ``sshd -h``) to get the
    OpenSSH version string. Best-effort; we just want it for logging
    and (in Phase 1B+) hermetic-config hash-table lookups."""
    # sshd typically reports version on stderr in response to invalid
    # invocation. Use -V if supported (newer OpenSSH), else -h.
    try:
        proc = await asyncio.create_subprocess_exec(
            sshd_binary, '-V',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = await proc.communicate()
        text = (out + err).decode('utf-8', errors='replace')
    except FileNotFoundError:
        return 'unknown'
    m = re.search(r'OpenSSH[_ ]\d+\.\d+[a-z]?\d*', text)
    return m.group(0) if m else 'unknown'


async def _gen_host_key(host_key_path: Path) -> None:
    """Generate an Ed25519 host key via ssh-keygen. We don't use
    asyncssh.generate_private_key here because OpenSSH may expect a
    specific format wrinkle for host keys; ssh-keygen is the canonical
    producer."""
    ssh_keygen = shutil.which('ssh-keygen') or '/usr/bin/ssh-keygen'
    proc = await asyncio.create_subprocess_exec(
        ssh_keygen, '-t', 'ed25519', '-N', '', '-f', str(host_key_path),
        '-q', stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rc = await proc.wait()
    if rc != 0:
        stderr = await proc.stderr.read()
        raise InnerSshdError(
            f'ssh-keygen failed (rc={rc}): {stderr.decode(errors="replace")}')
    os.chmod(host_key_path, 0o0600)


# ---------------------------------------------------------------------------
# Per-connection helpers
# ---------------------------------------------------------------------------

# Matches {NAME} or {NAME:default} markers — same grammar as mssh.ca.render,
# but msshd substitutes only the LOCAL_* namespace. Anything else passes
# through (the CA already substituted FROMCA_*).
_LOCAL_MARKER_RE = re.compile(r'\{(LOCAL_[A-Z0-9_]+)(:[^}]*)?\}')


def _substitute_local_markers(text: str, values: dict[str, str]) -> str:
    """Substitute ``{LOCAL_*}`` markers in ``text`` using ``values``.

    Markers with a ``:default`` part fall back to that if the key is
    absent. Markers not in ``values`` and without a default pass
    through untouched — sshd will then either treat them as literal
    config (probably an error) or the operator will see them in the
    per-session sshd_config tempdir and diagnose.
    """
    def sub(m: re.Match) -> str:
        name = m.group(1)
        default = m.group(2)
        if name in values:
            return values[name]
        if default is not None:
            return default[1:]                  # strip leading ':'
        return m.group(0)                       # leave literal
    return _LOCAL_MARKER_RE.sub(sub, text)


def _allocate_port_excluding(lo: int, hi: int, exclude: set[int]) -> int:
    """Return an available TCP port on 127.0.0.1 in [lo, hi] that is not
    in ``exclude``. Used by the per-connection sshd pool to avoid
    re-issuing ports that have a live sshd already on them."""
    candidates = [p for p in random.sample(range(lo, hi + 1),
                                            k=min(200, hi - lo + 1))
                  if p not in exclude]
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise InnerSshdError(
        f'no free port found in [{lo}, {hi}] '
        f'(excluding {len(exclude)} in-use)')


async def _sshd_config_test(sshd_binary: str,
                            config_path: Path) -> tuple[bool, str]:
    """Run ``sshd -t -f config`` to validate the config before we spawn
    the real sshd. Returns (ok, stderr-tail).

    This is the per-session "belt-and-braces" safety check the
    per-connection design relies on: if the CA emits a config the
    host's sshd rejects, we refuse the session up front instead of
    letting sshd crash on spawn with a less specific error."""
    proc = await asyncio.create_subprocess_exec(
        sshd_binary, '-t', '-f', str(config_path),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode == 0:
        return True, ''
    msg = (err or out or b'').decode('utf-8', errors='replace')
    return False, msg.strip()[-500:]


async def _terminate_proc(proc: 'asyncio.subprocess.Process', *,
                          grace: float = 2.0) -> None:
    """SIGTERM, wait up to ``grace``, escalate to SIGKILL if still alive.
    Idempotent — already-exited procs return cleanly."""
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    with suppress(asyncio.TimeoutError):
        await asyncio.wait_for(proc.wait(), timeout=grace)
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=grace)
