"""mssh — client CLI for msshd hosts.

Speaks the outer-protocol-v1 (JSON header + raw byte stream) over a
TLS 1.3 + mTLS tunnel directly to msshd. No openssh-client dependency,
no openssl subprocess. Pure Python (uses ``ssl.SSLContext`` which
underlies OpenSSL).

Protocol (see design/architecture.md § wire protocols):

  1. TCP + TLS 1.3 + mTLS handshake.
  2. Client → server (1 line of JSON):
       {"v":1,"command":...,"interactive":...,"term":...,
        "rows":...,"cols":...,"env":...}
  3. Server → client ack: {"v":1,"ok":true} or {"v":1,"ok":false,"reason":...}
  4. After ack: raw bytes both ways (stdin ↔ stdout+stderr merged).
  5. TCP close = session end.

Usage:
    mssh alice@server-01                  # interactive shell, port 2200
    mssh alice@server-01 -- uname -a      # exec
    mssh -p 2222 alice@server-01
    mssh --identity ~/.mssh/alt-cert alice@server-01

Configuration (~/.mssh/config, key=value):
    default_port = 2200
    cert         = ~/.mssh/cert.pem
    key          = ~/.mssh/key.pem
    ca           = ~/.mssh/ca.pem
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import select
import shutil
import signal
import socket
import ssl
import sys
import termios
import tty
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mssh import frame


log = logging.getLogger('mssh')


DEFAULT_MSSHD_PORT = 2200
DEFAULT_CONFIG_PATH = '~/.mssh/config'
DEFAULT_CERT = '~/.mssh/cert.pem'
DEFAULT_KEY = '~/.mssh/key.pem'
DEFAULT_CA = '~/.mssh/ca.pem'

PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 4096


@dataclass
class Target:
    user: str
    host: str
    port: int


@dataclass
class Identity:
    cert: Path
    key: Path
    ca: Path


# ---------------------------------------------------------------------------
# Pure-data helpers (unit-tested in tests/test_mssh.py)
# ---------------------------------------------------------------------------

def _expand(p: str | Path) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(p))))


def parse_target(s: str, *, default_port: int,
                 default_user: str | None = None) -> Target:
    """'user@host[:port]' (user optional) → Target."""
    if '@' in s:
        user_part, rest = s.split('@', 1)
        user = user_part
    else:
        user = default_user or ''
        rest = s
    if ':' in rest:
        if rest.startswith('['):
            raise ValueError(
                'IPv6 bracket notation not supported in mssh v1; '
                'use -p <port> instead.')
        host, port_str = rest.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f'invalid port {port_str!r}') from None
    else:
        host = rest
        port = default_port
    if not host:
        raise ValueError('host required')
    return Target(user=user, host=host, port=port)


def load_config(path: str | Path) -> dict[str, str]:
    """Load a flat key=value config file."""
    p = _expand(path)
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for line_no, raw in enumerate(p.read_text().splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if '=' not in line:
            raise ValueError(
                f'{p}:{line_no}: expected key=value, got {raw!r}')
        k, v = line.split('=', 1)
        out[k.strip()] = v.strip()
    return out


def resolve_identity(config: dict[str, str], *,
                     cert_override: str | None = None,
                     key_override: str | None = None,
                     ca_override: str | None = None) -> Identity:
    """Resolve cert/key/ca paths from CLI / env / config / defaults."""
    cert = _expand(cert_override
                   or os.environ.get('MSSH_CERT')
                   or config.get('cert', DEFAULT_CERT))
    key = _expand(key_override
                  or os.environ.get('MSSH_KEY')
                  or config.get('key', DEFAULT_KEY))
    ca = _expand(ca_override
                 or os.environ.get('MSSH_CA')
                 or config.get('ca', DEFAULT_CA))
    return Identity(cert=cert, key=key, ca=ca)


def validate_identity(ident: Identity) -> None:
    for label, p in (('cert', ident.cert), ('key', ident.key),
                     ('ca', ident.ca)):
        if not p.exists():
            raise ValueError(
                f'{label} not found at {p}. Set MSSH_{label.upper()}=... '
                f'or write {p}.')
    mode = ident.key.stat().st_mode & 0o777
    if mode & 0o077:
        raise ValueError(
            f'private key {ident.key} has insecure permissions '
            f'(mode={mode:o}). Run: chmod 0600 {ident.key}')


def build_header(target: Target, *,
                 command: Optional[str] = None,
                 interactive: bool = False,
                 term: Optional[str] = None,
                 rows: Optional[int] = None,
                 cols: Optional[int] = None,
                 env: Optional[dict[str, str]] = None,
                 bypass_cert_b64: Optional[str] = None) -> bytes:
    """Construct the v1 outer-protocol header line (newline-terminated).

    ``bypass_cert_b64`` is the optional base64-DER of an
    operator-presentable CA-bypass cert. When present, msshd treats
    the connection as a bypass-injection request (validates the cert,
    stores it in the authz cache, acks, closes — no SSH session).
    See archive/design/notes-bypass-cache.md.
    """
    body = {
        'v': PROTOCOL_VERSION,
        'command': command,
        'interactive': interactive,
        'term': term,
        'rows': rows,
        'cols': cols,
        'env': env,
        # Principal echo for audit visibility on the server side.
        # msshd doesn't trust this — it derives the principal
        # from the mTLS cert — but it's useful in audit logs.
        'principal_hint': target.user,
        # v1.1 negotiation: client offers framed post-ack. Server's
        # ack echoes back `framing: true` only if it'll honor it; a
        # v1.0 msshd ignores the flag and the client falls back to
        # raw byte pump. See design/notes-protocol-v1.1.md.
        'supports_framing': True,
    }
    if bypass_cert_b64 is not None:
        body['bypass_cert'] = bypass_cert_b64
    encoded = json.dumps(body, separators=(',', ':')).encode('utf-8') + b'\n'
    if len(encoded) > MAX_HEADER_BYTES:
        raise ValueError(
            f'header too large ({len(encoded)} > {MAX_HEADER_BYTES})')
    return encoded


def parse_ack(line: bytes) -> tuple[bool, str, bool]:
    """Parse a server ack line into (ok, reason, framing).

    ``framing`` is True iff the server's ack explicitly opted into
    v1.1 framed mode. A v1.0 msshd never sets this flag; client
    falls back to the raw byte pump in that case.
    """
    try:
        body = json.loads(line.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f'malformed ack: {e}') from e
    if not isinstance(body, dict):
        raise ValueError(f'malformed ack: not an object: {body!r}')
    if int(body.get('v', 0)) != PROTOCOL_VERSION:
        raise ValueError(f'unsupported ack version: {body.get("v")}')
    framing = bool(body.get('framing', False))
    if body.get('ok'):
        return True, '', framing
    return False, str(body.get('reason', '(no reason given)')), framing


# ---------------------------------------------------------------------------
# Connect + run
# ---------------------------------------------------------------------------

def _build_ssl_context(ident: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(ident.cert), keyfile=str(ident.key))
    ctx.load_verify_locations(cafile=str(ident.ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # msshd hosts are addressed by IP/short name;
                                # SAN-based hostname verification isn't worth
                                # the operator-side complexity for v1.
    return ctx


def _read_line(sock: ssl.SSLSocket, max_bytes: int) -> bytes:
    """Read one newline-terminated line of at most max_bytes."""
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError('server closed before sending ack')
        buf.append(chunk[0])
        if chunk == b'\n':
            return bytes(buf)
        if len(buf) >= max_bytes:
            raise ConnectionError(f'ack exceeded {max_bytes} bytes')


def run_session(target: Target, ident: Identity, *,
                command: Optional[str], interactive: bool,
                env: Optional[dict[str, str]] = None) -> int:
    """Open the mTLS session, do the v1 handshake, pump stdin/stdout
    until either side closes. Returns 0 on clean close; non-zero on
    handshake / network error."""
    ctx = _build_ssl_context(ident)
    # 5s connect timeout. Without this, an unreachable IP hangs for the
    # kernel TCP timeout (~2 min). Users assume mssh is hung.
    try:
        raw_sock = socket.create_connection((target.host, target.port),
                                            timeout=5.0)
    except socket.timeout:
        print(f'mssh: connect {target.host}:{target.port}: '
              f'connection timeout (5s)', file=sys.stderr)
        return 4
    except OSError as e:
        print(f'mssh: connect {target.host}:{target.port}: {e}',
              file=sys.stderr)
        return 4

    try:
        sock = ctx.wrap_socket(raw_sock, server_hostname=target.host)
    except (ssl.SSLError, ConnectionError) as e:
        raw_sock.close()
        print(f'mssh: TLS handshake failed: {e}', file=sys.stderr)
        return 5

    try:
        # Pull terminal size if interactive (and stdin/stdout are TTYs).
        rows = cols = None
        if interactive and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                size = os.get_terminal_size(sys.stdout.fileno())
                rows, cols = size.lines, size.columns
            except OSError:
                pass

        term = os.environ.get('TERM') if interactive else None
        try:
            header = build_header(
                target, command=command, interactive=interactive,
                term=term, rows=rows, cols=cols, env=env,
            )
        except ValueError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 2
        sock.sendall(header)

        try:
            ack_line = _read_line(sock, MAX_HEADER_BYTES)
        except ConnectionError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 6
        try:
            ok, reason, framing = parse_ack(ack_line)
        except ValueError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 6
        if not ok:
            print(f'mssh: msshd rejected request: {reason}',
                  file=sys.stderr)
            return 7

        # Set the underlying TCP socket to non-blocking for the pump.
        # We do select() across the local stdin fd and the TLS socket
        # for portability across Python versions. Dispatch to the
        # framed pump iff the server's ack negotiated `framing: true`
        # — otherwise the legacy raw byte pump (v1.0 compatibility).
        if framing:
            return _pump_framed(sock, interactive=interactive)
        return _pump(sock, interactive=interactive)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _pump(sock: ssl.SSLSocket, *, interactive: bool) -> int:
    """Bidirectional stdin/stdout byte pump.

    Returns 0 on clean close (server EOF), non-zero on local I/O
    errors.
    """
    stdin_fd = sys.stdin.fileno() if sys.stdin.isatty() or interactive else 0
    stdout_fd = sys.stdout.fileno()

    # Put stdin into raw mode for interactive sessions so we don't
    # eat the Ctrl-C / arrow keys locally — they go to the remote.
    saved_tty: Optional[list] = None
    if interactive and sys.stdin.isatty():
        try:
            saved_tty = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)
        except (termios.error, OSError):
            saved_tty = None

    server_closed = False
    try:
        while True:
            r, _, _ = select.select([stdin_fd, sock.fileno()], [], [], 0.5)
            if stdin_fd in r:
                try:
                    chunk = os.read(stdin_fd, 65536)
                except OSError:
                    chunk = b''
                if not chunk:
                    # Local EOF: half-close write side via TLS shutdown
                    # is messy; just rely on close at exit.
                    pass
                else:
                    try:
                        sock.sendall(chunk)
                    except (ssl.SSLError, OSError):
                        break
            if sock.fileno() in r:
                try:
                    data = sock.recv(65536)
                except (ssl.SSLZeroReturnError, ssl.SSLWantReadError):
                    data = b''
                except (ssl.SSLError, OSError):
                    return 8
                if not data:
                    server_closed = True
                    break
                try:
                    os.write(stdout_fd, data)
                except OSError:
                    return 8
    finally:
        if saved_tty is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved_tty)
            except (termios.error, OSError):
                pass

    return 0 if server_closed else 8


def _pump_framed(sock: ssl.SSLSocket, *, interactive: bool) -> int:
    """v1.1 framed pump.

    Reads typed frames from the server, dispatches by type:

      - STDOUT  → write payload to stdout
      - STDERR  → write payload to stderr
      - BANNER  → write payload to stderr (pre-session)
      - DENY    → print "mssh: access denied — <reason>: <detail>",
                  set return code = 6, keep draining
      - EXIT    → record exit code, expect CLOSE next
      - SIGNAL  → record signal, expect CLOSE next
      - CLOSE   → exit loop, return recorded exit code (or 1 if none)

    Sends frames to the server in response to local events:

      - stdin readable + bytes      → STDIN frame
      - stdin EOF                   → STDIN_EOF frame, stop watching stdin
      - SIGWINCH (interactive)      → WINSIZE frame
    """
    stdin_fd = sys.stdin.fileno() if sys.stdin.isatty() or interactive else 0
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()

    # Raw TTY mode for interactive sessions.
    saved_tty: Optional[list] = None
    if interactive and sys.stdin.isatty():
        try:
            saved_tty = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)
        except (termios.error, OSError):
            saved_tty = None

    # SIGWINCH handler: when the terminal resizes, send a WINSIZE frame.
    # Only installed if we're attached to a TTY.
    pending_winsize: list[tuple[int, int]] = []
    prev_winch_handler = None
    if interactive and sys.stdin.isatty():
        def _on_winch(_sig, _frame):
            try:
                size = os.get_terminal_size(stdout_fd)
                pending_winsize.append((size.lines, size.columns))
            except OSError:
                pass
        try:
            prev_winch_handler = signal.signal(signal.SIGWINCH, _on_winch)
        except (ValueError, OSError):
            prev_winch_handler = None

    exit_code: Optional[int] = None
    deny_seen = False
    stdin_open = True

    try:
        while True:
            # Drain any pending window resizes.
            while pending_winsize:
                rows, cols = pending_winsize.pop(0)
                try:
                    sock.sendall(frame.encode_frame(
                        frame.WINSIZE, frame.encode_winsize(rows, cols)))
                except (ssl.SSLError, OSError):
                    return exit_code if exit_code is not None else 8

            watch = [sock.fileno()]
            if stdin_open:
                watch.append(stdin_fd)
            r, _, _ = select.select(watch, [], [], 0.5)

            if stdin_open and stdin_fd in r:
                try:
                    chunk = os.read(stdin_fd, frame.MAX_PAYLOAD)
                except OSError:
                    chunk = b''
                if not chunk:
                    # Local stdin EOF — signal the remote and stop watching.
                    try:
                        sock.sendall(frame.encode_frame(frame.STDIN_EOF))
                    except (ssl.SSLError, OSError):
                        return exit_code if exit_code is not None else 8
                    stdin_open = False
                else:
                    try:
                        sock.sendall(frame.encode_frame(frame.STDIN, chunk))
                    except (ssl.SSLError, OSError):
                        return exit_code if exit_code is not None else 8

            if sock.fileno() in r:
                try:
                    ftype, payload = frame.read_frame_sync(sock)
                except frame.ProtocolError as e:
                    print(f'mssh: protocol error: {e}', file=sys.stderr)
                    return exit_code if exit_code is not None else 8
                except (ssl.SSLZeroReturnError, ssl.SSLError, OSError):
                    return exit_code if exit_code is not None else 8

                if ftype == frame.STDOUT:
                    try:
                        os.write(stdout_fd, payload)
                    except OSError:
                        return 8
                elif ftype == frame.STDERR:
                    try:
                        os.write(stderr_fd, payload)
                    except OSError:
                        return 8
                elif ftype == frame.BANNER:
                    try:
                        os.write(stderr_fd, payload)
                    except OSError:
                        pass  # banner is informational; ignore write errors
                elif ftype == frame.DENY:
                    deny_seen = True
                    msg = _format_deny_payload(payload)
                    print(f'mssh: access denied — {msg}', file=sys.stderr)
                    exit_code = 6
                elif ftype == frame.EXIT:
                    try:
                        exit_code = frame.decode_exit(payload)
                    except frame.ProtocolError as e:
                        print(f'mssh: bad EXIT frame: {e}', file=sys.stderr)
                        exit_code = 8
                elif ftype == frame.SIGNAL:
                    signame = payload.decode('utf-8', errors='replace')
                    try:
                        # POSIX convention: 128 + signal number.
                        signum = int(signal.Signals[signame])
                        exit_code = 128 + signum
                    except (KeyError, ValueError, AttributeError):
                        exit_code = 129
                    print(f'mssh: remote killed by signal {signame}',
                          file=sys.stderr)
                elif ftype == frame.CLOSE:
                    break
                else:
                    print(f'mssh: unknown frame type 0x{ftype:02x}',
                          file=sys.stderr)
                    return 8
    finally:
        if prev_winch_handler is not None:
            try:
                signal.signal(signal.SIGWINCH, prev_winch_handler)
            except (ValueError, OSError):
                pass
        if saved_tty is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved_tty)
            except (termios.error, OSError):
                pass

    if exit_code is not None:
        return exit_code
    # Server closed without EXIT/DENY/SIGNAL → treat as a clean session
    # with success unless we saw a deny.
    return 6 if deny_seen else 0


def _format_deny_payload(payload: bytes) -> str:
    """Decode a DENY frame payload (UTF-8 JSON) into a human string.

    Falls back to raw text on parse error so the user still gets
    something useful.
    """
    import json as _json
    try:
        body = _json.loads(payload.decode('utf-8'))
        reason = body.get('reason', 'unspecified')
        detail = body.get('detail', '')
        if detail:
            return f'{reason}: {detail}'
        return str(reason)
    except (UnicodeDecodeError, _json.JSONDecodeError):
        return payload.decode('utf-8', errors='replace') or '(no detail)'


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='mssh',
        description='mssh client (mTLS + JSON-framed session-RPC to msshd).',
        usage='mssh [options] user@host[:port] [-- command [args ...]]',
    )
    parser.add_argument('target',
                        help='user@host[:port] or host[:port]')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help=f'msshd port (default {DEFAULT_MSSHD_PORT} '
                             f'or config.default_port)')
    parser.add_argument('-l', '--login-name',
                        help='login user (alternative to user@host syntax)')
    parser.add_argument('--identity', '-i',
                        help='path to mTLS client cert (default ~/.mssh/cert.pem)')
    parser.add_argument('--key',
                        help='path to mTLS client key (default ~/.mssh/key.pem)')
    parser.add_argument('--ca',
                        help='path to CA trust root (default ~/.mssh/ca.pem)')
    parser.add_argument('--config', default=DEFAULT_CONFIG_PATH,
                        help='path to mssh config (default ~/.mssh/config)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='log what mssh is doing to stderr')
    parser.add_argument('-t', '--force-tty', action='store_true',
                        help='request an interactive PTY even when stdin '
                             'is not a tty')
    parser.add_argument('-T', '--no-tty', action='store_true',
                        help='do not request a PTY')
    parser.add_argument('--inject-bypass-cert',
                        metavar='CERT_PATH',
                        help='Present this CA-bypass cert to msshd '
                             '(injects into its authz cache, then exits). '
                             'See archive/design/notes-bypass-cache.md.')
    parser.add_argument('command', nargs=argparse.REMAINDER,
                        help='optional remote command (after --)')

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='mssh: %(message)s',
        stream=sys.stderr,
    )

    try:
        cfg = load_config(args.config)
    except ValueError as e:
        print(f'mssh: config error: {e}', file=sys.stderr)
        return 2

    default_port = args.port or int(cfg.get('default_port',
                                            DEFAULT_MSSHD_PORT))

    try:
        target = parse_target(args.target,
                              default_port=default_port,
                              default_user=args.login_name or os.environ.get('USER'))
    except ValueError as e:
        print(f'mssh: {e}', file=sys.stderr)
        return 2

    if not target.user:
        print('mssh: no login user (use user@host or -l user)', file=sys.stderr)
        return 2

    try:
        ident = resolve_identity(cfg,
                                 cert_override=args.identity,
                                 key_override=args.key,
                                 ca_override=args.ca)
        validate_identity(ident)
    except ValueError as e:
        print(f'mssh: {e}', file=sys.stderr)
        return 2

    # argparse REMAINDER preserves the leading '--' if present.
    remote_command_parts = list(args.command)
    if remote_command_parts and remote_command_parts[0] == '--':
        remote_command_parts = remote_command_parts[1:]
    remote_command = ' '.join(remote_command_parts) if remote_command_parts else None

    if args.force_tty and args.no_tty:
        print('mssh: -t and -T are mutually exclusive', file=sys.stderr)
        return 2

    # Default: interactive when no command + stdin is a TTY.
    if args.force_tty:
        interactive = True
    elif args.no_tty:
        interactive = False
    else:
        interactive = remote_command is None and sys.stdin.isatty()

    log.debug('target=%s interactive=%s command=%r',
              target, interactive, remote_command)

    if args.inject_bypass_cert:
        return run_bypass_injection(target, ident, args.inject_bypass_cert)

    return run_session(target, ident,
                       command=remote_command,
                       interactive=interactive)


def run_bypass_injection(target: Target, ident: Identity,
                         bypass_cert_path: str) -> int:
    """Open the mTLS session, send the bypass cert in the v1 header,
    read the ack, exit. No SSH session is established.

    Returns 0 on injection-accepted, non-zero otherwise. Prints the
    server's reason string to stderr for both success and failure
    paths so the operator sees what was injected (and when it expires)
    or why it was rejected.
    """
    import base64 as _b64
    try:
        cert_pem = Path(bypass_cert_path).read_bytes()
    except OSError as e:
        print(f'mssh: cannot read bypass cert {bypass_cert_path}: {e}',
              file=sys.stderr)
        return 2
    # The wire form is base64 of DER. cryptography lib normalizes
    # PEM↔DER, but importing it here is a heavyweight dep for the
    # client — strip the PEM banners and re-base64 instead.
    try:
        body = cert_pem.decode('ascii').strip()
        # Strip PEM banners + whitespace; what remains is base64 DER.
        lines = [ln.strip() for ln in body.splitlines()
                 if ln.strip() and not ln.startswith('-----')]
        cert_der_b64 = ''.join(lines)
        # Validate that it round-trips through base64 cleanly.
        _b64.b64decode(cert_der_b64, validate=True)
    except Exception as e:
        print(f'mssh: bypass cert {bypass_cert_path} not a valid PEM: {e}',
              file=sys.stderr)
        return 2

    ctx = _build_ssl_context(ident)
    try:
        sock = socket.create_connection((target.host, target.port),
                                        timeout=5.0)
        sock = ctx.wrap_socket(sock, server_hostname=target.host)
    except socket.timeout:
        print(f'mssh: connect {target.host}:{target.port}: '
              f'connection timeout (5s)', file=sys.stderr)
        return 2
    except (ssl.SSLError, OSError) as e:
        print(f'mssh: TLS to {target.host}:{target.port} failed: {e}',
              file=sys.stderr)
        return 2

    try:
        header = build_header(target, command=None, interactive=False,
                              bypass_cert_b64=cert_der_b64)
        sock.sendall(header)
        ack_line = _read_line(sock, MAX_HEADER_BYTES)
        try:
            ok, reason, _framing = parse_ack(ack_line)
        except ValueError as e:
            print(f'mssh: malformed ack: {e}', file=sys.stderr)
            return 3
        if ok:
            # Server returns reason like 'injected:serial=… not_after=…'
            print(f'mssh: bypass cert injected ({reason or "OK"})',
                  file=sys.stderr)
            return 0
        print(f'mssh: bypass injection rejected: {reason}',
              file=sys.stderr)
        return 4
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == '__main__':
    sys.exit(main())
