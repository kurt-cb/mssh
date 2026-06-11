"""Inner SSH proxy — speaks outer-protocol-v1 to the mssh client and
asyncssh to the hermetic inner sshd.

After enforce_listener.py has done mTLS + CA call + cert mint, this
module:

  1. Reads one JSON header line from the outer stream.
  2. Acks (or denies) based on policy / sanity checks.
  3. Dispatches:
       - exec mode  → conn.run(command)
       - interactive → conn.create_session(..., term_type=...)
  4. Pumps bytes between the outer stream and the inner SSH session.

Protocol: see design/architecture.md §3.

Design: §5.3.4 (see design/mssh_design_v1.md) — AsyncSSH-based proxy
where msshd acts as the SSH client to the inner sshd; carries the
v1/v1.1 outer protocol header, ack, banner, framed/raw bidir traffic,
and the EXIT/SIGNAL/CLOSE shutdown frames.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import asyncssh

from mssh import frame


log = logging.getLogger('msshd.ssh_proxy')


PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 4096


async def _read_header_line(reader: asyncio.StreamReader) -> dict:
    """Read one newline-terminated JSON object, ≤ MAX_HEADER_BYTES."""
    line = await asyncio.wait_for(
        reader.readuntil(b'\n'), timeout=10.0)
    if len(line) > MAX_HEADER_BYTES:
        raise ValueError(
            f'header exceeds {MAX_HEADER_BYTES} bytes ({len(line)})')
    body = json.loads(line.decode('utf-8'))
    if not isinstance(body, dict):
        raise ValueError('header not a JSON object')
    if int(body.get('v', 0)) != PROTOCOL_VERSION:
        raise ValueError(
            f'unsupported protocol version {body.get("v")!r}')
    return body


def _write_ack(writer: asyncio.StreamWriter, *,
               ok: bool, reason: str = '',
               framing: bool = False) -> None:
    """Write the ack line. ``framing=True`` opts the client into v1.1
    typed framing for the post-ack stream — only set this if the
    client's header asked for it via ``supports_framing``."""
    body = {'v': PROTOCOL_VERSION, 'ok': ok}
    if not ok:
        body['reason'] = reason
    if framing:
        body['framing'] = True
    writer.write(json.dumps(body, separators=(',', ':')).encode('utf-8')
                  + b'\n')


class _BannerCapturingClient(asyncssh.SSHClient):
    """Captures the inner sshd's pre-auth banner so msshd can forward
    it to the mssh client as a BANNER frame in v1.1.

    asyncssh delivers the banner to ``SSHClient.auth_banner_received``;
    we stash it on a list the outer relay drains after session
    creation. In v1.0 (no framing) the banner is just dropped — the
    mssh client has no channel to display it on anyway (Bug #11).
    """

    def __init__(self) -> None:
        self.banner_chunks: list[str] = []

    def auth_banner_received(self, msg: str, lang: str) -> None:  # noqa: ARG002
        if msg:
            self.banner_chunks.append(msg)


class _OuterRelay(asyncssh.SSHClientSession):
    """Relays inner session stdout/stderr to the outer writer.

    Two modes:
      - **Legacy / v1.0**: writes raw bytes to the outer (everything,
        stdout + stderr, gets merged).
      - **Framed / v1.1** (``framed=True``): emits typed frames —
        STDOUT for datatype 0/None, STDERR for
        ``EXTENDED_DATA_STDERR``.

    The choice is made at construction time per the post-ack
    negotiation. See archive/closedbugs/bug-04-stdout-stderr-merged.md
    and design/notes-protocol-v1.1.md.
    """

    def __init__(self, outer_writer: asyncio.StreamWriter, *,
                 framed: bool = False):
        self._outer = outer_writer
        self._framed = framed

    def data_received(self, data, datatype):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            if self._framed:
                # datatype: 0/None = stdout, 1 = EXTENDED_DATA_STDERR.
                ftype = frame.STDERR if datatype == asyncssh.EXTENDED_DATA_STDERR \
                        else frame.STDOUT
                # Fragment payloads > MAX_PAYLOAD per spec.
                view = memoryview(data)
                for off in range(0, len(view), frame.MAX_PAYLOAD):
                    chunk = bytes(view[off:off + frame.MAX_PAYLOAD])
                    self._outer.write(frame.encode_frame(ftype, chunk))
            else:
                self._outer.write(data)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def eof_received(self):
        # v1.1 doesn't half-close the outer on inner EOF — the EXIT
        # frame + CLOSE come later via _run_session after wait_closed.
        # v1.0 (legacy) still half-closes for back-compat.
        if not self._framed:
            try:
                self._outer.write_eof()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
        return False


async def proxy_to_inner_ssh(
    *,
    outer_reader: asyncio.StreamReader,
    outer_writer: asyncio.StreamWriter,
    inner_host: str,
    inner_port: int,
    principal: str,
    user_private_key: asyncssh.SSHKey,
    user_cert: asyncssh.SSHCertificate,
    inner_host_key_path: str,
    conn_id: str = '?',
    max_session_seconds: Optional[int] = None,
    forced_command: Optional[str] = None,
    forced_env: Optional[dict[str, str]] = None,
    prefetched_header: Optional[dict] = None,
) -> None:
    # §5.3.4 outer-protocol v1 driver: header → ack → asyncssh connect
    # to inner sshd → dispatch exec vs interactive → bidir pump.
    """Drive asyncssh against the inner sshd.

    If ``prefetched_header`` is None, this function reads the v1
    outer-protocol header from ``outer_reader`` itself (legacy
    behavior). If the caller has already read the header (the
    enforce_listener path, which reads the header before its CA call
    so it can route bypass-cert injection), pass it through here so
    we don't try to double-read the same stream.

    Cert-mandated overrides:
      - ``forced_command`` (from mssh-force-command) overrides
        the client's ``command`` field if set.
      - ``forced_env`` (from mssh-environment) overrides /
        augments the client's ``env`` map.
    """
    # ---- 1. read header (or use prefetched one) ----
    if prefetched_header is not None:
        header = prefetched_header
    else:
        try:
            header = await _read_header_line(outer_reader)
        except asyncio.TimeoutError:
            log.warning('[%s] outer client did not send header in time', conn_id)
            _write_ack(outer_writer, ok=False, reason='header_timeout')
            await _drain_and_close(outer_writer)
            return
        except (json.JSONDecodeError, ValueError, asyncio.IncompleteReadError) as e:
            log.warning('[%s] outer header invalid: %s', conn_id, e)
            try:
                _write_ack(outer_writer, ok=False, reason=f'bad_header: {e}')
            except Exception:
                pass
            await _drain_and_close(outer_writer)
            return

    raw_command = header.get('command')
    interactive = bool(header.get('interactive'))
    term = header.get('term')
    rows = header.get('rows')
    cols = header.get('cols')
    env = header.get('env') or {}
    # v1.1: opt into typed framing only if the client advertised
    # support. Older clients omit `supports_framing` and we stay in
    # legacy raw-bytes mode for them.
    framed = bool(header.get('supports_framing'))

    # Apply cert-mandated overrides.
    command: Optional[str]
    if forced_command:
        command = forced_command
    elif isinstance(raw_command, str):
        command = raw_command
    else:
        command = None  # interactive shell
    if forced_env:
        # Force-env wins — operator policy overrides client preference.
        env = {**env, **forced_env}

    log.info('[%s] outer header: command=%r interactive=%s term=%s '
             'rows=%s cols=%s',
             conn_id, command, interactive, term, rows, cols)

    # ---- 2. connect to inner sshd ----
    # asyncssh's `known_hosts` parameter expects a file in
    # ``ssh_config(5) known_hosts`` format (host + key per line) or a
    # 3-tuple. msshd has just generated the inner sshd's host
    # key itself, so trust it explicitly via the tuple form.
    try:
        host_pubkey_bytes = open(inner_host_key_path, 'rb').read()
        trusted_host_key = asyncssh.import_public_key(host_pubkey_bytes)
    except Exception as e:
        log.error('[%s] cannot read inner host key %s: %s',
                  conn_id, inner_host_key_path, e)
        _write_ack(outer_writer, ok=False, reason='inner_host_key_unreadable')
        await _drain_and_close(outer_writer)
        return
    known_hosts_tuple = ([trusted_host_key], [], [])

    banner_client = _BannerCapturingClient()
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host=inner_host, port=inner_port,
                username=principal,
                client_keys=[(user_private_key, user_cert)],
                known_hosts=known_hosts_tuple,
                keepalive_interval=0,
                client_factory=lambda: banner_client,
            ),
            timeout=10.0,
        )
    except (asyncssh.Error, asyncio.TimeoutError, OSError) as e:
        log.error('[%s] inner SSH connect failed: %s', conn_id, e)
        _write_ack(outer_writer, ok=False, reason=f'inner_connect_failed')
        await _drain_and_close(outer_writer)
        return

    # ---- 3. ack the client ----
    _write_ack(outer_writer, ok=True, framing=framed)
    try:
        await outer_writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        conn.close()
        return

    # ---- 3.5: forward any pre-auth banner to the mssh client ----
    # In v1.0 (no framing) the mssh client has no channel for this,
    # so we drop it. v1.1 sends it before any STDOUT.
    if framed and banner_client.banner_chunks:
        banner_text = ''.join(banner_client.banner_chunks)
        try:
            outer_writer.write(frame.encode_frame(
                frame.BANNER, banner_text.encode('utf-8')))
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    # ---- 4. dispatch ----
    async with conn:
        try:
            await asyncio.wait_for(
                _run_session(conn, outer_reader, outer_writer,
                             command=command,
                             interactive=interactive,
                             term=term, rows=rows, cols=cols, env=env,
                             framed=framed,
                             conn_id=conn_id),
                timeout=max_session_seconds
                       if max_session_seconds and max_session_seconds > 0
                       else None,
            )
        except asyncio.TimeoutError:
            log.info('[%s] max_session_seconds elapsed; closing', conn_id)

    log.info('[%s] inner SSH session closed', conn_id)


async def _run_session(conn: asyncssh.SSHClientConnection,
                       outer_reader: asyncio.StreamReader,
                       outer_writer: asyncio.StreamWriter,
                       *,
                       command: Optional[str],
                       interactive: bool,
                       term: Optional[str],
                       rows: Optional[int],
                       cols: Optional[int],
                       env: dict[str, str],
                       framed: bool,
                       conn_id: str) -> None:
    # §5.3.4 session driver: create asyncssh session, pump v1/v1.1
    # inbound (raw or framed), emit EXIT/SIGNAL/CLOSE frames on close.
    # asyncssh's create_session signature:
    #   create_session(session_factory, command=None, *, request_pty='auto',
    #                  term_type=None, term_size=(cols, rows), env=...)
    # Choose request_pty explicitly to make behavior predictable.
    request_pty: bool | str
    if interactive:
        request_pty = True
    else:
        request_pty = False

    create_kwargs: dict = {
        'command': command,                # None ⇒ interactive shell
        'request_pty': request_pty,
        'env': env or None,
    }
    if interactive:
        if term:
            create_kwargs['term_type'] = term
        if rows and cols:
            create_kwargs['term_size'] = (int(cols), int(rows))

    # encoding=None keeps the SSH channel in byte-mode so non-UTF-8
    # bytes in the remote command's stdout don't trip asyncssh's
    # default utf-8 codec (which silently aborts the channel) and so
    # chan.write(bytes_from_stdin) doesn't raise the str-expected error.
    chan, _session = await conn.create_session(
        lambda: _OuterRelay(outer_writer, framed=framed),
        encoding=None, **create_kwargs)

    async def pump_outer_to_inner_raw():
        """Legacy v1.0: outer bytes → chan; outer EOF → chan.write_eof."""
        try:
            while True:
                data = await outer_reader.read(65536)
                if not data:
                    chan.write_eof()
                    break
                chan.write(data)
        except (ConnectionResetError, BrokenPipeError,
                 asyncio.IncompleteReadError):
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass

    async def pump_outer_to_inner_framed():
        """v1.1: parse typed frames from the outer client.

        STDIN     → chan.write
        STDIN_EOF → chan.write_eof
        WINSIZE   → chan.change_terminal_size
        CLOSE     → break (client signaled graceful close)
        Unknown   → log + break
        """
        try:
            while True:
                try:
                    ftype, payload = await frame.read_frame_async(outer_reader)
                except frame.ProtocolError as e:
                    log.warning('[%s] outer framing error: %s', conn_id, e)
                    break
                if ftype == frame.STDIN:
                    if payload:
                        chan.write(payload)
                elif ftype == frame.STDIN_EOF:
                    chan.write_eof()
                elif ftype == frame.WINSIZE:
                    try:
                        rows_, cols_ = frame.decode_winsize(payload)
                        chan.change_terminal_size(cols_, rows_)
                    except (frame.ProtocolError, Exception) as e:
                        log.debug('[%s] WINSIZE handler: %s', conn_id, e)
                elif ftype == frame.CLOSE:
                    break
                else:
                    log.warning('[%s] outer sent unexpected frame type '
                                '0x%02x; closing', conn_id, ftype)
                    break
        except (ConnectionResetError, BrokenPipeError,
                 asyncio.IncompleteReadError):
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass

    pump = asyncio.create_task(
        pump_outer_to_inner_framed() if framed else pump_outer_to_inner_raw()
    )
    try:
        await chan.wait_closed()
    finally:
        pump.cancel()
        try:
            await pump
        except (asyncio.CancelledError, Exception):
            pass

    # v1.1: emit EXIT (or SIGNAL) + CLOSE frames before closing the
    # outer writer. This is what carries the remote command's exit
    # code back to the mssh client.
    if framed:
        try:
            exit_status = chan.get_exit_status()
            exit_signal = chan.get_exit_signal()
        except Exception:
            exit_status = None
            exit_signal = None
        try:
            if exit_signal is not None:
                # asyncssh returns (signal_name, ...) as a tuple.
                signame = exit_signal[0] if isinstance(exit_signal, tuple) \
                          else str(exit_signal)
                outer_writer.write(frame.encode_frame(
                    frame.SIGNAL, signame.encode('utf-8')))
            elif exit_status is not None:
                code = max(0, min(255, int(exit_status)))
                outer_writer.write(frame.encode_frame(
                    frame.EXIT, frame.encode_exit(code)))
            outer_writer.write(frame.encode_frame(frame.CLOSE))
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    # Drain any remaining buffered output.
    try:
        await outer_writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


async def _drain_and_close(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
