"""Unit tests for mssh.frame (protocol v1.1).

Covers:
  - encode_frame produces the documented on-the-wire bytes
  - read_frame_sync / read_frame_async round-trip via encode_frame
  - WINSIZE / EXIT payload helpers round-trip
  - Error paths: short reads, oversize payloads, bad reserved bits
  - Empty payload (zero-length frames work)
  - Every frame-type constant is unique
"""
from __future__ import annotations

import asyncio
import io
import socket
import struct
import threading

import pytest

from mssh import frame as f


# ---------------------------------------------------------------------------
# encode_frame — direct byte-level checks against the spec
# ---------------------------------------------------------------------------

def test_encode_stdin_with_payload():
    out = f.encode_frame(f.STDIN, b'hello')
    # type=0x01, flags=0, reserved=0, length=5, payload=hello
    assert out == bytes([0x01, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x05]) + b'hello'


def test_encode_empty_payload():
    """STDIN_EOF / CLOSE / etc. send zero-payload frames."""
    out = f.encode_frame(f.STDIN_EOF)
    assert len(out) == f.HEADER_SIZE
    assert out == bytes([0x02, 0, 0, 0, 0, 0, 0, 0])


def test_encode_rejects_oversize():
    too_big = b'\x00' * (f.MAX_PAYLOAD + 1)
    with pytest.raises(ValueError, match='MAX_PAYLOAD'):
        f.encode_frame(f.STDOUT, too_big)


def test_encode_rejects_out_of_range_type():
    with pytest.raises(ValueError, match='out of range'):
        f.encode_frame(0x100, b'')


# ---------------------------------------------------------------------------
# read_frame_sync via a socket-pair — real I/O including short reads
# ---------------------------------------------------------------------------

@pytest.fixture
def socket_pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_read_frame_sync_roundtrip(socket_pair):
    a, b = socket_pair
    a.sendall(f.encode_frame(f.STDOUT, b'pong'))
    ftype, payload = f.read_frame_sync(b)
    assert ftype == f.STDOUT
    assert payload == b'pong'


def test_read_frame_sync_multiple_frames(socket_pair):
    a, b = socket_pair
    a.sendall(f.encode_frame(f.STDOUT, b'one'))
    a.sendall(f.encode_frame(f.STDERR, b'two'))
    a.sendall(f.encode_frame(f.EXIT, b'\x07'))
    assert f.read_frame_sync(b) == (f.STDOUT, b'one')
    assert f.read_frame_sync(b) == (f.STDERR, b'two')
    assert f.read_frame_sync(b) == (f.EXIT, b'\x07')


def test_read_frame_sync_short_read_on_close(socket_pair):
    a, b = socket_pair
    # Send only 3 bytes of an 8-byte header, then close.
    a.send(bytes([0x10, 0x00, 0x00]))
    a.close()
    with pytest.raises(f.ProtocolError, match='short read'):
        f.read_frame_sync(b)


def test_read_frame_sync_short_read_payload(socket_pair):
    a, b = socket_pair
    # Header claims length=100 but we only send 4 bytes of payload.
    header = struct.pack('!BBHI', f.STDOUT, 0, 0, 100)
    a.send(header + b'abcd')
    a.close()
    with pytest.raises(f.ProtocolError, match='short read'):
        f.read_frame_sync(b)


def test_read_frame_sync_rejects_oversize(socket_pair):
    a, b = socket_pair
    # Manually craft a header that claims length > MAX_PAYLOAD.
    header = struct.pack('!BBHI', f.STDOUT, 0, 0, f.MAX_PAYLOAD + 1)
    a.send(header)
    a.close()
    with pytest.raises(f.ProtocolError, match='MAX_PAYLOAD'):
        f.read_frame_sync(b)


def test_read_frame_sync_rejects_nonzero_reserved(socket_pair):
    a, b = socket_pair
    # type=STDIN, flags=0, reserved=0x1234, length=0
    header = struct.pack('!BBHI', f.STDIN, 0, 0x1234, 0)
    a.send(header)
    a.close()
    with pytest.raises(f.ProtocolError, match='reserved'):
        f.read_frame_sync(b)


def test_read_frame_sync_rejects_nonzero_flags(socket_pair):
    a, b = socket_pair
    header = struct.pack('!BBHI', f.STDIN, 0xFF, 0, 0)
    a.send(header)
    a.close()
    with pytest.raises(f.ProtocolError, match='flags'):
        f.read_frame_sync(b)


def test_read_frame_sync_handles_short_recvs(socket_pair):
    """Send bytes one at a time; receiver must loop until full frame."""
    a, b = socket_pair
    payload = b'x' * 1000
    wire = f.encode_frame(f.STDOUT, payload)

    # Sender drips bytes; receiver must reassemble.
    def drip():
        for byte in wire:
            a.send(bytes([byte]))
        # No close — we want the receiver to complete, not hit EOF.

    t = threading.Thread(target=drip)
    t.start()
    try:
        ftype, got = f.read_frame_sync(b)
    finally:
        t.join()
    assert ftype == f.STDOUT
    assert got == payload


def test_read_frame_sync_max_payload(socket_pair):
    """Right at the size cap — should succeed, not error."""
    a, b = socket_pair
    payload = b'x' * f.MAX_PAYLOAD
    a.sendall(f.encode_frame(f.STDOUT, payload))
    ftype, got = f.read_frame_sync(b)
    assert ftype == f.STDOUT
    assert got == payload


# ---------------------------------------------------------------------------
# read_frame_async via asyncio
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_frame_async_roundtrip():
    a, b = socket.socketpair()
    try:
        a.sendall(f.encode_frame(f.STDOUT, b'async-pong'))
        a.close()  # mark stream end so readexactly doesn't block past frame

        reader, _writer = await asyncio.open_connection(sock=b)
        ftype, payload = await f.read_frame_async(reader)
        assert ftype == f.STDOUT
        assert payload == b'async-pong'
    finally:
        try:
            _writer.close()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_read_frame_async_short_read():
    a, b = socket.socketpair()
    try:
        a.send(bytes([0x10, 0x00, 0x00]))  # 3 of 8 header bytes
        a.close()
        reader, _writer = await asyncio.open_connection(sock=b)
        with pytest.raises(f.ProtocolError, match='short read'):
            await f.read_frame_async(reader)
    finally:
        try:
            _writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# payload helpers
# ---------------------------------------------------------------------------

def test_winsize_roundtrip():
    for rows, cols in [(24, 80), (1, 1), (0xFFFE, 0xFFFE)]:
        assert f.decode_winsize(f.encode_winsize(rows, cols)) == (rows, cols)


def test_winsize_rejects_bad_input():
    with pytest.raises(ValueError):
        f.encode_winsize(-1, 80)
    with pytest.raises(ValueError):
        f.encode_winsize(24, 0x10000)
    with pytest.raises(f.ProtocolError, match='4 bytes'):
        f.decode_winsize(b'abc')


def test_exit_roundtrip():
    for code in (0, 1, 7, 42, 127, 128, 255):
        assert f.decode_exit(f.encode_exit(code)) == code


def test_exit_rejects_out_of_range():
    with pytest.raises(ValueError):
        f.encode_exit(256)
    with pytest.raises(ValueError):
        f.encode_exit(-1)
    with pytest.raises(f.ProtocolError, match='1 byte'):
        f.decode_exit(b'')


# ---------------------------------------------------------------------------
# frame-type sanity
# ---------------------------------------------------------------------------

def test_all_frame_types_unique():
    """Cross-check the constants we expose don't collide."""
    types = {
        'STDIN': f.STDIN,
        'STDIN_EOF': f.STDIN_EOF,
        'WINSIZE': f.WINSIZE,
        'STDOUT': f.STDOUT,
        'STDERR': f.STDERR,
        'BANNER': f.BANNER,
        'EXIT': f.EXIT,
        'SIGNAL': f.SIGNAL,
        'DENY': f.DENY,
        'CLOSE': f.CLOSE,
    }
    values = list(types.values())
    assert len(set(values)) == len(values), \
        f'duplicate frame types: {types}'


def test_header_size_constant():
    """Wire format documented in design/notes-protocol-v1.1.md."""
    assert f.HEADER_SIZE == 8
