"""mssh protocol v1.1 — typed framing for the post-ack stream.

Design: §3.1 + §14.7 (typed framing protocol v1.1; see
design/mssh_design_v1.md). Shared module per §15.4 (replaceable
broker wire-protocol surface).

Replaces the v1.0 raw byte pump after the JSON ack. Each post-ack
message is one frame:

    struct frame {
        uint8  type;      // FRAME_*
        uint8  flags;     // currently 0
        uint16 reserved;  // must be 0
        uint32 length;    // payload length in bytes (big-endian)
        uint8  payload[length];
    }

Big-endian throughout. 8-byte header.

See design/notes-protocol-v1.1.md for the rationale, frame-type
semantics, backward-compat negotiation, and state machines.

This module is socket-IO-agnostic: ``encode_frame`` returns the
bytes to write; ``read_frame_sync`` reads from a blocking ``recv()``-
capable socket; ``read_frame_async`` reads from an
``asyncio.StreamReader``. Callers choose whichever fits their loop.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Tuple


# ---- frame types -----------------------------------------------------------

# Client → server (mssh → msshd)
STDIN     = 0x01     # stdin bytes (payload = raw bytes)
STDIN_EOF = 0x02     # client signals "no more stdin" (zero payload)
WINSIZE   = 0x03     # interactive resize (payload = uint16 rows, uint16 cols, big-endian)

# Server → client (msshd → mssh)
STDOUT    = 0x10     # stdout bytes
STDERR    = 0x11     # stderr bytes
BANNER    = 0x12     # pre-stream banner (UTF-8 text payload)
EXIT      = 0x13     # remote command exit code (1-byte payload)
SIGNAL    = 0x14     # remote killed by signal (UTF-8 signal name)
DENY      = 0x15     # session denied (JSON payload: {reason, detail})

# Either direction
CLOSE     = 0x7F     # graceful close indication (zero payload)


# Maximum payload size on the wire. Larger writes must be fragmented
# by the sender into multiple frames of the same type. Receivers
# reject any frame with length > MAX_PAYLOAD.
MAX_PAYLOAD = 65536  # 64 KB

# Fixed-size header: 1 byte type, 1 byte flags, 2 bytes reserved,
# 4 bytes length. All multi-byte fields big-endian.
_HEADER = struct.Struct('!BBHI')
HEADER_SIZE = _HEADER.size  # = 8


class ProtocolError(Exception):
    """Raised when a frame can't be parsed or is otherwise malformed."""


# ---- public API ------------------------------------------------------------

def encode_frame(frame_type: int, payload: bytes = b'') -> bytes:
    """Serialize a frame. Returns the bytes ready for ``send()``.

    Raises ``ValueError`` if ``payload`` exceeds ``MAX_PAYLOAD``.
    """
    if not 0 <= frame_type <= 0xFF:
        raise ValueError(f'frame type out of range: 0x{frame_type:x}')
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(
            f'payload size {len(payload)} > MAX_PAYLOAD {MAX_PAYLOAD}; '
            f'sender must fragment')
    header = _HEADER.pack(frame_type, 0, 0, len(payload))
    return header + payload


def read_frame_sync(sock) -> Tuple[int, bytes]:
    """Read one frame from a blocking socket. Returns (type, payload).

    ``sock`` must support ``recv(n) -> bytes``. The function loops
    over short reads until the full frame is consumed.

    Raises ``ProtocolError`` on short reads (peer closed mid-frame),
    bad reserved bits, or payload-too-large.
    """
    header = _recv_exactly_sync(sock, HEADER_SIZE)
    frame_type, flags, reserved, length = _HEADER.unpack(header)
    _validate_header(frame_type, flags, reserved, length)
    payload = _recv_exactly_sync(sock, length) if length else b''
    return frame_type, payload


async def read_frame_async(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    """Read one frame from an asyncio StreamReader. Returns (type, payload).

    Raises ``ProtocolError`` on short reads, bad reserved bits, or
    payload-too-large.
    """
    try:
        header = await reader.readexactly(HEADER_SIZE)
    except asyncio.IncompleteReadError as e:
        raise ProtocolError(
            f'short read on frame header: got {len(e.partial)} of '
            f'{HEADER_SIZE} bytes') from e
    frame_type, flags, reserved, length = _HEADER.unpack(header)
    _validate_header(frame_type, flags, reserved, length)
    if length:
        try:
            payload = await reader.readexactly(length)
        except asyncio.IncompleteReadError as e:
            raise ProtocolError(
                f'short read on frame payload: got {len(e.partial)} of '
                f'{length} bytes (type=0x{frame_type:02x})') from e
    else:
        payload = b''
    return frame_type, payload


# ---- internals -------------------------------------------------------------

def _validate_header(frame_type: int, flags: int, reserved: int,
                     length: int) -> None:
    if reserved != 0:
        raise ProtocolError(
            f'frame header reserved field must be 0, got {reserved}')
    if flags != 0:
        raise ProtocolError(
            f'frame header flags must be 0 in v1.1, got {flags:#04x}')
    if length > MAX_PAYLOAD:
        raise ProtocolError(
            f'frame payload size {length} exceeds MAX_PAYLOAD {MAX_PAYLOAD} '
            f'(type=0x{frame_type:02x})')


def _recv_exactly_sync(sock, n: int) -> bytes:
    """Read exactly n bytes from a blocking socket. Loops over short reads."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError(
                f'short read: peer closed after {len(buf)} of {n} bytes')
        buf.extend(chunk)
    return bytes(buf)


# ---- helpers for common payload types --------------------------------------

def encode_winsize(rows: int, cols: int) -> bytes:
    """Encode WINSIZE payload (uint16 rows, uint16 cols, big-endian)."""
    if not (0 <= rows < 0x10000 and 0 <= cols < 0x10000):
        raise ValueError(f'rows/cols out of uint16 range: {rows}x{cols}')
    return struct.pack('!HH', rows, cols)


def decode_winsize(payload: bytes) -> Tuple[int, int]:
    """Decode a WINSIZE payload. Returns (rows, cols)."""
    if len(payload) != 4:
        raise ProtocolError(
            f'WINSIZE payload must be 4 bytes, got {len(payload)}')
    return struct.unpack('!HH', payload)


def encode_exit(exit_code: int) -> bytes:
    """Encode EXIT payload (1-byte exit code)."""
    if not 0 <= exit_code <= 0xFF:
        raise ValueError(
            f'exit code {exit_code} out of uint8 range; '
            f'callers should clamp non-shell exits to 255')
    return bytes([exit_code])


def decode_exit(payload: bytes) -> int:
    """Decode an EXIT payload. Returns the exit code (0-255)."""
    if len(payload) != 1:
        raise ProtocolError(
            f'EXIT payload must be 1 byte, got {len(payload)}')
    return payload[0]
