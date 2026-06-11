# Notes — protocol v1.1 (typed framing for the post-ack stream)

Design draft for future-ideas §21. Captures the framing layout,
EOF semantics, exit-status carrying, deny-reason carrying, and
banner pre-stream so the 5 open bugs in this cluster can be
closed in one PR.

**Status:** Draft. Not yet committed to implementation. Once the
shape stabilizes here, the actual code change lives in mssh-common
(frame definitions + read/write helpers), mssh client (`_pump`
rewrite), msshd `_OuterRelay` (typed-frame producer), and the CA
deny response.

## Why

Five user-visible bugs all trace to one structural fact: the
post-ack stream between mssh client and msshd is a **raw byte
pump**, with stdout + stderr merged on the wire, no exit status,
no EOF signal, no deny reason after ack-close.

| Bug | Today | Why structurally |
|---|---|---|
| #1 cryptic denials | `mssh: server closed before sending ack` | no deny-reason channel post-ack |
| #2 exit code always 0 | `mssh foo \|\| handle_err` is broken | no exit-status frame |
| #3 stdin EOF hangs | `echo x \| mssh ... cat` hangs | no half-close signal |
| #4 stderr merged | `2>` doesn't split streams | no stream-type field |
| #11 banner invisible | custom banner is server-side only | no banner channel |

Closing all five with a single protocol bump is much cleaner than
five point fixes.

## Wire shape

Pre-ack stays exactly as v1.0:

  1. TLS 1.3 handshake (mTLS).
  2. JSON header line: `{"v": <protocol>, ...}`.
  3. JSON ack: `{"v": <protocol>, "ok": <bool>, "reason": ...}`.

Post-ack is where v1.1 differs. Each direction is a stream of
frames:

```
struct frame {
    uint8  type;     // FRAME_TYPE_*
    uint8  flags;    // FRAME_FLAG_*  (currently 0)
    uint16 reserved; // must be 0
    uint32 length;   // payload length in bytes (network byte order)
    uint8  payload[length];
}
```

Fixed 8-byte header, variable payload. No framing-level checksum
(TLS handles integrity).

### Frame types

```
mssh → msshd                       msshd → mssh
─────────────────────────────────  ─────────────────────────────────
  0x01  STDIN     stdin bytes        0x10  STDOUT   stdout bytes
  0x02  STDIN_EOF stdin half-close   0x11  STDERR   stderr bytes
  0x03  WINSIZE   resize 16+16 LE    0x12  BANNER   pre-session banner
                                     0x13  EXIT     1-byte exit code
                                     0x14  SIGNAL   signal name (str)
                                     0x15  DENY     deny payload (JSON)
  0x7F  CLOSE     graceful close     0x7F  CLOSE    graceful close
```

Both sides reserve 0x80+ for future extensions; receivers must
treat unknown types as an error and close.

### Frame-type semantics

  - **STDIN / STDOUT / STDERR**: opaque bytes. No interpretation.
  - **STDIN_EOF**: zero-payload. Signals "no more stdin will arrive"
    — msshd calls `chan.write_eof()` on the inner SSH channel,
    causing the remote command to see EOF on stdin. Closes Bug #3
    completely.
  - **BANNER**: UTF-8 text. Sent at most once, BEFORE any STDOUT.
    The mssh client writes it to stderr. Closes Bug #11.
  - **EXIT**: a single uint8 exit code. Sent immediately before
    CLOSE on a graceful session end. mssh uses this as its own
    return code. Closes Bug #2.
  - **SIGNAL**: UTF-8 signal name (e.g. "TERM", "KILL"). Sent
    instead of EXIT when the remote command was killed by signal.
    mssh exits with `128 + signum` per shell convention.
  - **DENY**: JSON payload `{"reason": "...", "detail": "..."}`.
    Sent at most once, BEFORE the first STDOUT (i.e. on rejected
    sessions). mssh formats it as `mssh: access denied — <reason>:
    <detail>`. Closes Bug #1.
  - **WINSIZE**: 4 bytes = `uint16 rows, uint16 cols`, big-endian.
    Sent by mssh on local SIGWINCH if interactive. msshd forwards
    to the inner sshd via `chan.change_terminal_size`.
  - **CLOSE**: graceful indication that no more frames will come.
    Either side can send. Recipient closes the TLS socket.

### Backward compatibility

Negotiation lives in the JSON header that's already there:

```json
{"v": 1, "command": "...", "interactive": false, "supports_framing": true}
```

If the server's ack returns `{"v": 1, "ok": true, "framing": true}`,
both sides go framed. Otherwise it's the old raw byte pump.

A v1.0 mssh client connecting to a v1.1 msshd works (msshd doesn't
send `framing: true`; behavior is raw bytes). A v1.1 mssh client
connecting to a v1.0 msshd works (the ack doesn't contain
`framing: true`; client falls back to raw byte pump and accepts
the existing limitations).

This means the protocol bump is a **strict additive feature, not
a breaking change.** Mixed deployments work indefinitely.

## State machines

### mssh client (sender side)

```
                         ┌───────────────────────────┐
                         │  open TLS + send header   │
                         └────────────────┬──────────┘
                                          ▼
                              read JSON ack
                            ┌───────┴───────┐
                            │               │
                       ok=false           ok=true
                            │               │
                            ▼               ▼
                         print          framing ?
                         denial         ┌───┴───┐
                         exit non-      no    yes
                         zero           │      │
                                        ▼      ▼
                                     raw pump  framed pump
                                     (v1.0)    (see below)
```

### Framed pump — mssh client

Loop: select() across stdin_fd + sock.

  - stdin readable + bytes → send STDIN frame.
  - stdin EOF → send STDIN_EOF frame, stop watching stdin_fd.
  - sock readable → read one frame, dispatch by type.
  - DENY received → print "mssh: access denied — <reason>: <detail>",
    set return code = 6 (deny), continue draining.
  - BANNER received → write payload to stderr.
  - STDOUT → write payload to stdout.
  - STDERR → write payload to stderr.
  - EXIT received → record exit code, expect CLOSE next.
  - SIGNAL received → record signum, expect CLOSE next.
  - CLOSE received → exit loop, return recorded exit code (or 1
    if none was set).

### Framed pump — msshd (server side)

Same shape, mirror direction. msshd is an asyncssh client to the
inner sshd, so it:

  - reads STDIN frames from outer → writes them to chan.
  - reads STDIN_EOF from outer → `chan.write_eof()`.
  - reads bytes from chan stdout (datatype=0) → wraps in STDOUT.
  - reads bytes from chan stderr (datatype=EXTENDED_DATA_STDERR=1) →
    wraps in STDERR.
  - on chan.wait_closed: read exit_status / exit_signal, send EXIT
    or SIGNAL frame, send CLOSE.

The asyncssh `data_received(data, datatype)` callback already
distinguishes datatype 0 vs 1 — we currently merge them but the
new code keeps them separate.

## Implementation outline

### Phase A: protocol layer in mssh-common

New module `mssh.frame`:

```python
# Frame types
STDIN = 0x01
STDIN_EOF = 0x02
WINSIZE = 0x03
STDOUT = 0x10
STDERR = 0x11
BANNER = 0x12
EXIT = 0x13
SIGNAL = 0x14
DENY = 0x15
CLOSE = 0x7F

HEADER = struct.Struct('!BBHI')   # 8 bytes: type, flags, reserved, length

def read_frame(sock) -> tuple[int, bytes]:
    """Read one frame from sock. Returns (type, payload). Raises
    ProtocolError on bad header / truncated payload."""

def write_frame(sock, frame_type: int, payload: bytes = b'') -> None:
    """Write one frame. payload may be empty."""
```

About 100 LOC including tests. mssh-common is the right home: both
mssh client and msshd need it.

### Phase B: mssh client `_pump` rewrite

In `client.py`, `_pump` becomes a state machine that reads frames
on socket-ready and writes frames on stdin-ready. The exit-code
plumbing replaces the current "return 0 on clean close, 8 on I/O
error" with "return whatever EXIT frame carried."

Estimated diff: ~150 LOC modified, ~50 net added.

### Phase C: msshd `_OuterRelay` rewrite

`_OuterRelay.data_received(data, datatype)` becomes a frame
emitter:
  - datatype 0 → STDOUT frame
  - datatype 1 → STDERR frame
  - on `eof_received` → no-op (we get the exit info via
    chan.wait_closed)
  - on chan close → look up exit_status / exit_signal, emit
    EXIT or SIGNAL, then CLOSE

The outer-reader side becomes a frame parser that translates
STDIN/STDIN_EOF/WINSIZE back into asyncssh chan operations.

Estimated diff: ~120 LOC modified, ~30 net added.

### Phase D: CA deny response shape

The CA already returns `{status: "denied", reason: "...", detail:
"..."}` in its HTTP response. msshd just needs to translate that
into a DENY frame instead of closing silently.

In `enforce_listener.py`, after `AuthorizationDeny` is returned,
write a DENY frame to the outer socket before closing. About
10 LOC.

### Phase E: tests

The four xfail tests in [static-test-plan.md](static-test-plan.md)
all flip to passing once §21 lands:

  - `test_tier2_stdin_eof` — stdin EOF terminates cleanly
  - `test_tier2_exit_code` — `false` returns 1
  - `test_tier2_deny_message` — stderr contains "denied —"
  - `test_tier2_stderr_routing` — stderr is split from stdout

Plus new tests:

  - Frame round-trip (encode → decode → equal).
  - Backward-compat: v1.0 client + v1.1 server, traffic flows as raw.
  - Backward-compat: v1.1 client + v1.0 server, traffic flows as raw.
  - Banner delivery to mssh client's stderr.

Estimated ~250 LOC.

## Total LOC

| Component | LOC |
|---|---|
| mssh-common frame module | ~100 |
| mssh client `_pump` rewrite | ~150 |
| msshd `_OuterRelay` rewrite | ~120 |
| CA deny → DENY frame | ~10 |
| Tests | ~250 |
| **Total** | **~630** |

Roughly 2-3 focused sessions. Single PR.

## Risks / open questions

  - **Interactive PTY mode** — today the client puts stdin in raw
    mode and the byte pump carries the raw bytes. With framing,
    each keystroke becomes a STDIN frame with 8-byte overhead. For
    typing humans that's invisible. For a paste of 1MB through
    interactive stdin it's 4% overhead. Acceptable.

  - **Frame size limits** — should there be a max payload length
    (say 64 KB)? Senders fragment larger writes? Yes — pick 64 KB
    as the cap, both sides fragment STDOUT/STDIN that's larger.
    Avoids unbounded memory allocation on the receive side.

  - **Backward compat carefully verified** — the v1.0 client
    expects raw bytes after the ack. If a v1.1 msshd sends a
    frame, the v1.0 client treats the framed bytes as raw output
    (corrupted display). The negotiation MUST be correct: msshd
    only sends framed if the ack said `framing: true`, which only
    happens if the client sent `supports_framing: true` in its
    request. Both sides must respect the negotiation.

  - **Interaction with `--inject-bypass-cert`** — that flow uses
    the existing ack-then-close shape. v1.1 leaves it alone; the
    bypass-injection request doesn't open a session and so doesn't
    need framing.

  - **DENY frame timing** — must come before any STDOUT (so the
    client knows the session was rejected, not partially run).
    msshd's enforce_listener already orders things this way (deny
    → close). Just need to interpose the DENY frame write before
    the close.

  - **What if STDIN is sent after STDIN_EOF?** Receiver should
    treat as a protocol violation and CLOSE.

## Open: should v1.1 also carry a structured server-side ack on
success?

Today the JSON ack is `{"v": 1, "ok": true}` after which session
data flows. The v1.1 negotiation just adds a `framing` field. But
there's room to also carry the **inner sshd version**, msshd
version, banner pre-set, etc. — useful for debugging without
needing a separate metadata round-trip.

Worth considering but not blocking. Default position: do nothing
extra here; revisit when we have a concrete need.

## Migration plan

1. Land mssh-common frame module + tests.
2. Land mssh client framed pump + version-negotiation. Old labs
   keep working (no msshd advertises framing yet, so client
   falls back to raw).
3. Land msshd `_OuterRelay` framing + advertise `framing: true`
   in ack when client requested it. Now new clients get framed
   sessions; old clients keep raw.
4. Land CA deny → DENY frame plumbing.
5. Flip xfail tests to passing.
6. Update `design/openbugs/` → `archive/closedbugs/` for #1, #2,
   #3, #4, #11.

Each step keeps the test suite green. Any one can be reverted
independently if a session goes sideways.
