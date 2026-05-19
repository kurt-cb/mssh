# Bug #3 — stdin is not forwarded to the remote

**Status:** OPEN.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #3 — stdin is not forwarded to the remote (PARTIALLY FIXED)

The data half is now fixed by Bug #5's `encoding=None` fix — chan.write
no longer raises on bytes input, so stdin bytes reach the remote and
the remote's response comes back. See verified post-fix output above.

**Still broken: stdin EOF doesn't propagate.** After the local echo
exits, the mssh client busy-spins because:

1. [client.py:339-342](python/src/mssh/client.py#L339-L342) — on
   stdin EOF the client falls into `pass` ("rely on close at exit").
2. select() keeps marking the EOF'd pipe as readable (level-triggered
   EOF), so the loop spins reading empty chunks forever.
3. msshd never sees a close-write signal, so the remote command
   (e.g. `cat`) keeps waiting for input.

**Architectural — flagged.** The fix needs a way to signal "stdin
half-closed" across the outer protocol. Three viable shapes:

- **(a) TLS-under-TCP half-close** — call `socket.shutdown(SHUT_WR)`
  on the underlying socket after stdin EOF. TLS 1.3 doesn't formally
  support half-close, so behavior is implementation-dependent. Likely
  fragile.
- **(b) Add a typed framing layer** to the post-ack stream, so we can
  send a `{type:"stdin_eof"}` message. This is the same protocol
  promotion that Bug #2 wants for exit-status. One shape solves both.
- **(c) Close the connection immediately on stdin EOF** and rely on
  msshd having buffered the response. Racy and breaks long-running
  pipelines.

I'd recommend (b). It's the same protocol work as Bug #2 — a single
framed layer carrying `{stdin, stdout, stderr, exit, signal}`
messages.

**Detection in static tests:** subprocess-level test piping stdin to
mssh client, then asserting the client exits within N seconds after
its stdin closes. Currently no such test.

---
