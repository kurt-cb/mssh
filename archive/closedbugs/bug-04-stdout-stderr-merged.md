# Bug #4 — stdout + stderr merged on the wire

**Status:** CLOSED via protocol v1.1 typed framing (future-ideas §21). Implementation: commits c12b1fa, ee1526a, c50dc9c. Verified end-to-end against lab claude-e69a69d7.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #4 — stdout + stderr merged on the wire

**Severity:** Design.
**Triggered by:** any `mssh user@host -- 2>/tmp/err`.

The mssh post-ack outer protocol does not have separate channels for stdout and stderr — the remote merges both into a single byte
stream. Clients cannot route stderr to a separate file.

**Acknowledged design** per the client.py docstring. Subsumed by
the planned framed protocol (future-ideas §21).

