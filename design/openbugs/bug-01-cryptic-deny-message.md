# Bug #1 — Denial message is cryptic + sounds like a network error

**Status:** OPEN.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #1 — Denial message is cryptic + sounds like a network error

**Severity:** UX, **architectural**.
**Triggered by:** any user → unauthorized server.

```
$ mssh_as alice sales whoami
mssh: server closed before sending ack
exit=6
```

**What user sees:** `server closed before sending ack` — reads like the
server crashed or is unreachable. User has no signal that they were
deliberately denied or what to do about it.

**What the CA actually knows** (`/var/log/mssh/audit.jsonl`):
```json
{"decision":"denied","reason":"no_matching_policy",
 "detail":"user 'alice' has no policy granting access to server 'srv-sales'",
 "identity":{"username":"alice"}, "server":{"canonical_name":"srv-sales"}}
```

The deny reason is structured and actionable at the CA. It just never
reaches the client.

**Root cause hypothesis:** v1 protocol probably has msshd close the
inner channel on deny without sending a structured reason. The mssh
client interprets the close as a generic protocol failure.

**Architectural — flagged, not fixed.** Belongs in the protocol
contract (extend v1 to v1.1 with a `deny_reason` field, or carry it in
a banner-like pre-close message). Connects to future-ideas §18
("self-service why was I denied"), which assumes the user can at least
ask — today they don't even know they were denied vs offline.

**Suggested patch shape (not applied):**
1. msshd reads CA response's `denied` branch, sends one final
   structured message to the mssh client before closing.
2. mssh client surfaces it as `mssh: access denied — <reason> (see
   admin or run mssh-admin auth-failures-report)`.

**Detection in static tests:** a unit-level test that asserts on the
exact stderr string of a denial would catch any regression in deny
formatting. We have unit tests of the CA's deny logic but not of the
mssh client's deny rendering.

---
