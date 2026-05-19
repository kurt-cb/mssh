# Bug #9 — Revocation doesn't propagate when only denials are happening

**Status:** CLOSED.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #9 — Revocation doesn't propagate when only denials are happening (FIXED — see #10)

**Severity:** correctness, **architectural-then-simple**.
**Triggered by:** revoke a user via `mssh-admin cert revoke <serial>`,
then have only-denial traffic flow through msshd.

Observed: alice's cert revoked on the CA (seq advanced to 1). Other
users continued to try and be denied by policy on the same msshd.
30 seconds, then 60 seconds — alice STILL connects (cache valid,
CRL sync never ran).

**Root cause:** see Bug #10. Fixed via #10.

---
