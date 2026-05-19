# Bug #11 — Custom banner renders but mssh client never sees it

**Status:** OPEN.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #11 — Custom banner renders but mssh client never sees it

**Severity:** UX, design gap.
**Triggered by:** following operations.md § customize the per-server
pre-auth banner.

**What works:**
- `banner.template_path` + `values` substitution works as documented
- The rendered banner lands at `/var/lib/mssh/inner-sshd/banner` with
  substituted tokens (`{server}`, `{group}` replaced)
- The inner sshd reads it as its Banner directive

**What's broken:**
- The mssh client never sees the banner. The outer protocol is
  TLS+JSON, with raw bytes only post-ack. The SSH banner is a
  pre-auth SSH protocol message between msshd-as-client and
  inner-sshd. It never reaches the user.

Operators who customize the banner expecting users to see it will be
confused — the banner is invisible in enforce mode.

**Disposition:** **Design gap.** The banner feature has a documented
purpose (welcoming users, showing context) that the architecture
doesn't deliver. Options:

1. **Treat the banner as msshd-internal only** (an inner-sshd log
   marker, server attestation, etc.) — update operations.md to
   say so.
2. **Surface the banner through the outer protocol** — add a
   pre-ack JSON field carrying the banner text, mssh client
   prints it to stderr before the byte pump starts. Touches the
   protocol but is bounded (no new framing).
3. **Defer to future-ideas §17** which talks about per-session
   banner substitution — but that proposal needs to also figure
   out delivery to the client to actually be valuable.

**Detection in static tests:** Tier-2 test asserts that `mssh user@host
-- whoami` emits the banner text before the command output. Currently
no such test.

---

## Verified scenarios in round 2 (added to learnings)

| ID | Scenario | Outcome |
|----|----------|---------|
| A1 | happy path mssh | ✓ working |
| A7 | binary stdout 1MB | ✓ post-fix working |
| A12 | concurrent (3 parallel) | ✓ working |
| A14 | wrong port | ✓ clear error "Connection refused" |
| A20 | bypass cert inject | ✓ works "mssh: bypass cert injected (OK)" |
| B1 | mssh-admin status | ✓ (via python -m mssh.admin.main) |
| B2 | mssh-admin next | ✓ |
| B6 | mssh-admin audit | ✓ (with `--decision`, not `--result` as in docs) |
| B5 | mssh-admin user remove | ✓ (with `--user`, not positional as in docs) |
| B8 | bypass-cert mint | ✓ |
| B9 | cert revoke | ✓ (after Bug #10 fix; was failing before) |
| C1 | CA down cold-cache | ✓ correctly denies |
| C2 | CA down warm-cache | ✓ cached entry still works |
| C3 | revoke + cache invalidate | ✓ post-Bug-#10-fix |
| C4 | bypass cert during outage | ✓ end-to-end works |
| C6 | flip_to_per_connection | ✓ post-Bug-#8-fix |
| C10 | corrupt wrapper.yaml | ✓ msshd refuses to start, clear error |
