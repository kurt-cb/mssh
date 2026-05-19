# Bug #7 — `mssh-admin audit --result` documented but doesn't exist

**Status:** OPEN.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #7 — `mssh-admin audit --result` documented but doesn't exist

**Severity:** docs/UX, simple.
**Triggered by:** following [docs/operations.md:239](docs/operations.md#L239):

```
$ mssh-admin audit --since "1 hour ago" --result denied
```

The actual flag is `--decision`, not `--result`. There's also no
`--since` time-window flag — only `--limit`.

**Disposition:** **Open / simple.** Either fix the CLI to match docs
or fix the docs to match the CLI. The CLI's `--decision` name is
arguably better (it matches the audit-record field), so update the
doc.

**Bonus:** there is no `mssh-admin` binary installed on the CA
container in the adhoc lab. Operators following the docs hit
`mssh-admin: command not found`. Must invoke `python3 -m
mssh.admin.main` directly. The setup-only test framework uses
`mssh.admin.client.CAClient` instead, bypassing the CLI entirely.
**Suggested fix:** drop a wrapper at `/usr/local/bin/mssh-admin`
in the lab provisioning, same shape as `/usr/local/bin/mssh`.

**Detection in static tests:** Tier-2 test invoking each documented
admin command, asserting it doesn't fail with "no such option" or
"command not found." Currently no such test.

---
