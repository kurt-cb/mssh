# Bug #10 — CRL sync only triggers on grant responses, not denies

**Status:** CLOSED.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

---

## Bug #10 — CRL sync only triggers on grant responses, not denies (FIXED)

**Severity:** correctness, simple but cross-file.
**Triggered by:** any deployment where msshd's authz cache mostly hits
and most CA traffic is denials. Revocations sit indefinitely on
msshd until SOME grant happens.

**Root cause:**
1. CA's `_deny()` response body
   ([authorize.py:70](python/src/mssh/ca/authorize.py#L70)) didn't
   include `current_crl_seq`. Only the grant path emitted it.
2. msshd's `AuthorizationDeny` dataclass + parse path
   ([msshd/ca.py:49-52](python/src/mssh/msshd/ca.py#L49-L52),
   [msshd/ca.py:190-195](python/src/mssh/msshd/ca.py#L190-L195))
   didn't extract `current_crl_seq` from the deny body even if it
   were there.
3. msshd's enforce_listener
   ([enforce_listener.py:249-258](python/src/mssh/msshd/enforce_listener.py#L249-L258))
   `maybe_sync()`'d only on grants, not on denies.

So even with a busy CA-deny path, CRL revocations stalled until some
fresh grant came through. On small fleets with stable populations,
this could be ∞.

**Fix applied (three places):**

1. `_deny()` gains `current_crl_seq` kwarg and includes it in the
   response body. All 8 deny call sites updated to pass
   `crl_seq = ctx.crl.current_seq() if ctx.crl is not None else None`.
2. `AuthorizationDeny` gains `current_crl_seq: int = 0` field; parse
   path extracts it from the response.
3. Enforce listener's deny branch calls
   `self.crl_sync.maybe_sync(result.current_crl_seq)` if nonzero.

**Verified post-fix:**

```
alice has cached entry, cert revoked on CA (seq → 1)
$ mssh_as bart acct whoami        # bart denied by policy
msshd.crl_sync: caught up from seq=0 to seq=1
$ mssh_as alice acct whoami       # alice's cache invalidated by CRL
mssh: server closed before sending ack       # now correctly denied
```

**Detection in static tests:** the existing `test_ca_crl.py` exercises
the CRL machinery but not the deny-response carrying current_crl_seq.
Add a Tier-2 test: ‘revoke a cert, force a deny from msshd, assert
last_crl_seq advanced.'

---

## Bug architectural caveat: CRL sync remains lazy

Even with #10 fixed, msshd only learns about CRL changes when SOMEONE
makes a CA call. If a server has 100% cache hits forever — small fleet,
stable population, recently warm — revocations propagate only via
the next cold call, which might never come.

**Not a bug per se:** the design is explicit that the strict-mode
threshold (`crl_strict_threshold`, default 50) catches drift via a
forced cold-call after the threshold is crossed. For small fleets,
this threshold is effectively never reached.

**Possible improvement (open / architectural):** a periodic
poll-the-CRL task at startup + every N minutes, even with no traffic.
Cheap (a single GET /v1/crl), bounded propagation. Cost: msshd has a
background task even when idle.


---
