# Implementation notes: authz cache + bypass cert

Working notes against `understanding.txt`. Captures where I'd extend
or differ from the simplest reading of the outline. Folded into the
canonical design docs once the implementation lands.

---

## Where I agree with the outline

- Cache is checked FIRST on every connection. CA call only on miss.
- Cache miss + CA down = fail. No special "CA-down" code path.
- Bypass cert injection writes directly into the cache.
- No active CA probe / retries before allowing bypass injection. The
  cert just goes in. Audit logs the event prominently.

## Where I'm extending beyond the outline (small)

### Cache key

Outline says "already granted list" without specifying the key. I'm
using **principal** (the SSH username). Future: could include a
fingerprint of the identity blob if multi-key-per-principal becomes
necessary. Out of scope for v1.

### Cache TTL

Each entry expires when its X.509 `not_after` passes. Eviction is lazy
(on lookup). The cache doesn't run a sweeper. Simple, correct,
no scheduler dependency.

### Cache invalidation on CA deny

When CA *is* reachable and returns a deny for a principal, msshd
invalidates that principal's cache entry. Without this, a once-granted
operator stays granted forever (until cert TTL) even after admin
revoke at the CA. This is the only way revocation works under a
cache-first model.

Open question: does CA deny invalidate ALL entries for that
principal, or just CA-sourced entries? See "second cache" below.
Kurt: should be the same policy for any cert, regardless of where the cert came from

### Bypass-cert validation

Before injecting, msshd verifies:

1. Cert signature chains to the trusted CA root.
2. Cert has the `mssh-ca-bypass` critical extension marker.
3. Cert's `not_before ≤ now ≤ not_after`.
4. Cert's bound principal **matches the mTLS handshake principal** —
   prevents a stolen bypass cert from being injected by an attacker
   who has a different mTLS cert (i.e., bypass injection is
   "presented by the rightful owner only").

### Wire protocol

mssh client adds an optional `bypass_cert: <base64-DER>` field to the
existing JSON header. Present → bypass-inject path. Absent → normal
flow. No new endpoint, no separate connection type.

---

## Where I'd want a second cache (or source-tagged entries)

The outline implies ONE cache. I think one is right, but a few
behaviors get cleaner if entries are tagged with their source
(`'ca'` vs `'bypass'`) even within a single dict. Concretely:

### CA-deny invalidation should not nuke bypass entries

If the CA is reachable and returns a deny for alice, we want alice's
cached **CA grant** invalidated. But should we invalidate her
bypass-injected cert too? Two views:

- **Yes (single cache, deny invalidates all):** simplest. Admin
  revokes alice → next CA call for alice returns deny → all of
  alice's cache is cleared, including bypass. Matches operator
  intuition: "alice is revoked, period."
- **No (source-tagged, bypass survives deny):** the bypass cert was
  pre-issued by the CA with explicit operator intent. A live deny
  shouldn't auto-revoke a deliberately-pre-cached emergency
  credential — that creates a race where someone with brief CA
  control can void all bypass certs. Operator must explicitly
  revoke the bypass cert (via `mssh-admin bypass-cert revoke`).

I'd lean toward **source-tagged: deny invalidates only CA entries**.
Bypass certs are explicit operator commitments; the operator should
have to explicitly revoke them. This is a security choice not in
the outline; flagging for review.
Kurt: you can make the argument that once the CA is back up and running,
you would want the cert deleted.  I would lean toward safety, and delete
in all cases.  Admin can always re-inject, but if the server is up, it
should always be the oracle.

### Admin visibility

`mssh-admin status` should be able to list "what's currently cached
on each msshd, by source." A single-dict-with-source-tag suffices;
no need for two physical stores. The CLI just filters by tag.

### Future: persistence

If we ever add disk persistence for bypass entries (survive msshd
restart, so a CA-down restart doesn't strand operators), only the
bypass entries should persist — CA grants are inherently short-lived
and revalidating via the CA on restart is correct. Source-tagged
entries make "persist only bypass" trivial.
Kurt: I thought we agreed to disk persistence before, but once injected
all should be treated the same.  lots of times an operator needs to
fix things, reboot, test, fix more reboot, etc.  If it is not persitent
operator would be force to reinject the bypass every time.  But I think
your marking this as future signals to me that this is in memory only 
in the current implementatoin.

### Future: separate eviction policies

CA grants often have short validity (minutes). Bypass certs often
have long validity (months). A common cache eviction by LRU /
capacity would surface odd behavior — long-lived bypass entries
hold cache slots while short-lived CA grants churn. Capacity-based
eviction would treat them asymmetrically. With source tags we can
apply different policies (e.g., capacity limit only on CA-source
entries; bypass entries never evicted under capacity pressure).
Kurt: this is no different than the revocation path. But this 
is an hole in the design, not just for bypass certs.  this needs
addressed as a todo.
---

## Net recommendation for v1

- **One cache, source-tagged entries.**
- Entry struct: `{grant, source: 'ca'|'bypass', injected_at}`.
- CA grants get cached on successful `/v1/authorize`.
- Bypass injections write tagged-as-bypass entries.
- CA deny invalidates only `'ca'`-source entries for the principal.
- Lookups don't care about source; they just find non-expired hits.
- Admin tools can filter by source for visibility.

This buys us all the optional behaviors above without needing a
second physical cache, and aligns with the spirit of the outline.
Kurt: I am fine with tagging them, we are aligned

---

## Resolutions (post-Kurt-review, 2026-05-18)

After Kurt's inline comments above, the v1 implementation lands on:

1. **One cache, source-tagged entries** — confirmed. Tag is
   `'ca' | 'bypass'`. Entries are otherwise interchangeable.

2. **CA deny invalidates ALL entries for the principal, regardless
   of source.** Reverses my earlier "bypass survives deny" lean.
   Kurt's view: "if the server is up, it should always be the
   oracle." Admin can re-inject if they still need bypass. Same
   policy for any cert.

3. **Disk persistence is v1, not future.** Both CA and bypass
   entries persist across msshd restarts. Reason: operator
   workflows during repair involve multiple reboots; making them
   re-inject the bypass every time is friction without security
   benefit (the cert is the same; storage location doesn't add
   risk beyond what already exists in `state_dir`). On-disk
   format: JSON, mode 0600, atomic write per change. Loaded on
   msshd startup with lazy expiry of stale entries.

4. **Eviction-on-capacity is a separate design hole.** Not
   bypass-specific. Tracked as a TODO; not addressed in v1.
   Acknowledged: with unbounded entries + long-lived bypass
   certs, the cache could grow without bound in pathological
   cases. Real-world cache sizes are small (one entry per
   active principal), so the bound matters less than the
   semantics. To-do tracked separately.

5. **`mssh-admin status` filters by source tag** for operator
   visibility into "what's currently cached, where it came from."

These are the load-bearing decisions for the v1 implementation.

---

## Amendment 2026-05-18 (b) — CRL revocation channel

Resolution of "design hole #4" above. Eviction-on-capacity remains
unaddressed; but the deeper issue — *how does a revoke at the CA
propagate to in-flight cache entries across the fleet?* — is now
solved by a sequence-based CRL.

### The shape

CA-side: append-only log of revocation entries
([`python/src/mssh/ca/crl.py`](../python/src/mssh/ca/crl.py)).

```
seq | revoked_at        | serials                | revoked_by | reason
----+-------------------+-------------------------+------------+-------
  1 | 2026-05-20T10:00Z | ["abc123"]              | boot-admin | rotation
  2 | 2026-05-23T09:00Z | ["alice-bypass-serial"] | boot-admin | offboard
```

Sequence is forever-incrementing; entries are atomic diffs.
Persisted as JSONL at `<enrollment_dir>/crl.jsonl`.

### Protocol

- Every `/v1/authorize` response now carries `current_crl_seq: M`.
- msshd persists its `last_crl_seq` on disk alongside the authz cache.
- When msshd sees `M > last_applied`, a background task fetches
  `GET /v1/crl?after=N&limit=K` against the CA endpoints, applies
  each entry's serials to the authz cache via
  `cache.invalidate_by_serial(serial)`, bumps `last_applied`,
  persists.
- The authorize request also sends `last_crl_seq` so the CA's audit
  log records fleet drift.

### Strict-mode gate (operator-configurable)

`ca.crl_strict_threshold` in wrapper.yaml (default 50). When
`(known_ca_seq - last_applied) > threshold`, msshd refuses cache
hits and falls through to live CA calls for every connection until
sync catches up. Default catches up briefly; operators worried about
revocation propagation can crank the threshold lower (down to 1 if
desired). Setting it to 0 disables the gate entirely.

### What the CRL apply does NOT do

- It doesn't re-validate cert chains, because cache entries are
  certs the CA itself signed and that have already passed validation.
- It doesn't differentiate by source tag — a revoked bypass cert is
  dropped exactly like a revoked CA-grant cert. Per the original
  resolution above (#2), CA is the oracle when reachable.

### Operator UX

```sh
# Revoke (superuser only):
mssh-admin cert revoke deadbeef abcd1234 --reason 'key rotation'

# Inspect the CRL log:
mssh-admin crl list
mssh-admin crl list --after 100 --limit 20
```

Every msshd in the fleet picks the revocation up on its next
authorize call. Affected operators get denied on cache invalidation;
their next attempt forces a fresh CA call which deny-confirms.

### What this closes (and what it doesn't)

**Closes:** the cache-eviction-on-revocation hole. Revoked certs
exit cache deterministically.

**Still open (acknowledged in original note #4):**
eviction-on-capacity. Cache size still has no upper bound. With
sequence-based CRL the lifetime is bounded by `not_after`, so the
pathological-growth concern is reduced — but a deployment minting
many long-lived bypass certs that all stay distinct in the cache
could still in principle grow without limit. Tracked separately.

**Not addressed here:** CA restart with seq-reset. If a CA reseeds
its CRL sequence at 0 (e.g., DR rebuild) while msshds in the fleet
have last_applied >0, the new entries won't reach them. That's a
multi-msshd-coordination problem the simple design doesn't solve.
Operator-side mitigation today: rebuild msshd state when
reseeding the CA.
