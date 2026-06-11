# mssh-admin 2FA — design

How mssh-ca gates its own privileged operations behind a 2FA
ceremony. The operator (an enrolled admin) runs an mssh-admin
command; policy says the command requires 2FA; mssh-ca interrupts
the operation, sends a WebAuthn challenge to the operator's phone
via [mssh-passkey](mssh-passkey-module.md), waits for the
approval, then completes the operation.

This is **distinct** from:

  - [ca-integration.md § mssh-passkey integration](ca-integration.md#mssh-passkey-integration-)
    — that document covers the case where an external tool (not
    mssh-ca itself) uses mssh-ca as its WebAuthn RP service. Same
    broker, different consumer.
  - [mssh-passkey-module.md](mssh-passkey-module.md) — the broker
    module itself, identical regardless of which flow uses it.

The split exists because the surrounding context differs:

  - **In mssh-admin 2FA**: the "user" being challenged IS the
    operator running `mssh-admin`. Credentials live alongside the
    operator's admin enrollment record in mssh-ca's DB. The
    consumer of the verified outcome is mssh-ca itself.
  - **In external-tool integration**: the "user" is some
    end-user of a separate application. Credentials live in
    mssh-ca on behalf of that application. The consumer of the
    outcome is the external tool, which receives a forwarded
    verification result from mssh-ca.

---

## Operator-facing summary

For day-to-day operator workflow + setup, see
[docs/operations.md § Require passkey 2FA for high-privilege admin operations](../docs/operations.md#require-passkey-2fa-for-high-privilege-admin-operations).
That doc is the operator playbook; this one is the design.

---

## When 2FA kicks in

mssh-ca's existing role-permission table
([admin.py:_PERMISSIONS](../python/packages/mssh-ca/src/mssh/ca/admin.py))
maps actions to allowed admin roles. The 2FA layer is **per-policy**
— each policy row (the same shape that
`mssh-admin policy add` produces) can carry:

```yaml
require_2fa: passkey           # or "none" (default)
2fa_within_seconds: 60         # cache window after a successful 2FA
```

When mssh-ca receives an admin request that maps to a policy with
`require_2fa: passkey`:

  1. Check the **per-admin 2FA cache**. If the calling admin has
     completed a 2FA ceremony in the last `2fa_within_seconds`,
     accept and proceed.
  2. Otherwise interrupt the request: respond `202 Accepted` with
     a `passkey_ceremony` block carrying the qr_url, expires_at,
     and ceremony_id. Don't process the underlying operation.
  3. The mssh-admin CLI displays the URL to the operator (and
     optionally renders a QR code in the terminal).
  4. Operator approves via the phone.
  5. mssh-ca receives the broker's callback, verifies the
     assertion, records the success in the per-admin 2FA cache,
     and processes the underlying operation.
  6. The CLI polls `mssh-ca` for the result of the original
     operation.

---

## Dataflow

End-to-end mssh-admin 2FA flow. 4-column timeline.

```
  mssh-admin            mssh-ca              mssh-passkey         operator's
   (CLI)             (private net)             (broker)              phone
       │                  │                       │                     │
       │ <privileged cmd> │                       │                     │
       │ ───────────────► │                       │                     │
       │                  │                       │                     │
       │                  │ 1. resolve policy:    │                     │
       │                  │    "this admin's role │                     │
       │                  │     + this command =  │                     │
       │                  │     require_2fa:      │                     │
       │                  │     passkey"          │                     │
       │                  │                       │                     │
       │                  │ 2. check per-admin    │                     │
       │                  │    2FA cache:         │                     │
       │                  │    a) recent success  │                     │
       │                  │       → skip to 16    │                     │
       │                  │    b) no recent       │                     │
       │                  │       success → 3     │                     │
       │                  │                       │                     │
       │                  │ 3. lookup admin's     │                     │
       │                  │    registered passkey │                     │
       │                  │    credential_ids     │                     │
       │                  │    (none?  → fail)    │                     │
       │                  │                       │                     │
       │                  │ 4. webauthn.          │                     │
       │                  │    generate_          │                     │
       │                  │    authentication_    │                     │
       │                  │    options(           │                     │
       │                  │      rp_id,           │                     │
       │                  │      challenge,       │                     │
       │                  │      allow_           │                     │
       │                  │      credentials=     │                     │
       │                  │      admin's IDs)     │                     │
       │                  │                       │                     │
       │                  │ 5. store pending op + │                     │
       │                  │    challenge keyed    │                     │
       │                  │    by ceremony_id     │                     │
       │                  │                       │                     │
       │                  │ 6. POST /broker/      │                     │
       │                  │    ceremony  (mTLS)   │                     │
       │                  │    {type:"approve",   │                     │
       │                  │     options_json,     │                     │
       │                  │     description=      │                     │
       │                  │       "<the command>",│                     │
       │                  │     callback_url}     │                     │
       │                  │ ──────────────────►   │                     │
       │                  │                       │                     │
       │                  │                       │ INSERT ceremony     │
       │                  │                       │                     │
       │                  │ {ceremony_id,         │                     │
       │                  │  qr_url}              │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │ 7. 202 Accepted  │                       │                     │
       │    {passkey_     │                       │                     │
       │     ceremony: {  │                       │                     │
       │      qr_url,     │                       │                     │
       │      expires_at, │                       │                     │
       │      ceremony_id │                       │                     │
       │    }}            │                       │                     │
       │ ◄────────────────│                       │                     │
       │                  │                       │                     │
       │ 8. CLI shows:    │                       │                     │
       │    "Approve on   │                       │                     │
       │     your phone:  │                       │                     │
       │     <qr_url>"    │                       │                     │
       │    + QR code     │                       │                     │
       │    (then polls)  │                       │                     │
       │                  │                       │                     │
       │                  │                       │   GET /approve/<id> │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ HTML page with the  │
       │                  │                       │ command description │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │      9. navigator.  │
       │                  │                       │         credentials.│
       │                  │                       │         get(opts)   │
       │                  │                       │         → Face ID   │
       │                  │                       │                     │
       │                  │                       │  POST /approve/<id>/│
       │                  │                       │  respond            │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ UPDATE outcome=     │
       │                  │                       │ "approved"          │
       │                  │                       │                     │
       │                  │ 10. POST callback     │                     │
       │                  │     (mTLS)            │                     │
       │                  │     {ceremony_id,     │                     │
       │                  │      outcome:         │                     │
       │                  │       "approved",     │                     │
       │                  │      response_json}   │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │                  │ 11. webauthn.verify_  │                     │
       │                  │     authentication_   │                     │
       │                  │     response(         │                     │
       │                  │       response,       │                     │
       │                  │       expected_       │                     │
       │                  │         challenge,    │                     │
       │                  │       expected_rp_id, │                     │
       │                  │       expected_origin,│                     │
       │                  │       credential_     │                     │
       │                  │         public_key,   │                     │
       │                  │       credential_     │                     │
       │                  │         current_sign_ │                     │
       │                  │         count)        │                     │
       │                  │                       │                     │
       │                  │     • signature?      │                     │
       │                  │     • counter?        │                     │
       │                  │     • origin?         │                     │
       │                  │                       │                     │
       │                  │ 12. UPDATE per-admin  │                     │
       │                  │     2FA cache:        │                     │
       │                  │     last_verified=now │                     │
       │                  │                       │                     │
       │                  │ 13. UPDATE credential │                     │
       │                  │     sign_count        │                     │
       │                  │                       │                     │
       │                  │ 14. RESUME original   │                     │
       │                  │     operation         │                     │
       │                  │                       │                     │
       │                  │ 15. (callback ack)    │                     │
       │ (polling for     │ ──────────────────►   │                     │
       │  outcome)        │                       │                     │
       │ ───────────────► │                       │                     │
       │                  │                       │                     │
       │ 16. <operation   │                       │                     │
       │      result>     │                       │                     │
       │ ◄────────────────│                       │                     │
```

The cache-hit path (step 2a) skips steps 3-13 entirely. Within the
`2fa_within_seconds` window, additional 2FA-required commands
from the same admin go through without re-prompting. This makes
"batch of admin actions in a session" usable without one tap per
command.

---

## Per-admin 2FA cache

Schema addition to mssh-ca's admin enrollment record:

```
admin:
  name: "alice-admin"
  role: "superuser"
  mtls_subject: "CN=alice-admin"
  passkey_credentials:                      # NEW
    - credential_id: "..."
      public_key: "..."                     # COSE-encoded
      aaguid: "..."
      sign_count: 12
      label: "alice yubikey 5C"
      enrolled_at: "..."
      revoked_at: null
  passkey_2fa_cache:                        # NEW (transient, in-memory only)
    last_verified_at: "2026-05-20T18:32:10Z"
    last_credential_id: "..."
```

The cache is in-memory; mssh-ca restart invalidates every admin's
2FA state. That's intentional — restart is a security boundary.
The cache TTL is bounded by `2fa_within_seconds` regardless.

If the operator wants persistence across mssh-ca restarts,
they configure a larger `2fa_within_seconds` window; persisting
the cache to disk is explicitly out of scope.

---

## CLI experience

```
$ mssh-admin user remove --user bob
mssh-admin: 2FA required for this operation.

  Open this URL on your enrolled phone:
    https://passkey.example.com/approve/8c3e2f4b-...

  ┌─────────────────────────────┐
  │  █▀▀▀▀▀█ ▄▄ ▀▀█  █▀▀▀▀▀█    │  (QR code, if terminal supports it)
  │  █ ███ █ ▄▀▄ ▀▄  █ ███ █    │
  │  ...                       │
  └─────────────────────────────┘

  Expires in 4:58. Polling for approval…

⠋ awaiting approval
✓ approved (alice-admin's Yubikey 5C)
removed  bob
status   ok
```

If approval times out:

```
⠋ awaiting approval
✗ ceremony expired without approval — operation cancelled
mssh-admin: 2FA timeout. Re-run the command to retry.
```

If denied:

```
✗ denied by user — operation cancelled
mssh-admin: 2FA denied. The operator declined the prompt.
```

---

## Policy DSL extension

```bash
mssh-admin policy add \
    --user alice-admin \
    --servers prod-* \
    --channels session \
    --require-2fa passkey \
    --2fa-within-seconds 60
```

`require_2fa: passkey` on a policy means: this admin's actions
matching the policy require a passkey ceremony to complete (or a
cache hit within `2fa_within_seconds`).

Three values for `require_2fa`:

  - `none` (default) — no 2FA layer
  - `passkey` — WebAuthn ceremony via mssh-passkey broker
  - (future) `totp` — TOTP via mssh-ca's own validator. Not in
    v1.

Setting `require_2fa: passkey` on a policy when no passkey
broker is configured in ca-config.yaml is a startup error — fail
closed rather than silently let admins through.

---

## Open questions / future work

  - **CLI presentation of the QR code.** Some terminals render
    QR codes via `qrcode-terminal`; others won't. Fallback to a
    URL + an optional "open in browser" shortcut. Worth a config
    flag.
  - **2FA cache disclosure.** Should `mssh-admin status` surface
    that a given admin is "currently 2FA-cached" for transparency,
    or is that an information leak? Probably surface it; the cache
    state is operationally interesting.
  - **Cross-admin attestation revocation.** If superuser-A revokes
    superuser-B's passkey credentials mid-session while B has a
    2FA cache hit, should B's in-flight 2FA cache invalidate
    immediately? Probably yes — credential revoke should expire
    every cache entry referencing that credential.
  - **Forced re-auth on sensitive ops.** Some operations might
    want to bypass the cache and always require a fresh 2FA
    ceremony. Policy DSL flag `2fa_force_fresh: true`. Not in v1.
