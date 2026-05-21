# mssh-passkey — module design

A separate WebAuthn relying party + transaction broker. Consumed
by mssh-ca (and other back-end mssh components) via mTLS for 2FA
on high-privilege operations. Reachable from end-user phone
browsers over HTTPS.

This doc covers the **module internals**. Two sibling docs cover
the surrounding decisions:

  - [passkey-design-document.md](passkey-design-document.md) —
    architectural option evaluation (4 options, Option 2 chosen).
  - [ca-integration.md § mssh-passkey integration](ca-integration.md#mssh-passkey-integration-for-2fa-on-ca-operations-) —
    consumer-side integration: how mssh-ca calls the broker,
    ca-config, CLI surface.

> **Status:** initial implementation in progress (v0.1.5+). Storage,
> WebAuthn RP adapters, and the broker API land first; browser
> pages and adhoc-lab integration follow. Each decision below is
> the choice we're making for v1; "Decision needed:" markers flag
> places the operator may want to revisit later.

---

## 1. Module scope

**mssh-passkey is a relay only.** It owns no keys, performs no
WebAuthn verification, and holds no per-user state. The
relying-party role — credential storage, challenge generation,
attestation verification, assertion verification — lives in
mssh-ca (or any other back-end client that has an enrollment
DB). mssh-passkey carries the bytes between the back-end and the
user's browser.

**What mssh-passkey IS:**

  - A public-facing HTTPS relay. The user's phone browser reaches
    it; the back-end client (mssh-ca) reaches it over mTLS.
  - A short-lived ceremony broker. For each pending ceremony it
    holds `(ceremony_id → options_blob, callback_url, expires_at,
    description)` until the browser response arrives or the TTL
    expires.
  - A minimal web surface. Two pages: `/register/<id>` and
    `/approve/<id>`. Each runs the relevant `navigator.credentials.*`
    call and POSTs the response back to the broker, which relays
    it to the back-end client.

**What mssh-passkey IS NOT:**

  - **Not a WebAuthn relying party.** The `webauthn` library calls
    (`generate_registration_options`, `verify_registration_response`,
    `generate_authentication_options`, `verify_authentication_response`)
    are made by mssh-ca, not by mssh-passkey. The broker never
    sees a public key, never verifies an attestation.
  - **Not a credential store.** No table for users, no table for
    credentials, no AAGUID allowlist. Those live in the back-end
    client's enrollment DB.
  - **Not a general-purpose IdP.** No OAuth, no SAML, no password
    DB.
  - **Not a session/cookie service.** Each ceremony is one-shot.
  - **Not an audit-of-record.** Logs ceremony lifecycle events for
    operational visibility, but the canonical record lives in the
    back-end client (mssh-ca's audit log).

### Why broker-only

  - **Smaller blast radius on compromise.** A compromised broker
    cannot forge assertions — it holds no private material and no
    public keys to verify against. The worst it can do is drop
    transactions (DoS) or swap descriptions across in-flight
    ceremonies (transaction-binding attack, mitigated below).
  - **One source of truth.** Each user's credentials live
    alongside their other identity material in mssh-ca's
    enrollment record. No sync, no two-database consistency.
  - **Multiple back-end clients share one broker.** mssh-ca,
    msshd, future kiosk consumers can each hold their own
    credentials in their own enrollment DBs and share the same
    broker without coordination — the broker doesn't even know
    which back-end client is for which user.
  - **Easier to audit + deploy.** One table, two routes per page,
    relay logic. The broker can be reviewed and operationally
    hardened in isolation from the credential-handling code.

### Residual risk: description binding

The text the user reads on the approval page ("Revoke admin cert
for bob") is rendered by mssh-passkey but **not cryptographically
bound to the WebAuthn challenge**. A compromised broker could swap
descriptions across in-flight ceremonies — the user might approve
thinking they're approving X when they're really approving Y.

This is bounded:

  - The broker can't fabricate ceremonies — every ceremony has to
    be initiated by an mTLS-authenticated call from a back-end
    client. So a compromised broker can only confuse the user
    about which of the legitimate-in-flight ceremonies they're
    approving.
  - Production mitigation: back-end clients should include a
    short correlation ID in the description ("Revoke admin cert
    for bob, ticket #12345") that the admin who initiated the
    operation can confirm out-of-band before the user approves.
  - Catastrophic mitigation: if mssh-passkey is compromised,
    operator runbook is "rotate broker mTLS creds + alert users to
    stop approving until further notice."

Strictly better than the alternative where the broker holds
credentials: that version's catastrophic mitigation is "every
user re-registers every authenticator."

---

## 2. Storage schema (SQLite v1)

Single SQLite file, mode 0600. Persistent in production
deployments; ephemeral in adhoc-lab. **One table only** — the
broker holds nothing per-user, only in-flight ceremonies.

```sql
CREATE TABLE ceremonies (
  ceremony_id     TEXT PRIMARY KEY,      -- UUID; appears in the public URL
  ceremony_type   TEXT NOT NULL,         -- 'register' | 'approve'
  options_json    TEXT NOT NULL,         -- PublicKeyCredentialCreationOptions or
                                         -- PublicKeyCredentialRequestOptions, as
                                         -- built by the back-end client. The
                                         -- broker passes this verbatim to the
                                         -- browser; never inspects it.
  description     TEXT NOT NULL,         -- shown to the user on the page
  display_name    TEXT,                  -- account label shown on the page
  callback_url    TEXT NOT NULL,         -- where to POST the browser's response
  created_by      TEXT NOT NULL,         -- back-end client's mTLS CN
  created_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  consumed_at     TEXT,                  -- set when browser POSTs the response
                                         -- (or when /deny is clicked, or sweeper
                                         -- expires it)
  outcome         TEXT,                  -- 'approved' | 'denied' | 'expired'
                                         -- 'approved' means the browser
                                         -- responded; whether the response
                                         -- VERIFIES is the back-end client's
                                         -- decision after callback delivery
  response_json   TEXT,                  -- the AttestationResponse or
                                         -- AssertionResponse, JSON-encoded.
                                         -- Set when the browser POSTs; relayed
                                         -- verbatim to the back-end client.
  callback_status TEXT                   -- null | 'pending' | 'delivered'
                                         --      | 'failed_max_retries'
);

CREATE INDEX idx_ceremonies_expires ON ceremonies(expires_at, outcome);
```

**Notes on the schema:**

  - **No `users` table.** The broker doesn't know who alice is.
    The back-end client puts whatever user identity it wants into
    the `options_json.user` field for the browser to display,
    and the broker just relays the bytes.
  - **No `credentials` table.** Credentials live in the back-end
    client's enrollment DB.
  - **No `aaguid_allowlist`.** Allowlist enforcement happens in
    the back-end client during attestation verification.
  - `options_json` is the exact blob the browser passes to
    `navigator.credentials.create()` or `navigator.credentials.get()`.
    The back-end client builds it (via the `webauthn` library);
    the broker stores it as opaque text.
  - `response_json` is the browser's response, again opaque to
    the broker — JSON-serialized and relayed.
  - `outcome = 'approved'` here means "the browser responded";
    the back-end client makes the actual signature-verification
    decision on its end after receiving the callback. If
    verification fails server-side, the back-end client logs
    the failure and refuses the operation — the broker doesn't
    learn this (and doesn't need to).

---

## 3. Registration ceremony

Sequence (back-end client = mssh-ca in the canonical case;
diagram in [ca-integration.md § Registration dataflow](ca-integration.md#registration-dataflow)
shows the broker-side detail with timing):

```
mssh-ca                  mssh-passkey                    user's phone
                          (broker)
   │                          │                                │
   │ webauthn.generate_       │                                │
   │ registration_options(    │                                │
   │   rp_id="passkey.exam…", │                                │
   │   user_id="alice",       │                                │
   │   ...)                   │                                │
   │ → options_json,          │                                │
   │   challenge_bytes        │                                │
   │ (mssh-ca stores the      │                                │
   │  challenge in a pending- │                                │
   │  registrations table     │                                │
   │  keyed by ceremony_id)   │                                │
   │                          │                                │
   │ POST /broker/ceremony    │                                │
   │ (mTLS)                   │                                │
   │ {type: "register",       │                                │
   │  options_json,           │                                │
   │  description, ttl,       │                                │
   │  callback_url}           │                                │
   ├─────────────────────────►│                                │
   │                          │ INSERT ceremonies row          │
   │                          │ generate ceremony_id           │
   │                          │                                │
   │ {ceremony_id, url,       │                                │
   │  expires_at}             │                                │
   │◄─────────────────────────┤                                │
   │                          │                                │
   │ (operator sends url      │                                │
   │  to alice OOB)           │                                │
   │                          │                                │
   │                          │ GET /register/<ceremony_id>    │
   │                          │◄───────────────────────────────┤
   │                          │                                │
   │                          │ HTML page (Flask + Bootstrap5) │
   │                          │ with options_json embedded     │
   │                          ├───────────────────────────────►│
   │                          │                                │
   │                          │                  navigator.    │
   │                          │                  credentials.  │
   │                          │                  create(       │
   │                          │                    options)    │
   │                          │                  → biometric   │
   │                          │                                │
   │                          │ POST /register/<id>/respond    │
   │                          │ {attestationObject, client-    │
   │                          │  DataJSON, transports}         │
   │                          │◄───────────────────────────────┤
   │                          │                                │
   │                          │ UPDATE ceremony:               │
   │                          │   response_json = ...          │
   │                          │   outcome = "approved"         │
   │                          │   consumed_at = now            │
   │                          │                                │
   │                          │ (broker DOES NOT verify;       │
   │                          │  it just stores + relays)      │
   │                          │                                │
   │                          │ {ok: true}                     │
   │                          ├───────────────────────────────►│
   │                          │                                │
   │                          │ (HTML page: "Submitted; check  │
   │                          │  with your operator if the     │
   │                          │  enrollment was accepted")     │
   │                          │                                │
   │ POST callback_url        │                                │
   │ (mTLS)                   │                                │
   │ {ceremony_id,            │                                │
   │  outcome: "approved",    │                                │
   │  response_json}          │                                │
   │◄─────────────────────────┤                                │
   │                          │                                │
   │ webauthn.verify_         │                                │
   │ registration_response(   │                                │
   │   response,              │                                │
   │   expected_challenge,    │                                │
   │   expected_rp_id,        │                                │
   │   expected_origin)       │                                │
   │ • signature valid?       │                                │
   │ • origin = passkey.…?    │                                │
   │ • AAGUID in allowlist?   │                                │
   │                          │                                │
   │ If all checks pass:      │                                │
   │   INSERT credential into │                                │
   │   alice's enrollment     │                                │
   │   record (public_key,    │                                │
   │   credential_id, AAGUID, │                                │
   │   sign_count, label).    │                                │
   │ Else: refuse, log,       │                                │
   │   alert.                 │                                │
   │                          │                                │
   │ (200 to broker's         │                                │
   │  callback POST)          │                                │
   ├─────────────────────────►│                                │
```

The broker is genuinely just a relay. Every WebAuthn-specific
operation (`generate_*_options`, `verify_*_response`, AAGUID
allowlist enforcement, public-key storage) happens in mssh-ca.
The broker stores the `options_json` blob and the response blob
and ships them across the network boundaries.

### Multi-device

To add a second credential for an existing user, mssh-ca builds
fresh registration options (`generate_registration_options`) and
posts a new ceremony to the broker. The `options_json` includes
the user's existing credential IDs in `excludeCredentials` so the
authenticator can refuse to re-register the same device.

The broker doesn't need to know this is "alice's second device" —
that's mssh-ca's concern.

### Recovery

> **Decision needed (deferred to v2):** explicit recovery flow.
> v1 answer: operator runs `mssh-admin user passkey revoke
> --user alice --all` (revokes every credential), then
> `mssh-admin user passkey enroll --user alice` to mint a fresh
> registration ceremony. Auditable, slow, no special "recovery
> code" path.

### AAGUID allowlist lives at mssh-ca, not at the broker

The allowlist is a property of the **back-end client's** policy:
"this CA accepts these hardware models." mssh-ca enforces it
during `webauthn.verify_registration_response()` by checking the
attestation statement's AAGUID against the configured list and
refusing to insert the credential into its enrollment DB if the
AAGUID isn't allowed.

YAML file at `/etc/mssh-ca/aaguid-allowlist.yaml`:

```yaml
allowed_aaguids:
  - "ee882879-721c-4913-9775-3dfcce97072a"  # YubiKey 5 NFC
  - "fa2b99dc-9e39-4257-8f92-4a30d23c4118"  # YubiKey 5 USB-C
  - "8876631b-d4a0-427f-5773-0ec71c9e0279"  # SoloKey 2
require_allowlist: true
```

In dev (`require_allowlist: false`), any attestation is recorded
+ the AAGUID logged for later vetting.

The broker never sees this file. Different back-end clients
sharing the same broker can have different allowlists; the
broker doesn't care.

---

## 4. Approval ceremony

Same broker-only shape as registration. Sequence:

```
mssh-ca                  mssh-passkey                    user's phone
                          (broker)
   │                          │                                │
   │ webauthn.generate_       │                                │
   │ authentication_options(  │                                │
   │   rp_id, challenge=...,  │                                │
   │   allow_credentials=     │                                │
   │     alice's credential   │                                │
   │     IDs from enrollment  │                                │
   │     DB)                  │                                │
   │ → options_json,          │                                │
   │   challenge_bytes        │                                │
   │ (mssh-ca stores ceremony │                                │
   │  metadata + description  │                                │
   │  locally, keyed by       │                                │
   │  ceremony_id)            │                                │
   │                          │                                │
   │ POST /broker/ceremony    │                                │
   │ (mTLS)                   │                                │
   │ {type: "approve",        │                                │
   │  options_json,           │                                │
   │  description, ttl,       │                                │
   │  callback_url}           │                                │
   ├─────────────────────────►│                                │
   │                          │ INSERT ceremonies row          │
   │                          │                                │
   │ {ceremony_id, url}       │                                │
   │◄─────────────────────────┤                                │
   │                          │                                │
   │                          │ GET /approve/<ceremony_id>     │
   │                          │◄───────────────────────────────┤
   │                          │                                │
   │                          │ HTML page: description +       │
   │                          │ "Approve" / "Deny" buttons     │
   │                          │ options_json embedded for JS   │
   │                          ├───────────────────────────────►│
   │                          │                                │
   │                          │                  navigator.    │
   │                          │                  credentials.  │
   │                          │                  get(options)  │
   │                          │                  → biometric   │
   │                          │                                │
   │                          │ POST /approve/<id>/respond     │
   │                          │ {credentialId, authData,       │
   │                          │  clientDataJSON, signature}    │
   │                          │◄───────────────────────────────┤
   │                          │                                │
   │                          │ UPDATE ceremony:               │
   │                          │   response_json, outcome=      │
   │                          │   "approved", consumed_at      │
   │                          │                                │
   │                          │ (broker DOES NOT verify;       │
   │                          │  it just stores + relays)      │
   │                          │                                │
   │                          │ {ok: true}                     │
   │                          ├───────────────────────────────►│
   │                          │                                │
   │                          │ (HTML: "Submitted")            │
   │                          │                                │
   │ POST callback_url        │                                │
   │ (mTLS)                   │                                │
   │ {ceremony_id,            │                                │
   │  outcome: "approved",    │                                │
   │  response_json}          │                                │
   │◄─────────────────────────┤                                │
   │                          │                                │
   │ webauthn.verify_         │                                │
   │ authentication_response( │                                │
   │   response,              │                                │
   │   expected_challenge,    │                                │
   │   expected_rp_id,        │                                │
   │   expected_origin,       │                                │
   │   credential_public_key, │                                │
   │   credential_current_    │                                │
   │     sign_count)          │                                │
   │ • signature valid?       │                                │
   │ • origin match?          │                                │
   │ • counter > previous?    │                                │
   │                          │                                │
   │ If all pass:             │                                │
   │   UPDATE alice's         │                                │
   │   credential sign_count  │                                │
   │   + last_used_at         │                                │
   │   APPROVE the original   │                                │
   │   high-privilege op      │                                │
   │ Else: refuse, log,       │                                │
   │   alert                  │                                │
   │                          │                                │
   ├─────────────────────────►│  200 OK                        │
```

### Denial path

User clicks "Deny" on the approval page → `POST /approve/<id>/deny`
(no WebAuthn ceremony). Broker marks the ceremony
`outcome = "denied"` and POSTs the callback. mssh-ca refuses the
original operation.

### Expiry

A background sweeper in the broker runs every 30 seconds:

  1. `UPDATE ceremonies SET outcome = 'expired', consumed_at = NOW()
     WHERE outcome IS NULL AND expires_at < NOW()`
  2. For each newly-expired ceremony, schedule a callback POST
     with `outcome: "expired"`.

mssh-ca also has its own TTL on the original operation; if the
ceremony expires, mssh-ca cancels the pending op.

### Counter validation lives in mssh-ca

Each authenticator maintains a monotonic counter incremented on
every signature. A counter that goes backwards or stays equal is
a clone-detection signal — mssh-ca's
`verify_authentication_response()` call enforces this against the
sign-count it stored for that credential. Broker never sees the
counter; broker doesn't care.

> **Decision needed:** auto-revoke on counter regression vs alert
> only? v1 chose alert-only on the mssh-ca side because some
> legit authenticators (especially platform credentials) don't
> increment monotonically. Operator runbook: investigate the
> alert manually.

---

## 5. Broker API surface (mTLS)

All `/broker/...` endpoints require an mTLS client cert.
Authorization is by CN match against an allowed-clients list in
config. The broker is dumb on purpose — only three endpoints, no
user / credential / allowlist surface (those live in mssh-ca).

### `POST /broker/ceremony`

Create a new ceremony. Used for both registration AND approval —
the back-end client decides which by setting `type`.

Request:
```json
{
  "type": "register",                    // or "approve"
  "options_json": "{...}",               // the back-end-client-built
                                         // PublicKey*Options blob; opaque
                                         // to the broker
  "description": "Register a new authenticator for alice",
  "display_name": "Alice Example",       // shown on the page
  "ttl_seconds": 300,
  "callback_url": "https://mssh-ca.internal:8443/v1/admin/passkey/callback"
}
```

Response (201):
```json
{
  "ceremony_id": "8c3e2f4b-...",
  "url": "https://passkey.example.com/approve/8c3e2f4b-...",
  "expires_at": "2026-05-20T18:35:00Z"
}
```

The `url` shape: `/register/<id>` for type `register`,
`/approve/<id>` for type `approve`.

Errors:
- 400 missing fields, malformed JSON, bad ceremony_type, bad URL
- 401 mTLS cert missing or not in allowed-clients list
- 503 broker can't reach its DB

### `GET /broker/ceremony/<ceremony_id>`

Query a ceremony's current state. Used by back-end clients as a
poll fallback when the callback hasn't arrived.

Response:
```json
{
  "ceremony_id": "8c3e...",
  "type": "approve",
  "outcome": "approved",                 // null | "approved" | "denied" | "expired"
  "consumed_at": "2026-05-20T18:32:10Z",
  "response_json": "{...}",              // present iff outcome="approved" or "denied"
  "callback_status": "delivered"         // null | "pending" | "delivered" | "failed_max_retries"
}
```

`outcome` is `null` while the ceremony is pending.

### `DELETE /broker/ceremony/<ceremony_id>`

Cancel an in-flight ceremony. Back-end client uses this if it
needs to revoke the pending operation before the user acts. Sets
`outcome = "expired"`; if the user navigates to the URL after
cancellation, they see "this ceremony was cancelled by the
operator." Callback is NOT fired for cancellations — the cancelling
client already knows.

### No `/broker/credentials` endpoint

The broker has no per-user state. Listing alice's credentials,
labeling them, revoking them — all happens at mssh-ca through
the existing user-enrollment CRUD path. The broker doesn't even
know who alice is.

### No `/admin/reload-allowlist` endpoint

The AAGUID allowlist lives at mssh-ca; reloading it is an mssh-ca
operation, not a broker concern.

### Public (non-mTLS) endpoints

These are the routes the user's browser actually hits — no mTLS,
ordinary HTTPS:

  - `GET  /register/<ceremony_id>`    — render the registration page
  - `POST /register/<ceremony_id>/respond` — receive the WebAuthn response
  - `GET  /approve/<ceremony_id>`     — render the approval page
  - `POST /approve/<ceremony_id>/respond`  — receive the WebAuthn response
  - `POST /approve/<ceremony_id>/deny`     — explicit denial (no WebAuthn)
  - `GET  /`                          — static landing page

None of these need auth — the unguessable ceremony_id IS the
auth. Token discovery is the security boundary: if you know the
URL, you can attempt the ceremony. (One-time use enforced by
`consumed_at`; TTL enforced by sweeper.)

---

## 6. Callback delivery

mssh-passkey notifies the back-end client when a transaction
reaches a terminal outcome (`approved` | `denied` | `expired`).

### Webhook semantics

POST to the `callback_url` recorded at challenge-creation time.
Body:

```json
{
  "transaction_id": "8c3e…",
  "outcome": "approved",
  "verified_at": "2026-05-20T18:32:10Z",
  "credential_id": "Yj9q…",
  "user_id": "alice"
}
```

The POST is mTLS-authenticated: mssh-passkey presents its own
mTLS client cert (separate from its public TLS server cert) so
the receiving back-end client can verify "this callback really
came from passkey".

### Retry policy

| Attempt | Delay before retry |
|---|---|
| 1 | Immediate after outcome |
| 2 | 5 seconds |
| 3 | 30 seconds |
| 4 | 2 minutes |
| 5 | 10 minutes |
| Final | mark `callback_status = "failed_max_retries"` and stop |

Idempotency: each callback carries the `transaction_id` as a
natural idempotency key. Back-end clients should deduplicate on
that.

### Poll fallback

Back-end clients can `GET /broker/status/<transaction_id>` at any
time. Recommended pattern: client schedules a poll at `expires_at`
(or a few seconds before) to catch the outcome if the webhook
hasn't arrived. v1 mssh-ca will implement this.

---

## 7. Browser pages

Flask templates + Bootstrap 5 (CDN-loaded, mirrors the
msshd-admin-web pattern). Three pages, minimal client JS.

### `/register/<token>`

Page shown when a user clicks the registration URL.

```
┌──────────────────────────────────────────┐
│  mssh-passkey — register a new credential │
├──────────────────────────────────────────┤
│                                          │
│  Account:  alice                         │
│  Display:  Alice Example                 │
│                                          │
│  This URL is one-time use.               │
│  Expires in: 4:23                        │
│                                          │
│  [ Register this device ]                │
│                                          │
└──────────────────────────────────────────┘
```

JS flow on button click:

  1. `POST /register/<token>/begin` → receive options
  2. `navigator.credentials.create(options)`
  3. `POST /register/<token>/finish` with the credential
  4. Show success / error

### `/approve/<txn_id>`

Page shown when a user clicks the approval URL.

```
┌──────────────────────────────────────────┐
│  mssh-passkey — approve operation         │
├──────────────────────────────────────────┤
│                                          │
│  Account:  alice                         │
│  Request:                                │
│    "Revoke admin cert for bob            │
│     (serial abc123)"                     │
│                                          │
│  Expires in: 4:42                        │
│                                          │
│  [ Approve ]    [ Deny ]                 │
│                                          │
└──────────────────────────────────────────┘
```

JS flow on Approve:

  1. `POST /approve/<txn_id>/begin` → receive options with
     `allowCredentials` for alice's registered credentials
  2. `navigator.credentials.get(options)`
  3. `POST /approve/<txn_id>/finish` with the assertion
  4. Show success / error

### `/` (root)

Static landing page: title, link to operator docs, version.
No interactive content; the URLs above are the only
user-reachable functionality.

### Error states

  - Token expired / consumed → "This link has expired or already
    been used. Ask your operator for a new one."
  - WebAuthn not supported → "This browser doesn't support
    WebAuthn. Use a recent Chrome or Safari on iOS / Android."
  - AAGUID not in allowlist → "This authenticator isn't approved
    for this deployment. Contact your operator."
  - Counter regression → "Authentication failed (replay
    detected). Contact your operator."

---

## 8. Deployment shape

### Runtime

Python 3.11+. Same baseline as mssh-ca.

### Process model

**Production: Apache2 + mod_ssl + mod_wsgi in front of Flask.**
Apache2 handles all TLS termination + mTLS client validation;
the Flask app sees plain HTTP on a localhost socket and reads
the validated client identity from request headers Apache2
populates.

```
                Public internet
                       │
                       │  HTTPS :443  (browser)
                       │  mTLS  :8443 (back-end clients)
                       ▼
              ┌────────────────────────────┐
              │   Apache2 + mod_ssl        │
              │                            │
              │  VirtualHost :443          │
              │   ServerName passkey.…     │
              │   SSLCertificateFile …     │  ← public CA cert
              │   ProxyPass / http://…/    │     (Let's Encrypt)
              │                            │
              │  VirtualHost :8443         │
              │   ServerName passkey.…     │
              │   SSLCertificateFile …     │  ← operator's mTLS
              │   SSLVerifyClient require  │     server cert
              │   SSLCACertificateFile …   │
              │   ProxyPass /broker/ http: │
              │   RequestHeader set        │
              │     X-Client-CN %{SSL_     │  ← passes verified CN
              │     CLIENT_S_DN_CN}s       │     to Flask
              └────────────┬───────────────┘
                           │
                  localhost:5000 (HTTP, no TLS)
                           │
                           ▼
              ┌────────────────────────────┐
              │   Flask app (mssh-passkey) │
              │                            │
              │   • routes /register/…     │
              │   • routes /approve/…      │
              │   • routes /broker/…       │
              │     (check X-Client-CN     │
              │      against allowed list) │
              └────────────────────────────┘
```

**Dev / adhoc-lab: Werkzeug dev server, no Apache2.** The Flask
app runs its own dual TLS listeners (HTTPS for browser, mTLS
for broker) — same Python code path, just configured to
terminate TLS itself. This keeps the lab self-contained
without an Apache2 dependency in the container.

The two modes share the application logic; only the front-end
differs. The config knob is `front_end: apache | dev`:

```yaml
# Production
front_end: apache
listen:
  bind: 127.0.0.1
  port: 5000             # plain HTTP, Apache2 owns TLS

# Dev / adhoc-lab
front_end: dev
listen:
  public_https: …        # dual TLS handled in-process
  broker_mtls:   …
```

### Apache2 → Flask identity propagation

When `front_end: apache`:

  - The Flask app reads `request.headers["X-Client-CN"]` for the
    verified back-end client identity. Set unconditionally by
    Apache2 to whatever `SSL_CLIENT_S_DN_CN` is.
  - For non-mTLS routes (the browser-facing `/register/…` and
    `/approve/…`), Apache2 doesn't populate the header, so its
    absence is the dev signal "this request didn't go through
    the mTLS VirtualHost".
  - The Flask app refuses any `/broker/…` request that doesn't
    carry a populated `X-Client-CN`. This guards against an
    Apache2 misconfiguration where the broker port accidentally
    accepts un-validated clients.
  - The Flask app additionally checks the CN against
    `allowed_client_cns` from its own config — defense in depth.

### Trust + cert distribution at deploy time

In production:

  - Apache2's `:443` cert: Let's Encrypt (`certbot --apache`)
    or the operator's web-PKI choice. Operator-managed; not in
    mssh-passkey's scope.
  - Apache2's `:8443` cert: signed by the operator's internal
    TLS hierarchy. Issued by `mssh-admin cert mint --type
    tls-server --cn passkey.internal.example.com --san DNS:…`
    when mssh-ca runs the operator's PKI; or by any other
    internal CA otherwise.
  - Apache2's mTLS client trust root (`SSLCACertificateFile`):
    the CA cert that signed the back-end clients' (e.g.
    mssh-ca's) broker-client certs.

### Systemd unit

```ini
[Unit]
Description=mssh passkey broker
After=network-online.target

[Service]
ExecStart=mssh-passkey --config /etc/mssh-passkey/config.yaml
Restart=on-failure
User=mssh-passkey
WorkingDirectory=/var/lib/mssh-passkey

[Install]
WantedBy=multi-user.target
```

`mssh-passkey` is the Flask app; Apache2 has its own unit.

### Config

`/etc/mssh-passkey/config.yaml`. Two layouts depending on
`front_end`:

#### Production (Apache2)

```yaml
front_end: apache

listen:
  bind: 127.0.0.1
  port: 5000              # plain HTTP; Apache2 fronts with TLS

# Apache2 sets X-Client-CN from SSL_CLIENT_S_DN_CN; Flask checks
# against this list.
allowed_client_cns:
  - "mssh-ca"
  # Additional back-end consumers can be added here.

# Callback delivery: cert mssh-passkey presents when calling
# back-end clients' callback URLs. Flask handles this directly
# (Apache2 isn't in the outbound path).
callback:
  client_cert: /etc/mssh-passkey/tls/callback-cert.pem
  client_key:  /etc/mssh-passkey/tls/callback-key.pem
  ca_cert:     /etc/mssh-passkey/tls/callback-ca.pem  # verifies back-end client TLS

rp:
  # WebAuthn RP ID — must match the public hostname.
  rp_id:   passkey.example.com
  rp_name: "mssh passkey broker"
  expected_origins:
    - https://passkey.example.com

database:
  path: /var/lib/mssh-passkey/state.db

aaguid_allowlist:
  path: /etc/mssh-passkey/aaguid-allowlist.yaml
  require_allowlist: true       # production default
```

#### Dev / adhoc-lab (Werkzeug in-process TLS)

```yaml
front_end: dev

listen:
  public_https:
    host: 0.0.0.0
    port: 8000
    cert: /etc/mssh-passkey/tls/public-cert.pem
    key:  /etc/mssh-passkey/tls/public-key.pem

  broker_mtls:
    host: 0.0.0.0
    port: 8443
    cert: /etc/mssh-passkey/tls/broker-cert.pem
    key:  /etc/mssh-passkey/tls/broker-key.pem
    client_ca_cert: /etc/mssh-passkey/tls/client-ca.pem

allowed_client_cns:   # same list in both modes
  - "mssh-ca"

# (callback + rp + database + aaguid_allowlist unchanged from above)
```

### Apache2 config sketch (production)

A minimal reference `/etc/apache2/sites-available/mssh-passkey.conf`
the operator drops in:

```apache
<VirtualHost *:443>
    ServerName passkey.example.com
    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/passkey.example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/passkey.example.com/privkey.pem

    ProxyPreserveHost On
    ProxyPass        /  http://127.0.0.1:5000/
    ProxyPassReverse /  http://127.0.0.1:5000/
</VirtualHost>

<VirtualHost *:8443>
    ServerName passkey.example.com
    SSLEngine on
    SSLCertificateFile      /etc/mssh-passkey/tls/broker-cert.pem
    SSLCertificateKeyFile   /etc/mssh-passkey/tls/broker-key.pem

    # Require + validate back-end client mTLS.
    SSLVerifyClient         require
    SSLVerifyDepth          2
    SSLCACertificateFile    /etc/mssh-passkey/tls/client-ca.pem

    # Pass the verified CN to Flask. Flask refuses /broker/*
    # requests without it.
    RequestHeader set X-Client-CN "%{SSL_CLIENT_S_DN_CN}s"

    # Only the broker + admin paths reach Flask on this VHost.
    ProxyPass        /broker/  http://127.0.0.1:5000/broker/
    ProxyPassReverse /broker/  http://127.0.0.1:5000/broker/
    ProxyPass        /admin/   http://127.0.0.1:5000/admin/
    ProxyPassReverse /admin/   http://127.0.0.1:5000/admin/
</VirtualHost>
```

mod_wsgi is an alternative to mod_proxy_http if the operator
prefers in-process Python — both work. The reference config
uses ProxyPass for clarity and to keep the Flask process
unprivileged.

### Adhoc-lab integration

A new LXC container (`mssh-passkey`) in the adhoc lab:

  - Provisioned alongside the CA via the test framework.
  - mTLS broker port reachable from the CA container.
  - Public HTTPS port forwarded to the host so a real phone can
    register via the host's IP for hand testing.
  - Self-signed certs minted by the lab's existing PKI helpers
    (mTLS chain) + an explicit dev TLS cert for the public port
    (browsers will warn — accept the dev cert for testing).

---

## 9. Threat-model carry-over

Carries over from
[browser.md § WebAuthn](browser.md#webauthn-with-hardware-only-authenticators--the-cleaner-path)
and
[passkey-design-document.md](passkey-design-document.md):

  - **Public-CA TLS attack surface on the browser-facing port:**
    real. Public CAs can in principle misissue
    `passkey.example.com`. Mitigations: HSTS preload, CAA records,
    Certificate Transparency monitoring. This is the operator's
    responsibility to set up at deploy time (in production, on
    the Apache2 VirtualHost — `mssh-passkey` doesn't terminate
    TLS itself).
  - **Apache2 misconfiguration risk:** in production the Flask
    app trusts `X-Client-CN` set by Apache2 for mTLS identity. A
    misconfigured VirtualHost that exposes the broker port
    without `SSLVerifyClient require`, or that lets an attacker
    set `X-Client-CN` directly, breaks the trust chain.
    Mitigations:
      - The Flask app refuses any `/broker/…` request that
        doesn't carry `X-Client-CN`. A misconfig that fails to
        set it fails closed.
      - The Flask app additionally checks the CN against
        `allowed_client_cns` (defense in depth — an attacker
        who somehow set X-Client-CN to an unknown value still
        fails authorization).
      - Operator runbook: production deployment validation
        includes a "make sure unauthenticated `:8443` requests
        get 403 from Apache2 before reaching Flask" smoke test.
  - **Hardware-bound-only enforcement:** the AAGUID allowlist
    rejects iCloud-Keychain-synced passkeys + software-only
    platform authenticators. Production deployments MUST set
    `require_allowlist: true`.
  - **mTLS client cert leak on the broker port:** if mssh-ca's
    broker-client cert is stolen, the attacker can mint
    arbitrary transactions. Mitigation: same custody as any
    high-value mTLS key; rotate quickly on suspicion. mssh-ca
    audit log records every broker call.
  - **Callback URL forgery:** if an attacker can intercept the
    DNS for the callback URL, they can deliver a fake
    `approved` outcome. Mitigation: mssh-passkey's callback POST
    uses mTLS and verifies the back-end client's TLS server cert
    against `callback.ca_cert`. Both directions are
    cryptographically authenticated.
  - **Stolen phone (unlocked):** WebAuthn requires biometric per
    operation if `userVerification: required` is set. v1 sets
    this in `PublicKeyCredentialCreationOptions.authenticator-
    Selection.userVerification = "required"`.

### What mssh-passkey is NOT responsible for

  - Back-end policy decisions ("does alice's role require 2FA on
    this op?"). That's the back-end client's call; mssh-passkey
    just provides the ceremony.
  - Long-lived session management. Each transaction is one-shot.
  - Per-user rate limiting beyond a coarse default
    (10 transactions/minute/user, configurable). Back-end
    clients can apply their own.

### Hardening v2 — defending against a compromised broker (deferred)

> **Status:** captured for v2; not in first-pass scope.

A compromised broker has limited blast radius (it holds no keys
and cannot fabricate ceremonies), but its callback-side interface
to mssh-ca is still an attack surface. A pwned broker can attempt:

  - **Injection attacks** against mssh-ca's callback handler.
    `response_json` is opaque bytes from the broker's perspective
    but parsed by mssh-ca; mssh-ca must treat it as untrusted
    input. Concrete vectors: oversized payloads (memory DoS),
    deeply-nested JSON (parser stack DoS), unexpected fields, or
    cleverly-crafted base64url blobs aimed at the underlying
    crypto parsers.
  - **Bogus callbacks**: callback for an unknown ceremony_id;
    callback for a ceremony that hasn't been issued; callback
    with a ceremony_id that mssh-ca DID issue but with a tampered
    outcome / response_json.
  - **Slow-loris / connection-exhaustion** against mssh-ca's
    inbound callback listener.
  - **TLS downgrade or stripped mTLS** if Apache2 (or whatever
    fronts mssh-ca) is misconfigured.

mssh-ca's v2 hardening requirements:

  1. **Strict, bounded parsing on `response_json`.** Enforce a hard
    size cap (e.g. 64KB) before JSON decode. Reject any field not
    on a whitelist. Reject nested objects beyond a fixed depth.
    Use streaming parsers where available; avoid `json.loads`
    blocking on a 100MB payload.
  2. **Callback authenticity check.** Every incoming callback
    must reference a ceremony_id mssh-ca actually issued AND must
    arrive within an expected wall-clock window. Replays of stale
    callbacks rejected.
  3. **mTLS pinning to the broker's identity cert.** The TLS
    handler verifying the inbound callback's client cert pins
    against a specific cert fingerprint, not just "chain
    validates." A compromised broker that retains its cert can
    still call back, but a broker rotated to a fresh attacker-
    held cert (impossible without the broker's key but...) is
    refused.
  4. **2FA fail-state.** If mssh-ca detects multiple suspicious
    callback events in a short window (oversized payloads,
    unknown ceremony_ids, tampered responses, etc.), it enters a
    **2FA fail-state**: every subsequent operation requiring 2FA
    is refused, regardless of whether a fresh callback would
    actually succeed. The fail-state is operator-cleared via an
    out-of-band admin command (`mssh-admin passkey-broker
    reset --reason "..."`) that requires the operator to confirm
    they've investigated. Mirrors the
    "fail-closed-on-anomaly" pattern from the CRL-strict-mode
    gate.
  5. **Rate-limit + anomaly detection.** Per-ceremony callbacks
    capped at 1 (idempotency on transaction_id). Per-source
    callbacks capped at a sensible rate.
  6. **Independent observability.** mssh-ca's audit log records
    every callback (delivered + rejected) with full context.
    Operators can spot a wave of suspicious activity even if
    individual rejected requests didn't trip the fail-state.

Carries no impact on the broker module — these are entirely
defenses inside mssh-ca's callback receiver. The broker design
is unchanged; what changes is what mssh-ca trusts about the
broker's output.

---

## 10. Test strategy

### Unit tests

  - Storage round-trip (CRUD on each table).
  - AAGUID allowlist parsing + reload.
  - Token TTL enforcement (consumed-tokens, expired-tokens).
  - Counter regression detection.
  - Callback retry scheduling.

### Integration tests

  - Stub back-end client (mTLS) calls `/broker/register` → token
    is returned → token URL works → ceremony completes → callback
    fires.
  - Same for `/broker/challenge` → approve flow.
  - Same for deny flow.
  - Same for expiry sweeper.
  - Wrong-mTLS-CN gets 401 on broker endpoints.
  - WebAuthn ceremonies driven by `webauthn`'s test helpers
    (`generate_registration_response_for_testing`, similar). No
    real authenticator needed; the library provides synthetic
    ones with known keypairs.

### Smoke tests

  - Service starts with example config.
  - Public landing page returns 200.
  - mTLS broker port refuses unauthenticated GETs.

### Adhoc-lab tests

  - End-to-end test where a stub mssh-ca pushes a challenge to
    the lab's mssh-passkey container, a synthetic browser
    completes the WebAuthn ceremony, callback delivers, mssh-ca
    sees the outcome.
  - Real-phone manual smoke: a developer can scan a QR from a
    `mssh-admin user passkey enroll` invocation and complete the
    ceremony against the host-forwarded public port. Documented
    in the adhoc-lab README.

---

## Open decisions (consolidated)

For convenience, the open decisions marked above:

1. **Recovery flow** — v1: operator-mediated revoke + re-enroll.
   v2 may add explicit recovery codes.
2. **Counter regression handling** — v1: alert only. v2 may
   auto-revoke.
3. **`POST /admin/reload-allowlist` authorization** — v1: mTLS
   CN check (only the operator's admin cert).
4. **Multi-device enrollment** — v1: operator mints a fresh
   registration token. v2 may add authenticate-then-register.
5. **AAGUID allowlist location** — broker-side per deployment
   (decided, recorded above).
6. **Callback push vs poll** — hybrid, push primary with poll
   fallback (decided).
7. **Public HTTPS port cert authority** — operator's choice
   (Let's Encrypt typical); mssh-passkey doesn't ship its own
   public-PKI mint capability (it's a consumer, not an issuer).

---

## LOC estimate

| Piece | LOC |
|---|---|
| Storage (SQLite + schema migrations) | 250 |
| WebAuthn RP adapters (around `webauthn` lib) | 200 |
| Broker API endpoints (mTLS) | 200 |
| Browser pages (Flask + Bootstrap 5 templates + small JS) | 200 |
| Dual-listener wiring + config | 100 |
| Callback delivery + retry | 150 |
| Sweeper + counter validation | 80 |
| Service main + CLI (`mssh-passkey serve`) | 80 |
| mssh-ca client + admin handlers | 250 |
| Adhoc-lab integration (container provisioning) | 100 |
| **Total v1** | **~1610** |
| Tests | ~500 |

Larger than initial sketches because the storage + ceremony
machinery is real, not just plumbing. Still bounded — no
recovery-code crypto, no Argon2 vault, no high-availability
clustering in v1.
