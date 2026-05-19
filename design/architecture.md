# mssh — architecture

mssh is a runtime, CA-mediated SSH authorization system. SSH client
identity and credentials don't change; **authorization** moves out
of the client and into a CA on a separate, restricted network. The
server contacts the CA at connection time and gets a short-lived
authorization decision back.

The defining property: **a stolen client credential is useless if
the attacker can't reach the CA.** Put the CA on a network reachable
only from your SSH servers; stolen keys can't trigger authorization
from anywhere else.

---

## Components

```
                       ┌──────────────────┐
                       │      CA           │
                       │  • policy engine  │
                       │  • cert minter    │
                       │  • enrollment DB  │
                       │  • audit log      │
                       └────────┬─────────┘
                                │  mTLS REST
                                │
   ┌─────────────────────────────┼─────────────────────────────┐
   │                             │                              │
   │  ┌────────────────────────┴──────────────────────────┐    │
   │  │                       msshd                        │    │
   │  │  • outer listener (mTLS to mssh clients)           │    │
   │  │  • per-connection CA call                          │    │
   │  │  • ephemeral OpenSSH cert mint (local user-CA)     │    │
   │  │  • hermetic inner sshd                             │    │
   │  └──────────────────────────────────────────────────┬─┘    │
   │                                                       │      │
   └──────── mTLS+JSON-frame outer protocol ──────────────┘      │
                                ▲                                 │
                                │                                 │
                          ┌─────┴────┐                            │
                          │   mssh    │                           │
                          │  client   │                           │
                          └──────────┘                            │
                                                                   │
                          ┌──────────────┐                         │
                          │  mssh-admin   │ mTLS REST              │
                          │  (CLI)        │────────────────────────┘
                          └──────────────┘
```

There are five distinct pieces. Two are user-facing, three are
infrastructure.

### CA

The central authorization service. mTLS-only REST API. Three
responsibilities:

  - **Authorize:** evaluate an authorization request against
    enrollment + policy, mint a short-lived X.509 cert if the
    answer is yes.
  - **Enroll:** maintain the inventory of servers, users, keys,
    policies via the admin API.
  - **Audit:** log every authorization decision and every admin
    action to an append-only JSON-Lines file.

The signing key never leaves the CA host. The CA is typically
deployed on a private network reachable only from your SSH servers
and your admin workstations.

### `mssh` (client)

Pure-Python TLS client. Reads an X.509 client cert + key + trust
root from `$HOME/.mssh/` (or env vars), opens a TLS connection to
msshd, presents an mTLS client cert, sends a JSON-framed
session-RPC header, and from there acts like a standard SSH client.

### `msshd` (server-side gateway)

The outer-facing server. Terminates the mTLS+JSON-frame outer
protocol from mssh clients, calls the CA to authorize the
connection, mints an ephemeral OpenSSH user cert with a local
user-CA, hands the cert to a **hermetic inner sshd** that it
owns, and proxies the byte stream end-to-end-encrypted.

The inner sshd is a **stock unmodified OpenSSH** instance launched by
msshd with a generated, locked-down `sshd_config` (see
[§ Hermetic inner sshd](#hermetic-inner-sshd)). msshd manages its
lifecycle; the operator never edits the inner config directly.

**Why native OpenSSH (not a Python SSH server) for production:** the
SSH protocol implementation we ship in production has to be the one
the wider world has spent decades hardening — OpenSSH (or, on size-
constrained targets, Dropbear). msshd's hermetic config uses OpenSSH's
own auth machinery and cert validation. We deliberately do **not** ship
a Python SSH server in the production data path.

msshd supports three modes ([§ Operating modes](#operating-modes)).

### `mssh-admin` (CLI)

Operator CLI for the CA's admin API. Enrols servers, users, keys,
and policies; rotates certs; runs audits. mTLS-authenticated with
role-based access control (`superuser`, `admin`, `auditor`).

### `debug_sshd` — NOT for production

A Python AsyncSSH-based server that calls the CA inline after pubkey
auth. **Not a production deployment target.** It exists exclusively
as a debugging affordance: when something in the CA → cert →
authorization path misbehaves, `debug_sshd` lets you stand up a
diagnostic SSH server with structured, verbose logging of every step
the auth path takes, so you can see exactly which check failed.

It is intentionally a **smaller** SSH implementation than OpenSSH —
the trade is "less complete protocol surface, easier to instrument."
Several SSH features (full PTY mode quirks, X11 forwarding, agent
forwarding, certain cipher suites) are best-effort or missing in
debug_sshd. **If something works in debug_sshd but not in production
msshd**, that's a debug_sshd limitation, not a bug in production.
**If something works in production but breaks in debug_sshd**, treat
it as a debug_sshd issue first.

The adhoc lab's "debug" tier (`./setup_adhoc.sh debug`) is what spins
up this server. The default `./setup_adhoc.sh` (no argument) uses the
production msshd + hermetic OpenSSH path.

---

## Operating modes

`msshd` supports three modes selected at config time. Two are
implemented today; one is a deferred design (see
[design/future-ideas.md](future-ideas.md) §gated).

| Mode | Outer auth (mssh→msshd) | Inner auth (msshd→sshd) | Whose policy wins | Status |
|---|---|---|---|---|
| **fallback** | none — TCP proxy | the operator's existing sshd_config | the operator | implemented |
| **gated** | mTLS + CA approval | the operator's existing sshd_config | the operator, gated by CA | deferred |
| **enforce** | mTLS + CA approval + ephemeral cert minted | hermetic minimal sshd_config (trusts only the mint key) | the CA | implemented |

The intended adoption journey is **fallback → gated → enforce**,
each step reversible by a single config flag. Operators can
preserve their existing sshd policy as long as they want and
flip to CA-mediated auth on their schedule. See
[docs/operations.md § adoption journey](../docs/operations.md#the-adoption-journey).

### Why three modes (not just enforce)

Operators have years of accumulated policy in `/etc/ssh/sshd_config`,
`authorized_keys`, PAM, AllowGroups. Flipping straight from "vanilla
sshd" to "CA does everything" on day one is the highest-risk
moment in any adoption. The three modes give the operator
intermediate states where they can verify the gateway is wired in
correctly (fallback), then introduce CA-gating without changing
auth (gated), then move full policy to the CA (enforce) on a
per-server schedule.

---

## Hermetic inner sshd

In **enforce** mode, msshd doesn't trust the operator's
`/etc/ssh/sshd_config`. It launches its own sshd subprocess against
a config it controls, with these invariants:

  - listens only on localhost (msshd is the only client)
  - accepts only ed25519 + ecdsa-p256, AEAD ciphers only
  - accepts only pubkey auth, only via `TrustedUserCAKeys` pinned
    to msshd's local user-CA
  - has no PAM, no Include directives, no Match blocks
  - logs to msshd's stderr (no syslog, no separate log files)

The inner sshd has **two lifecycle modes**, selected by
`wrapper.yaml`'s `inner.mode`:

  - **long-lived** (default) — one inner sshd at msshd boot,
    rendered once from a fixed template, serving every session
    afterward. No per-session policy variability in the sshd_config
    itself; per-session policy is enforced at the OpenSSH cert
    layer (principals, critical options, force-command). Lowest
    overhead; matches msshd's pre-1.1 behavior.
  - **per-connection** — fresh sshd per session. The
    `inner_sshd_config` is rendered by the **CA** as part of the
    authorize response, with policy directives (`ForceCommand`,
    `SetEnv`, forwarding flags, per-user banner) baked in by the
    CA's template engine. msshd substitutes its own `{LOCAL_*}`
    paths (port, host key, user-CA pubkey, banner file), runs
    `sshd -t` as a sanity check, then spawns. ~50–100ms session
    overhead. Unlocks per-user banner substitution and
    OpenSSH-native enforcement of per-session policy without an
    application-layer policy translator on msshd.

Both modes guarantee the operator never edits the running config.
In long-lived mode, the config is a fixed artifact generated from
mssh's shipped template plus msshd-local paths. In per-connection
mode, the rendered config is a **CA-signed artifact** (signed by
the same authorize-response signing as the X.509 authz cert) —
making the inner sshd config policy versioned and audited at the
CA, not on each msshd host.

This is the safety net: even if msshd has a bug in its
authorization decision, the hermetic sshd cannot accept any
credential msshd did not just mint. There is no other trust path
into the inner sshd.

**Recovery when the CA is unreachable.** Per-connection mode
depends on the CA to render the config. To keep break-glass
recovery from depending on the CA being up, msshd ships a local
**emergency template** (`/usr/share/mssh/sshd_config.emergency.template`,
optional operator override at `/etc/mssh/sshd_config.emergency.template`)
that uses only `{LOCAL_*}` markers. When the CA is unreachable and
an emergency cert is configured, msshd renders the emergency
template locally and spawns the per-session sshd from it — same
safe-by-default posture as a normal hermetic config, but with no
per-session policy. The path is rate-limited per
[security.md](security.md) "emergency cert". Operators whose
break-glass story is simpler (system sshd on a different port)
should leave the emergency cert unconfigured and use `mode:
fallback` instead.

---

## Trust model

Two distinct certificate hierarchies, intentionally separate:

  - **CA's signing key.** Lives only on the CA host. Mints the
    short-lived X.509 authorization certs that msshd reads. Also
    mints the mTLS client certs for each enrolled server and admin.
    Lost or compromised → re-enroll everything.
  - **msshd's local user-CA.** A separate keypair, one per msshd
    deployment. Used only to sign ephemeral OpenSSH user certs
    for the hermetic inner sshd. Never leaves the msshd host;
    rotation is cheap (mint a new pair, restart msshd, the inner
    sshd re-loads its `TrustedUserCAKeys`).

Two more certificates exist outside the CA's signing hierarchy:

  - **msshd's TLS server cert.** What msshd presents to mssh
    clients. Issued by a **user-facing CA** chosen by the
    operator (could be the mssh CA itself, could be a separate
    web-PKI CA — the choice is operational, not architectural).
  - **mssh client certs.** Issued by the same user-facing CA
    chosen above. mssh clients present these on TLS handshake;
    msshd verifies and forwards the certificate identity to the
    mssh CA for the authorization call.

Operators who want a fully self-contained deployment can use the
mssh CA for both the authorization hierarchy *and* the
user-facing hierarchy. Operators who want web-PKI for the
user-facing side can use a separate issuer. The mssh CA does not
care which.

---

## Wire protocols

  - **mssh ↔ msshd:** TLS 1.3 outer transport with mutual auth.
    Inside the TLS tunnel: a small JSON-framed session-RPC header
    (`{"version": 1, "user": "...", "command": [...]}`) followed
    by an encapsulated SSH transport stream. The JSON header lets
    msshd attribute the connection to a specific user identity
    without trusting an attacker-supplied SSH `user` field.

  - **msshd ↔ CA:** standard HTTPS with mutual TLS. `POST
    /v1/authorize` carries the connection context and identity
    blob; the response carries the X.509 authorization cert or
    a structured denial.

  - **mssh-admin ↔ CA:** same HTTPS + mTLS. Separate `/v1/admin/`
    URL prefix. Role-checked by the admin's certificate subject
    against the enrollment record.

  - **msshd ↔ inner sshd:** standard SSH transport. Localhost-only.

Concrete API: see [api.md](api.md).

---

## Failure model

Default behavior on every failure is **deny**:

  - CA unreachable: msshd denies the authorization. Optional
    emergency cert (long-lived, kept offline, restored manually)
    can override this for break-glass continuity.
  - Cert validation fails: deny.
  - Policy returns no match: deny.
  - Inner sshd refuses the ephemeral cert: connection closed.

mssh client never retries automatically against a different
endpoint with the same identity — the CA endpoint list in the
client config defines the failover order, and once all endpoints
are exhausted, the client fails.

---

## What's deliberately NOT in scope

  - **Password authentication.** Ever. Even as a fallback.
  - **Server-side per-user configuration.** Everything per-user is
    a CA enrollment, not a server-side file edit.
  - **mssh client agent forwarding by default.** The client cert
    binds to a specific session; forwarding it is a policy choice
    that must be explicitly enabled in the CA policy.
  - **Long-lived credentials.** Authorization certs are
    minute-scale. Identity certs (the user's mTLS cert) can be
    longer-lived but are still bounded.

See [security.md](security.md) for the threat model and
[future-ideas.md](future-ideas.md) for everything we've considered
adding later.


---

## Authz cache + bypass-cert (added 2026-05-18)

msshd has an in-memory + on-disk authz cache (one entry per
principal). On every incoming connection it checks the cache
first; on hit, no CA call. On miss, it calls the CA, stores the
result, uses it. The cache is the load-bearing structure for two
features:

  - **Reduced CA load.** Short-bursting connections from the same
    principal coalesce into one CA call.
  - **Operator break-glass.** An operator with an offline-stored
    *bypass cert* can `mssh --inject-bypass-cert <cert>` against
    a msshd whose CA is unreachable. msshd validates the cert
    (chain + bypass marker + principal match) and writes it
    directly into the cache. The operator's next normal `mssh`
    session hits the cache and succeeds — no CA call.

Cache entries are persisted on disk at
`<state_dir>/authz_cache.json` (mode 0600). Survives msshd
restarts so operators repairing across reboots don't have to
re-inject. See [security.md § Authz cache + bypass-cert + CRL](security.md#authz-cache--bypass-cert--crl-2026-05-18)
for the security analysis.

## CRL revocation channel (added 2026-05-18)

The CA maintains an append-only CRL log (`crl.jsonl`). Each entry
is `{seq, revoked_at, serials, revoked_by, reason}` — sequence
numbers monotonically increase. Every `/v1/authorize` response
carries the CA's current sequence number; msshd tracks the highest
sequence it has applied and fetches missing entries via
`GET /v1/crl?after=N&limit=K`. Applied entries invalidate matching
cache entries by serial — source-agnostic (bypass certs are
revocable the same as CA-granted certs).

Operators issue revocations via `mssh-admin cert revoke <serial>`.
Fleet propagation happens on each msshd's next authorize call.

A configurable strict-mode gate prevents serving from a stale
cache: if `(known_ca_seq - last_applied) > threshold`
(`ca.crl_strict_threshold`, default 50), msshd refuses cache hits
and forces live CA calls until catch-up. Set to 0 to disable.

## PKI hierarchy migration (in progress)

The CA is migrating from single-signer (one signing key for authz
certs + one TLS CA for mTLS certs) to a root + 4 named intermediates
hierarchy:

```
root  (mssh-root, self-signed, long-lived)
 ├── user-mint     — per-session authz certs
 ├── bypass-mint   — operator-presentable bypass certs
 ├── host-mint     — server identities (CA TLS, msshd mTLS)
 └── auth          — admin/client mTLS certs
```

Each intermediate has its own keypair and signs the leaves in its
role. Rotating one intermediate (e.g. bypass-mint) invalidates
its outstanding certs (chain breaks) without affecting any other
role. CRL state becomes per-issuer, keyed by
`<short-name>:<pubkey-fp16>`.

Migration is staged across several commits — see
[design/notes-pki-hierarchy.md](notes-pki-hierarchy.md) for the
phased plan + current status. Phase 1 (foundation: helpers,
dataclasses, backward-compat function signatures) has landed.
Bootstrap refactor + per-issuer CRL + msshd chain validation +
admin CLI commands land in subsequent commits.
