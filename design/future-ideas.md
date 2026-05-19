# mssh — future ideas

**Status:** Capture-only. Not on any current critical path.

Design ideas considered but deferred. Each entry has a rough sense
of scope and risk; none are committed work yet. They get promoted
to formal design docs (or merged into existing ones) when a
decision is made to build them.

See [architecture.md](architecture.md) for what's implemented today;
see [api.md](api.md) for the API contract; see [security.md](security.md)
for the trust model. Items below extend or compose with those.

---

## 2. Smart-card (PIV / PKCS#11) support

**Status:** Probably trivial. Investigate in a focused half-day.

### Idea

Three roles where smart-card backing materially improves the security
story:

1. **CA admins.** The bootstrap-admin cert (and any subsequent
   superuser admins) are highest-value targets. Backing them with a
   YubiKey / PIV card eliminates exfiltration-by-file-system-access.
2. **Wrapper's mTLS-to-CA key.** Today msshd holds this on disk
   (mode 0600). A PIV card means a compromised wrapper host can use
   the key WHILE compromised but can't exfiltrate it to use later.
3. **mssh client.** The user's mTLS cert is the most lateral-
   movement-relevant key in the system. PIV-backing it raises the
   bar significantly with near-zero UX cost on modern OSes.

### Approach

- Python's `cryptography` library doesn't speak PKCS#11 directly.
  Use `python-pkcs11` (10kLOC mature lib) OR shell out to `openssl`
  with a PKCS#11 engine for cert ops. Either is well-understood.
- mssh: add `--pkcs11-uri` flag and use `ssl.SSLContext`'s engine
  support to load the private key from the card. Browser-style.
- Wrapper: same approach for its mTLS-to-CA leg.
- CA admin CLI: same approach for admin certs.

### Cons

- Operator complexity. A PIV card lost is a key lost.
- The wrapper as a daemon can't prompt for a PIN; the card must be
  pre-unlocked or use a slot configured for no-PIN-required.

### Out of scope

Storing msshd's **local user-CA** signing key on a card —
that key signs ~30s-lived OpenSSH user certs at high volume. PIV
signing throughput (~10-50 ops/sec on commodity cards) might
bottleneck at burst-login time. Worth measuring before committing.

---

## 4. Wrapper supports protocols beyond SSH — HTTPS / TCP proxy

**Status:** Genuinely interesting; needs analysis.

### Idea

The wrapper's authentication path (mTLS client cert → CA call →
policy decision) is **protocol-agnostic**. Today it dispatches to an
inner SSH session, but it could just as easily dispatch to an inner
HTTP proxy, TCP forward, or anything else.

User-side experience: instead of `mssh alice@host -- whoami`, the
user opens a browser. The browser already speaks mTLS and already
stores the user's PIV-backed (or passkey-backed) cert. The wrapper
authenticates the browser session, calls the CA, gets a policy decision
for "access internal-tool.example.com", and proxies HTTPS to the
internal target.

Result: narrow-scoped, per-request-authorized access to internal
HTTPS services. No VPN tunnel ("everything I can route to from
this machine"), no broad SSH-based port forward — just "alice is
authorized to reach internal-tool today, from these IPs, in this
time window."

### Comparable products

- Cloudflare Access — same shape but cloud-hosted.
- Pomerium, Teleport's Application Access — open-source equivalents.
- BeyondCorp — Google's internal reference architecture.

We'd be cloning a pattern that has multiple production proofs of
concept. The differentiator: tight coupling with our existing
runtime-CA-mediated authorization model.

### Open design questions

- **Outer protocol.** Browsers don't speak our v1 JSON-framed thing
  — they speak HTTPS. The wrapper would need a separate listen path
  for HTTPS (port 443) where the outer protocol is HTTP/2, the
  client cert is presented in mTLS, and msshd's policy decision
  results in a proxied HTTP request to the inner target.
- **Per-request vs per-session authorization.** SSH gets a single
  authz at connection time. HTTP could authorize per-request (every
  call hits the CA) or per-session (one CA call, cached for N
  minutes). Per-request is more expensive but tighter; per-session
  matches the SSH model better.
- **Service discovery.** Where does "internal-tool.example.com" map
  to "msshd should proxy to https://10.0.0.42:8443"? Static
  config? Consul-style discovery? Out-of-scope-for-PoC.

### LOC estimate

Hard to say without design work. Likely 1-2k LOC for v1 — HTTPS
listener, request-level policy hooks, configurable backend routing,
session cookie handling.

---

## 5. The CA could mint certs for other applications (step-ca parallel)

**Status:** Architecturally trivial; worth doing once a real consumer asks.

### Idea

The CA already:
- Holds two signing keys (auth-signing for X.509 authz, mTLS-root for
  client-cert issuance).
- Has an enrollment DB with users / policies / RBAC.
- Has an audit log.
- Has an admin CLI.

This is **most of what step-ca offers** (https://smallstep.com/docs/step-ca/).
With modest additions it could mint:

- **TLS server certs for internal services.** "Issue a 30-day cert
  for grafana.internal.example.com" — same enrollment model, same
  policy DSL, same audit.
- **Code-signing certs.** Sign binaries with a cert traceable to a
  particular admin / build agent.
- **SSH user certs.** Today the CA mints X.509 authz certs for the
  shim/wrapper. It could also mint OpenSSH user certs directly,
  bypassing msshd for shops that just want better SSH
  certificate management.
- **mTLS certs for service-to-service.** Each microservice gets a
  cert from the CA; the CA's enrollment policy decides who's allowed
  to issue / renew.

### What we'd need to add

- New admin endpoints: `cert mint --type=tls-server`, `cert mint
  --type=code-sign`, etc.
- Per-cert-type policy DSL extensions (validity windows, allowed
  SANs, allowed signature algorithms).
- ACME endpoint compatibility (so existing ACME clients can use us).
  Optional but high adoption-value.

### LOC estimate

~1500 LOC. Mostly endpoint plumbing, since the core minting
machinery is already in [ca/cert_minter.py](../ca/cert_minter.py).

---

## 6. Require 2FA for high-privilege roles (with air-gap fallback)

**Status:** Design needed; implementation isn't trivial.

### Idea

Some roles should require a second factor beyond "the user holds the
mTLS cert." Examples:

- `superuser` admins on the CA.
- A `root-prod` role that grants production SSH as root.
- Anything with `force-command: /bin/db-shell` on the user's primary
  identity store.

Second-factor options:

- **TOTP** (Google Authenticator / Authy / 1Password / etc.). Cheap,
  ubiquitous, works offline.
- **Push to phone** (Duo / Okta Verify / etc.). Better UX, requires
  internet on the user side.
- **Hardware key tap** (YubiKey, FIDO2). Highest assurance.
- **WebAuthn / passkey** challenge from msshd or mssh. Modern.

### The air-gap angle

> "eliminate if auth was air-gapped" — the user

If the CA is reachable only from a private network, **and** the
attacker's path also requires reaching the CA, then the 2FA layer's
value drops: the attacker who can't reach the CA can't drive
authorization anyway. In an air-gapped deployment, 2FA mostly defends
against insider-with-credentials, not external attackers.

That's a legitimate position for an air-gapped deployment to take.
The 2FA mechanism should be **policy-driven**, not hardcoded:
operator decides per-role whether to require it.

### Mechanism sketch

CA-side policy DSL gains:

```yaml
- name: root-admin
  servers: ['*']
  channels: ['session']
  require_2fa: totp     # totp | push | hardware | webauthn | none
  2fa_within_seconds: 60   # how recently the user authenticated 2FA
```

The wrapper's `POST /v1/authorize` request body grows a
`2fa_evidence` field (already on the cert-extension side at OID
`.1.7`, just not produced by clients today). mssh CLI grows a
`--totp` flag (or auto-prompts).

### Cons

- Adds runtime dependency on a TOTP / push / WebAuthn endpoint.
- Adds operator friction for what may be low-frequency operations
  anyway — diminishing returns.
- Doesn't help the air-gapped case (per above).

### LOC estimate

~500 LOC for TOTP only (which is the easiest factor). WebAuthn adds
significantly more (browser-style challenge protocol).

---

## 7. Passkey / WebAuthn support

**Status:** Investigate. Likely complements (2) and (5) rather than
standing alone.

### Idea

Passkeys are the WebAuthn-based credential format that browsers and
OS keychains now natively support. Where smart cards (item 2)
require an extra piece of hardware, passkeys are zero-extra-hardware
for users on modern Mac / Windows / Android / iOS.

Two paths:

1. **Passkey-backed mssh client cert.** Same shape as PIV
   (item 2) — the mssh client's private key lives in the OS
   keychain, accessed via platform credential APIs. Lower friction
   than PIV cards.
2. **Passkey as the 2FA second factor.** The mssh client (or a
   helper website the CA hosts) presents a WebAuthn challenge; the
   user's passkey signs it; signature goes to the CA as
   `2fa_evidence`.

Path 2 is the more natural fit — passkeys are best understood as
"unlock the next step" rather than "be the long-lived identity."

### Cons

- WebAuthn protocol is browser-centric; CLI usage requires platform
  helpers (`secretive`, `pinentry`-style daemons, or shelling out to
  a browser).
- Server-side requires a WebAuthn library (Python: `webauthn` PyPI
  package).

### Composes with

- Item 2 (smart-card) as an alternate factor.
- Item 5 (2FA for high-privilege roles) as one of the supported
  mechanisms.
- Item 4 (HTTPS proxy in msshd) — browser passkey flows are
  natural when msshd is already speaking HTTPS to browsers.

---

## 8. Centralized client config — `~/.mssh/` replaces `~/.ssh/`

**Status:** **Partial.**
- **v1 — landed:** the file-system layout (`~/.mssh/cert.pem`,
  `~/.mssh/key.pem`, `~/.mssh/ca.pem`, `~/.mssh/config`) is
  recognized by the mssh client by default
  ([client.py:52-55](../python/packages/mssh/src/mssh/client.py#L52-L55)).
- **v2 — deferred, scoped:** the "CA-managed distribution + sync"
  piece (which is the actually-valuable bit — the CA pushes cert/key
  rotations to every enrolled client without operator action) is its
  own initiative. Depends on §22 (push channel CA → endpoint), since
  the mechanism that delivers config is the same one that delivers
  revocations.

### Idea

Today an SSH-using laptop is a snowflake. `~/.ssh/config` accumulates
per-host stanzas, `~/.ssh/known_hosts` accumulates fingerprints,
`~/.ssh/authorized_keys` (on the server side) accumulates per-user
public keys, plus there's per-user / per-host config drift in
`/etc/ssh/`. Operators describe the result as "a maintenance
nightmare of separate client and server configs spread over the
network."

The CA already knows:
- Which servers exist (`server add`).
- Which users are enrolled (`user add`).
- Which (user, server) pairs are allowed by policy.
- The wrapper's server cert and the user-mTLS root.

So the CA can **mint a per-user client config** that mssh consumes:

```
~/.mssh/
├── cert.pem                  # user's mTLS cert (PIV-backed in v2)
├── key.pem                   # user's mTLS key (or PIV slot URI)
├── ca.pem                    # trust root for wrapper server certs
├── config                    # CA-rendered: alias → wrapper-host:port
└── known-wrappers            # CA-rendered: list of allowed wrapper hosts
```

`~/.mssh/config` is generated server-side and pulled by `mssh --sync`
(or auto-refreshed every login). It contains *only* the hosts the
user is currently authorized to reach. Operators don't maintain it
by hand; the CA's enrollment DB IS the config.

### Wins

- **One source of truth** for which servers a user can reach: the
  CA's enrollment DB. No drift between client config and server-side
  policy.
- **Removing a user from a policy auto-removes the host from their
  `mssh config`** on next sync. Today the user keeps the old
  `~/.ssh/config` entry forever; the SERVER denies them but the
  client doesn't know that until it tries.
- **No `known_hosts` mystery.** The wrapper's TLS server cert is
  signed by a CA the user already trusts. No "host key has changed"
  prompts ever again.
- **Restricts client behaviour.** `~/.mssh/` has only what mssh
  needs — no agents, no socks proxies, no random key files getting
  loaded by accident. Smaller surface than `~/.ssh/`.

### Incremental migration story

```
Day 1:  Install mssh alongside ssh. Tell users:
        "for the new bastions, use mssh instead of ssh."

Day 7:  Each user has done a few mssh sessions; they verify access
        works as expected.

Day 30: Operator pushes a config that disables ssh access on the
        wrapper hosts. mssh keeps working.

Day 31: User notices ssh no longer works; rm -rf ~/.ssh/.
        That stuff was bit-rotting anyway.
```

The point: **existing SSH stays operational the entire time.** No
flag day. mssh runs side-by-side until the user is comfortable.

This aligns with [scripts/upgrade.sh](../scripts/upgrade.sh)'s
server-side phased upgrade — both ends do incremental, verify-as-you-go
migration.

### Open questions

- **Sync mechanism.** Push (`mssh --sync` against the CA's admin
  API)? Pull (CA exposes a per-user-cert-authenticated endpoint)?
  Probably pull, scoped to the user's own cert.
- **Where does sync happen.** First connection of the day? Every
  connection? On a schedule? Probably first-of-day or explicit
  `mssh --sync`.
- **What about non-CA-enrolled servers?** If a user wants to mssh
  to a host that isn't in the CA's enrollment (e.g., a brand-new
  test box), they need a way to bypass the CA-managed config.
  `--no-sync` + explicit host:port flag works as a v1 escape hatch.
- **Privacy.** The CA's enrollment DB now knows everywhere every
  user can reach. Was always true server-side; now also true on the
  client. Worth surfacing in the security analysis doc.

### LOC estimate

~200 LOC. New CA endpoint (`GET /v1/clients/<cert-fingerprint>/config`,
mTLS-authenticated with the user's own cert), `mssh --sync` flag,
renderer for the config file.

---

## 10. Browser-based SSH terminal (xterm.js over HTTPS, mTLS-authenticated)

### Idea

Add an HTTPS entry point to `msshd` that serves a browser-side SSH
terminal (xterm.js + WebSocket). The browser authenticates with the
user's existing mssh X.509 client cert (presented as a TLS client cert
during the HTTPS handshake). Server-side, msshd treats the browser
session exactly like a regular `mssh` session: same CA call, same
ephemeral inner-sshd cert mint, same policy enforcement.

Net effect: a single internet-facing `msshd` becomes a **web-based
bastion** that can proxy-jump to any backend SSH server the user is
authorized to reach — no local SSH client install required, no
client-side mssh binary required. Just a browser and the user's mTLS
cert.

### Composition

  ```
  browser (with user mTLS cert in keystore)
      │ HTTPS + mTLS (cert authenticates the user)
      ▼
  msshd HTTPS listener  ─►  CA  ─►  inner sshd cert
      │
      ▼
  msshd opens an outbound SSH session to target host (proxy-jump)
      │
      ▼
  xterm.js  ◄── WebSocket stream ──── PTY in the target session
  ```

### Wins

  - Zero-install client: any browser becomes an SSH client.
  - The mTLS cert workflow already exists; the browser just presents
    the cert during the TLS handshake (same machinery used by
    enterprise SSO over client certs).
  - Single chokepoint for auditing, recording, and policy: the
    bastion sees every keystroke if you want it to.
  - Works from networks where outbound SSH (port 22) is blocked but
    HTTPS (443) is open.

### Cons / open questions

  - **Browser support for client mTLS certs is uneven** — works in
    most desktop browsers but is awkward on mobile, often needs
    OS-level keychain integration, and some browsers (Safari, mobile
    Chrome) handle cert prompts poorly. Real test: can a Firefox user
    on Ubuntu and a Safari user on iOS both authenticate cleanly?
  - **Cert distribution to the browser keystore** is the rough edge.
    The mssh CLI knows how to read PEM files; the browser needs the
    cert imported (PKCS#12 + passphrase). Tooling and docs would be
    needed.
  - **Recording / session replay** raises privacy + compliance
    questions distinct from regular SSH — every keystroke transits
    the bastion, where regular SSH end-to-end-encrypts past it.
  - **WebSocket framing** is straightforward but adds a new wire
    format alongside the existing JSON-frame outer protocol — two
    things to keep in sync.
  - **Proxy-jump target list** — does the browser UI list the user's
    allowed servers (queried from the CA via the bastion), or does
    the user type a hostname? CA-driven would be cleaner but couples
    the UI to the CA's enrollment view.

### Composes with

  - Item 4 (HTTPS / TCP proxy) — same HTTPS listener can host both
    the terminal UI and protocol-proxy targets.
  - Item 7 (WebAuthn / passkeys) — passkeys could replace mTLS for
    browser auth where cert handling is painful (e.g. mobile).
  - Item 8 (centralized `~/.mssh/` client config) — server-side
    inventory of allowed targets feeds the terminal UI's target picker.

### LOC estimate

  - HTTPS+WebSocket listener inside msshd: ~300 lines.
  - Browser-side xterm.js + WebSocket glue: ~500 lines JS.
  - PTY + outbound-SSH plumbing on the bastion: ~200 lines.
  - Cert-import docs + Firefox/Chrome/Safari verification: weeks of
    real testing, not LOC.

Total order-of-magnitude: ~1k lines of code + meaningful UX work,
plus the recording / compliance design conversation.

---

## 11. In-situ `debug_sshd` swap-in for troubleshooting (sideband CA audit)

**Status:** **Partial.** Pieces in place + remaining work:

- **Done:** the `debug_sshd` component itself exists
  ([mssh.debug_sshd.ssh_server](../python/packages/msshd/src/mssh/debug_sshd/))
  and runs as a standalone debug tier via `./setup_adhoc.sh debug`.
- **Done (clarified in docs):** the architectural distinction is
  now explicit — production uses **native OpenSSH** as the hermetic
  inner sshd; debug_sshd is a smaller **Python** SSH implementation
  intended *only* for diagnosing the CA/cert/policy decision path.
  Operators should never deploy debug_sshd as a production inner sshd.
  See [architecture.md § debug_sshd](architecture.md) and
  [operations.md § debug mode](../docs/operations.md).
- **Remaining:** the **in-situ swap-in workflow** below — bringing
  debug_sshd up inside an already-running production deployment to
  diagnose without taking the production msshd down — is not built.

### Idea

Promote `debug_sshd` (the Python AsyncSSH server that already calls
the shim) from "debug-only utility" to **a hot-swappable inner SSH
server you can stand up next to the production sshd for in-situ
diagnosis**. An admin facing a "why is my mssh session failing on
this one server" mystery would:

1. SSH to the troubled server (break-glass path).
2. Run `msshd-admin enable-debug-sshd` — msshd starts spawning
   `debug_sshd` instead of the hermetic OpenSSH for new connections
   (existing connections unaffected).
3. Trigger the failing mssh from the client side.
4. Read structured debug output (per-stage shim call, cert validation,
   policy match) — either locally or streamed to the CA as a
   **sideband audit channel**.
5. `msshd-admin disable-debug-sshd` — back to production.

The sideband audit is the interesting part. `debug_sshd` already
parses the X.509 extensions inline (because it's a library-style
integration of the shim, not a delegating proxy). It can emit a
detailed per-event log alongside the regular CA audit, giving the
operator forensic-grade visibility into *exactly* what the inner
sshd saw and decided — without having to interpret strace or
sshd's terse DEBUG output.

### Composition with the adoption journey

  - In **fallback** mode, debug_sshd has no role (msshd is just a
    proxy).
  - In **gated** mode (§6.5.1 of wrapper detailed design),
    debug_sshd could be enabled as an alternative inner server
    that calls the shim, so the operator can see CA decisions
    even before flipping to enforce.
  - In **enforce** mode, debug_sshd replaces the hermetic OpenSSH
    on demand for troubleshooting. The hermetic config can't be
    instrumented at runtime; debug_sshd can.

### Wins

  - Single tool for "is the CA actually returning what I expect for
    this user?" without rebuilding/redeploying.
  - Sideband audit gives the CA visibility into per-decision detail
    that the production sshd path doesn't emit.
  - Re-uses code that already exists (debug_sshd has been kept
    explicitly for this kind of purpose).
  - Useful in the adhoc lab too: an operator running the tutorial
    can flip a knob and see CA decisions live.

### Cons / open questions

  - Hot-swap of the inner server while msshd is running implies
    msshd accepts a runtime config-change signal (graceful drain
    + restart the inner). That's a small-but-real piece of
    plumbing — not zero.
  - Sideband audit channel: ship logs to the CA over the existing
    mTLS connection, or open a separate one? Volume / format /
    retention questions.
  - Production deployments probably want this **gated by an admin
    role** at the CA — turning on debug_sshd on a sensitive host
    is itself an auditable action.
  - debug_sshd performance vs hermetic sshd: AsyncSSH is fine for
    debug, but you wouldn't want to leave it on as the steady-state
    inner server. Need a "this is temporary, expire after N hours"
    safety.

### LOC estimate

  - msshd: ~150 lines for inner-server swap + signal handling.
  - debug_sshd: ~200 lines for structured sideband-audit emitter.
  - CA: ~100 lines for receiving + storing the sideband stream
    alongside regular audit entries.

---

## 13. Legacy-config migration with dual-enforce / shadow mode

### Idea

When an organization adopts mssh, their existing servers carry
*years* of accumulated policy: `authorized_keys` files, sshd_config
`AllowGroups`/`AllowUsers`, PAM rules, AKC plugins, `/etc/security/`
limits, etc. Manually translating that into CA enrollments is
high-effort and the highest-risk part of the migration ("did I
remember to grant alice the same access she had before?"). It is
also where most adoptions stall.

Propose two things that compose:

1. **Capture-and-translate tool.** A new `mssh-admin import` mode
   scrapes the existing server config and produces a draft
   enrollment YAML:
   - `authorized_keys` entries → per-user `keys` enrollment
   - `AllowGroups` / `AllowUsers` → server `groups` + user policies
   - Existing AKC plugin output → pass-through allow rules
   - PAM-restricted users → annotate (won't translate; operator
     reviews)
   The output is a starting point, not final policy — the operator
   reviews and edits before applying. Adhoc-mode lab runs this on
   the Phase-0 vanilla sshd state so the lab visibly demonstrates
   "drop-in migration with no manual rewriting."

2. **CA-side dual-enforce / shadow mode.** A per-server CA policy
   flag enables a transitional state where every authorization
   decision is evaluated **twice**:
   - against the **legacy ruleset** (the imported authorized_keys
     / AllowGroups / etc.)
   - against the **new CA policy** (the operator's hand-curated
     enrollments)

   The CA returns the union (or chosen primary; configurable),
   and **emits a divergence audit entry** for every case where
   the two disagree:
   - `legacy_allow_only`: legacy said yes, CA said no — operator
     is more restrictive in the new policy (potentially desired,
     or might be missed access that needs re-granting)
   - `ca_allow_only`: CA said yes, legacy said no — operator
     intentionally widened access (probably fine, but worth flagging)
   - `both_deny`, `both_allow`: agreement (no event needed)

   The operator runs in dual-enforce mode for as long as it takes
   to see zero `legacy_allow_only` events for any user they still
   want to support. Then they flip a config flag and the legacy
   ruleset is dropped — single-source-of-truth enforcement going
   forward.

### Wins

  - Removes the biggest adoption blocker: "I don't trust myself to
    have translated 10 years of sshd config correctly into CA
    policies."
  - Users see **no disruption** during migration — they continue to
    have exactly the access they had before, plus whatever the new
    CA policy adds. Operators can iterate on the CA policy
    asynchronously.
  - Audit log becomes a discovery tool: "show me every user whose
    legacy access we haven't replicated" → punch list.
  - In the adhoc lab, the workflow is the most compelling demo
    we can ship: "your existing servers worked at Phase 0; flip
    on capture-and-translate; Phase 2 enforce works with the same
    access patterns; admin tightens policy with zero user impact."

### Cons / open questions

  - Translation is heuristic, not lossless. PAM rules in particular
    don't have a clean equivalent in CA policy. Need a clear
    "couldn't translate; please review" output stream.
  - Dual-enforce slows every auth decision (~2x evaluation per call).
    Acceptable transitionally, not in steady state. Need a hard
    deadline (e.g. dual-enforce auto-expires after 30 days unless
    re-armed).
  - The legacy-allow-only vs ca-allow-only labels are slightly
    misleading when a user's legacy access is "all systems" and
    the new policy intentionally narrows that. The audit needs to
    distinguish "policy gap" from "policy tightening."
  - Storing the legacy ruleset at the CA means the CA now has a
    direct copy of every server's `authorized_keys`. Custody +
    cleanup matter.

### Composes with

  - §6.5.1 of msshd detailed design (gated mode) — gated mode
    leaves the operator's sshd policy in place at run-time. Legacy
    capture-and-translate goes a step further: it lifts that policy
    into the CA so the operator can eventually retire the original.
    Gated mode is "preserve the policy where it lives"; this is
    "move the policy into the CA."
  - §9 (migration runbook) — capture-and-translate is the missing
    automation that runbook would otherwise have to walk operators
    through by hand.
  - §11 (debug_sshd sideband audit) — sideband logs make divergence
    cases inspectable in detail when the operator can't tell why
    legacy said yes and CA said no.

### LOC estimate

  - `mssh-admin import` parsers (authorized_keys, sshd_config,
    AllowGroups, PAM-summary): ~500 lines.
  - CA-side dual-enforce evaluator + divergence audit: ~300 lines.
  - Adhoc-lab integration (a `Phase 0.5` step that runs import,
    shows the operator the draft, applies it): ~200 lines.

---

## 16. Distro packaging path (`.deb` / `.rpm` / `.apk`)

### Idea

Long-term: ship native distro packages so the operator install
becomes literally `apt install mssh msshd` (Ubuntu/Debian),
`dnf install` (RHEL/Fedora), `apk add` (Alpine), instead of running
[§15](#15-install_mssh--distro-style-installer--byo-container-adhoc-lab)'s
shell installer.

### Three tiers of effort

  - **Quick win (~1 day): [`fpm`](https://github.com/jordansissel/fpm).**
    Eats a tarball or wheel, spits out `.deb` + `.rpm` + `.apk` from
    one command. No proper changelogs, no signing, no infrastructure;
    good enough for "users can `apt install ./mssh_0.1_amd64.deb`."
    Right call for the first release.

  - **Proper per-distro packaging (~1-2 weeks).** `dh-virtualenv`
    for Debian (packages the venv into a `.deb` — the standard
    Python-on-Debian story), proper `.spec` for RPM, `APKBUILD` for
    Alpine. Cleaner integration with apt/dnf/apk; more recipes to
    maintain over time.

  - **[openSUSE Build Service (OBS)](https://build.opensuse.org/).**
    Free for FOSS, used by KDE/Mozilla. Builds `.deb` / `.rpm` /
    `.apk` from a single source spec, for every distro you care
    about, automatically on push. Setup is half a day; after that
    it's a build-and-distribute pipeline you don't maintain.

### Why the underlying language matters

apt/dnf/apk were built around C's "one binary + shared libs in
known paths" model. Python (and to some extent Go) violate that
assumption — Python needs an interpreter + venv; Go static binaries
solve the interpreter problem but bring their own platform issues.

  - **Python** packaging: `dh-virtualenv` is the least-bad answer —
    you ship the entire venv (~30MB), distro-managed. `fpm` does
    the same thing with less ceremony.
  - **Go** packaging is *normally* trivial — a 15MB static binary
    that drops in `/usr/bin/`. **BUT Go does not target musl
    cleanly** (Alpine's libc). With `CGO_ENABLED=1` the binary
    depends on glibc; with `CGO_ENABLED=0` you lose cgo-dependent
    functionality (system DNS resolver, some crypto, system
    libraries). There are workarounds (alpine-go images, gccgo,
    cross-compile to musl with special toolchains) but they're
    not "just run `go build`."
  - **C / C++** packaging is what distro tooling was designed for;
    smallest binaries, cleanest integration, but biggest engineering
    investment to write.
  - **Rust** packaging is increasingly first-class via cargo-deb /
    cargo-rpm, with musl support that actually works (`x86_64-unknown-linux-musl`
    target builds cleanly for Alpine). If "small static binary that
    also runs on Alpine" matters, Rust is currently the cleanest
    answer of the cross-language options.

### Implications for the language strategy

If Alpine support stays a goal (it does — Alpine + Python is the PoC
target), the Go port's distro-packaging story is harder than initially
hoped. Options:

  1. Accept the constraint: ship Python on Alpine via the venv
     packaging path; Go on glibc-only distros.
  2. Bite the bullet on the C port for Alpine specifically (clean
     `.apk` story, smallest footprint, hardest to write).
  3. Consider Rust as the third language slot instead of Go for
     the Alpine target — single-binary `.apk` works out of the
     box, identity-management ecosystem (rustls, x509-cert, ssh-key)
     is mature enough.

This isn't a near-term decision, but worth knowing before committing
to a Go port whose primary value-prop (clean static binary
distribution) doesn't apply to half the deployment targets.

### Out of scope

The user noted this is "probably out of scope" — captured here so
we don't lose the constraint. No action implied; revisit when
shipping a real release becomes a priority.

---

## 17. Per-session banner with variable substitution

**Status:** **Partial — v2 deferred, blocked on §21.**
- **v1 — landed:** operator-templated, startup substitution. Operators
  customize via `banner.template_path` in `wrapper.yaml`; rendered at
  msshd boot.
- **v2 — deferred:** per-user / per-session substitution AND
  delivery of the banner to the *mssh client* (closed-bug #11). The
  per-session render side can plug into the per-connection inner
  sshd (§1, already landed). But the delivery side requires the
  framed v1.1 protocol of §21 — without it, the banner is invisible
  to mssh users (which makes the per-session work moot until §21
  lands first).

See "What's not done" below for the original v2 sketch.

### Idea

msshd serves a static hardcoded banner today via the hermetic inner
sshd's `Banner` directive (see `config/sshd_config.template` and
`python/src/mssh/msshd/inner.py:_DEFAULT_BANNER`). Per-session
dynamic content would make this much more useful as an immediate
"what's happening with this session" indicator.

### What's done (v1)

Operators can point `banner.template_path` in `wrapper.yaml` at a
text file and supply a `values` map; msshd substitutes `{key}`
tokens at startup and writes the rendered file as the inner sshd's
Banner. Missing tokens are left literal; missing or malformed
templates fall back to the default banner with a warning log (msshd
does not refuse to start). See
[docs/operations.md § customize the per-server pre-auth banner](../docs/operations.md#customize-the-per-server-pre-auth-banner)
for the operator workflow.

This gives operators per-server / per-group banner customization
without changing the existing long-lived-inner-sshd architecture.

### What's not done

  - **Per-user / per-session substitution.** The inner sshd is
    long-lived and shares its banner across sessions, so `{user}`
    can't change between connections without writing the banner
    file concurrently — a race. Per-connection inner sshd (§1)
    **landed** and unblocks this — msshd can now render the banner
    per-session against the full CA-decision context, including
    `{user}` and a `$MSSH_AUTH_DATA`-style summary. The CA-side
    template can write `Banner /var/lib/mssh/inner-sshd/sessions/{conn_id}/banner`
    and msshd writes the per-session banner text alongside the
    rendered sshd_config. Implementing this is small and bounded
    once a per-server CA template is in place.
  - **CA-stored banner templates + admin CLI.** Templates live in
    `wrapper.yaml` on each msshd today. Storing them centrally in
    the CA's enrollment record (per-server or per-server-group)
    and exposing `mssh-admin server banner set/show` would make
    fleet-wide updates a one-command operation. Out of scope for
    v1; revisit when the CA gains arbitrary per-server metadata
    storage.

Target template:

```
{user} — {client user; sally can be granted access to fred's account}
Welcome to {server}, owned by {group}.
Authorization: $MSSH_AUTH_DATA  (some details from the CA)
$ADMIN_HELP — how to modify this banner via mssh-admin on the CA.
```

### Implementation sketch

  - msshd already calls the CA for every connection and knows
    user / server / group / authorization details at session-establish
    time. Write a per-session banner file just before the inner sshd
    accepts the connection, and clean up after the session closes.
  - `Banner` is pre-auth in OpenSSH, but the inner sshd's "auth"
    is with msshd's just-minted ephemeral cert — by the time the
    banner is rendered the CA has already returned its decision,
    so the substitution data is all known.
  - Banner template lives in the CA enrollment record (per-server
    or per-server-group) so different deployments can carry their
    own welcome text.

### CA-side admin surface

  - `mssh-admin server banner set <server> --template <file>`
  - `mssh-admin server-group banner set <group> --template <file>`
  - `mssh-admin server banner show <server>` (preview with placeholders)

### LOC estimate

  - msshd inner.py: ~80 lines for per-session banner write +
    cleanup + template substitution.
  - CA enrollment schema + admin endpoints: ~120 lines.
  - mssh-admin CLI commands: ~60 lines.

---

## 18. Self-service "why was I denied" report

### Idea

A user who is already authenticated to a host (or to their
workstation) but who is hitting unexpected denies should be able to
ask the CA "why?" without bothering an admin. Today the audit log
has the answer but it's gated behind admin-level credentials.

Concrete shape: `mssh-admin auth-failures-report` (or
`mssh whatfailed`, scoped to the calling user's own identity, not
admin-grade). The CA exposes a per-user audit endpoint that
returns the last N denies for the caller's enrolled identity,
with the structured `denied_reason` for each.

### Wins

  - **Reduces admin burden.** "Why can't I get in?" is one of the
    most common operator-support questions. Self-serve answers
    cut that traffic.
  - **Composes with [[mssh-admin-status-next]].** `status` shows
    the deployment is healthy from the CA's view; `auth-failures-
    report` shows why a specific user's recent connection attempt
    failed. Together: a complete diagnostic loop.
  - **Re-uses existing audit infrastructure.** No new storage; the
    CA already records every decision.

### Implementation sketch

  - New CA endpoint: `GET /v1/user/<self>/recent-denies`. mTLS
    client cert identifies the calling user; no admin role
    required. Returns the last N (cap ~50) decisions where
    `decision == "deny"` and the caller's identity matches.
  - Response is the structured `denied_reason` field plus a
    human-readable rendering ("CIDR mismatch: your source was
    10.0.5.4, policy `analyst-policy` allows 10.0.0.0/16").
  - `mssh-admin auth-failures-report` (CLI) or built into
    `mssh next` so users see denies in their own status walk.
  - Anti-enumeration: the endpoint never reveals *other* users'
    denies, and rate-limits aggressively so it can't be used to
    probe policy.

### Cons / open questions

  - Timing-side-channel: a user could probe "is policy X attached
    to my account" by triggering connections and watching the
    deny reasons. Mitigate by collapsing similar reasons in the
    output (e.g. "policy denied" rather than naming the specific
    policy that denied).
  - User cert revocation: once a user is revoked, can they still
    call this endpoint? Probably not — revocation should be all-
    or-nothing for cert-bearing endpoints.

### LOC estimate

  - CA endpoint + identity scoping: ~150 lines.
  - CLI command: ~50 lines.
  - Tests covering policy / CIDR / time-window denies: ~200 lines.

---

## 19. Bash auto-completion scripts for mssh* commands

**Status:** Defer until v1 release readiness — bash completion is a
polish item, not a blocker. Worth ~30 minutes when we're packaging
a deliverable.

### Idea

Ship per-command bash (and zsh, fish) completion scripts for
`mssh`, `mssh-admin`, `mssh-ca`, `msshd`, and `msshd-admin`. Each
CLI is Click-based (except `msshd` itself), and Click already
generates shell completion via the `_<PROG>_COMPLETE=bash_source`
environment variable.

### Implementation sketch

  - For each Click-based command, ship a generated completion
    script under `scripts/completion/`:
    `mssh-admin.bash`, `mssh-admin.zsh`, `mssh-admin.fish`, etc.
  - Generated once at packaging time by running e.g.
    `_MSSH_ADMIN_COMPLETE=bash_source mssh-admin > mssh-admin.bash`.
  - Distro packages install these into the standard locations
    (`/etc/bash_completion.d/`, `/usr/share/zsh/site-functions/`,
    `/usr/share/fish/vendor_completions.d/`).
  - The non-Click `mssh` client and `msshd` daemon need
    hand-written completion (small surface — `mssh` is mostly
    `user@host`; `msshd` is mostly `--config <path>`).
  - Validate by `complete -p` round-trip in a CI test.

### LOC estimate

  - Generated scripts: zero hand-written LOC for Click-based.
  - Hand-written completion for `mssh` + `msshd`: ~50 lines each.
  - Packaging glue: ~30 lines.

### Composes with

  - §15 (install_mssh.sh) — installs the completion scripts.
  - §16 (distro packaging) — `.deb`/`.rpm` Drop-In Place via
    debhelper / rpm scriptlets.

---

## 20. End-to-end migration test with auto-generated playbook

**Status:** Substantial — the most ambitious test we'd build. High
value: validates the full migration story, produces an artifact
that doubles as both a verification gate AND a teaching aid for
operators (and for Claude) on how to perform the upgrade.

### Idea

A single LXC test that simulates a realistic legacy SSH deployment,
walks through the full migration to mssh enforce mode, and emits a
`migration_test_execution.md` artifact recording every command
executed, every output observed, total wall-clock time, and a
final summary "X admin-commands needed, estimated Y minutes per
server."

### Test scenario

  - **Initial state — legacy fleet.** Randomized seed populates:
    - 5–10 SSH hosts (mix of Ubuntu + Alpine) with their own
      sshd, known_hosts, and authorized_keys.
    - 15–25 users with randomized SSH keypairs distributed
      across hosts via authorized_keys (realistic sparsity:
      not every user on every host).
    - 2–3 **external** hosts — SSH servers outside the mssh
      fleet that some users still need access to. Their host
      keys live in user known_hosts but they're never enrolled
      in the CA. Validates "mssh doesn't break my non-mssh
      flows."
    - Per-user `~/.ssh/config` with aliases for some hosts.
  - **Validation phase 0.** Every documented user → host pair
    works via `ssh user@host`. External hosts work. This
    establishes the access baseline the migration must preserve.
  - **Migration walk.** The test drives the migration step by
    step, recording each `mssh-admin` invocation:
      1. CA bootstrap (`mssh-admin init`).
      2. Server enrollment (`mssh-admin server add` × N).
      3. User enrollment + key import (`user add` + `user key add`).
      4. Policy attachment derived from observed
         authorized_keys distribution.
      5. Drop msshd in fallback mode on each server.
      6. Flip each server to enforce.
      7. Roll out client config (`~/.mssh/`).
  - **Validation phase N (post-migration).** Re-run the full
    access matrix via `mssh` instead of `ssh`. External hosts
    still work via raw `ssh`. `~/.ssh/` is empty (or contains
    only what's needed for external hosts). Every previously
    successful (user, host) pair is still successful.
  - **Failure injection (optional, v2).** Revoke a user
    mid-flow. Disable a server. Confirm denies are clean and
    the audit log captures them.

### Generated artifact

`migration_test_execution.md` — a chronological log of every
command executed and its result, structured like:

```
## Phase 1.3: enrol user alice
    $ mssh-admin user add --user alice --key /artifacts/alice.pub
    user_added: alice
    key fingerprint: SHA256:…

    Cumulative: 7 admin commands, 00:01:42 elapsed.

## Phase 2.1: drop msshd on srv-acct-01 in fallback mode
    $ systemctl enable --now msshd
    ... output ...
    Cumulative: 12 admin commands, 00:03:18 elapsed.
```

The trailing summary section reports total command count, total
wall-clock time, and an estimated per-server / per-user effort.

### Wins

  - **Validates the migration end-to-end.** Catches regressions
    in any of the dozen-plus moving pieces.
  - **Doubles as documentation.** The generated playbook is the
    operator-facing migration runbook — auto-updated every CI
    run. Beats hand-written drift-prone docs.
  - **Teaches Claude.** When asked "how do I migrate srv-X",
    Claude can read the playbook as its source of truth, not
    risk hallucinating commands.
  - **Quantifies migration burden.** "X commands, Y minutes per
    server" is the number that wins or loses adoption
    conversations.

### Cons / open questions

  - Big test, big LOC. Probably ~1000 lines new code +
    significant new LXC scenario infrastructure.
  - Test runtime: realistic full-flow with 5–10 hosts is going
    to be 10–30 minutes per run. Acceptable for nightly CI, not
    for pre-commit.
  - The "external hosts that will never be part of mssh" piece
    is novel — needs careful design so it doesn't accidentally
    get sucked into mssh enrollment.

### Composes with

  - §13 (legacy capture + dual-enforce) — the test exercises the
    same scrape-and-translate path, with real legacy config.
  - §9 (migration runbook doc) — the test's output IS the
    runbook, freshly generated each run.
  - [[mssh-admin-status-next]] — the test verifies `status`
    correctly walks the adoption journey end-to-end.

### LOC estimate

  - LXC scenario builder (legacy fleet + randomized users):
    ~400 lines.
  - Migration walker + step recorder: ~300 lines.
  - Validation matrix (pre + post): ~200 lines.
  - Markdown emitter: ~100 lines.

---

## 21. Protocol v1.1 — typed framing for the post-ack stream

**Status:** Decided to do; design doc pending. Surfaced during the
2026-05-19 adhoc-testing round.

### Idea

The mssh ↔ msshd outer protocol is TLS + a JSON header + ack, then a
**raw byte pump** for the rest of the session. No frames, no message
types. Five separate user-visible bugs trace to the same root cause:
the post-ack stream can't carry anything but stdout (merged with
stderr).

| Bug | Today | Why it breaks |
|---|---|---|
| #1 cryptic denials | "server closed before sending ack" | Deny reason has no channel |
| #2 exit code always 0 | mssh returns 0 even on remote `false` | No exit-status frame |
| #3 stdin EOF hangs | `echo x \| mssh ... cat` hangs after data | No EOF signal |
| #4 stderr merged | `2>` doesn't separate stderr | No stream-type field |
| #11 banner invisible | Custom banner renders but mssh users never see it | No pre-stream banner channel |

### Sketch

Promote the byte pump to a small framing layer with typed messages:

```
struct frame {
    uint8  type;   // STDIN | STDOUT | STDERR | EXIT | SIGNAL | BANNER | DENY
    uint32 length;
    bytes  data[length];
}
```

Backwards-compat strategy: bump `PROTOCOL_VERSION` to `1.1`. The
existing header negotiates; if both sides speak ≥1.1, switch to framed
mode after the ack. Old clients see EOF when the new server closes,
same as today.

### Wins

- Closes 5 bugs in one change (above).
- Banner becomes user-visible (closes Bug #11 too).
- Stdout/stderr split (closes Bug #4 by design, not just acknowledgement).
- Exit-status semantics align with SSH / standard remote-exec.

### Cost

- ~400 LOC across mssh client (`_pump` rewrite) and msshd's
  `ssh_proxy` (the `_OuterRelay` data_received path needs to wrap each
  asyncssh data callback in a typed frame).
- 1 session of design (notes-protocol-v1.1.md), 1-2 sessions of
  implementation, 1 session of tests.

### Connects to

- Bug #1, #2, #3 (EOF half), #4, #11 in `design/openbugs/`.
- The post-ack architecture in `design/architecture.md § Wire protocols`.

### LOC estimate

  - Framing types + frame reader/writer in mssh-common: ~80 lines
  - mssh client `_pump` rewrite: ~120 lines
  - msshd `_OuterRelay` framing: ~80 lines
  - mssh-ca deny response: ~10 lines (already partly there for
    `current_crl_seq`)
  - Tests (unit + Tier-2 integration): ~150 lines

---

## 22. Push channel for revocation + live-session kill

**Status:** Decided to capture; design pending. Discussed during the
2026-05-19 review of CRL propagation gaps.

### Idea

Today msshd's CRL sync is reactive: it pulls revocations from the CA
only when an authorize call is happening anyway. On a small fleet
with mostly cache-hits, revocations may stall indefinitely until some
cold call forces a sync. The other half — **terminating an already-
established session** when a user is revoked — isn't addressed at all;
operations.md correctly notes "in-flight sessions unaffected."

For incident-response (compromised credential, dismissed employee)
this is the wrong shape. You want:
  - Revocations propagate within seconds, not minutes.
  - Active sessions for a now-revoked principal terminate.

Polling solves problem 1 at the cost of constant idle traffic. A push
channel solves both cleanly.

### Sketch

Each msshd opens a persistent mTLS connection to the CA at startup
and re-opens with exponential backoff on disconnect. The CA pushes:

```
{type: "revoke", serial: "<hex>",  reason: "..."}
{type: "kill",   principal: "alice", reason: "..."}
{type: "ping"}        // heartbeat
```

msshd handles each:
- revoke → invalidate any matching cache entry by serial (already wired
  up in `authz_cache.invalidate_by_serial`).
- kill → enumerate active inner-sshd sessions for that principal,
  SIGTERM them, audit the termination.

### Wins

- Revocation latency drops to milliseconds (one TCP RTT).
- Live-session-kill closes the architectural hole called out in the
  current operations.md.
- No idle polling; channel is silent at steady state.

### Cons

- One persistent TCP per msshd → CA. At fleet scale, the CA needs to
  hold N connections. Lightweight (no traffic) but real.
- Reconnect / backoff logic must be careful — overzealous backoff
  delays revocation; under-zealous backoff hammers the CA on a flap.
- The CA gains a "session registry" (which msshds are connected, what
  principals are active where) — useful for ops but new state to
  manage.

### LOC estimate

  - CA-side push endpoint + session registry: ~200 lines.
  - msshd-side persistent-channel client + handlers: ~200 lines.
  - kill-active-session plumbing into `inner.py`: ~80 lines.
  - Reconnect / backoff: ~50 lines.
  - Tests: ~150 lines.

Total ~700 lines; multi-session work.

### Connects to

- `notes-bypass-cache.md` (archived) — CRL sync design.
- `architecture.md § failure model`.
- Eventually replaces the "lazy CRL" caveat in the cache design.

---

## 23. Sshd_config template unification

**Status:** Equivalence test landed; full unification deferred.

### Background

The hermetic inner sshd_config exists in two places:
  - `config/sshd_config.template` — used by **long-lived** mode,
    rendered once at msshd boot.
  - `mssh.ca.templates.BUILTIN_OPENSSH_TEMPLATE` — used by
    **per-connection** mode, rendered by the CA on every authorize
    call.

Bug #8 was caused by these silently diverging on
`PubkeyAcceptedAlgorithms`. The 2026-05-19 round landed
`python/tests/test_template_equivalence.py` which catches future
divergences on auth-critical directives. Full unification (one
canonical template both contexts render from) is deferred.

### Idea

Reduce the two templates to one canonical source. The CA's
per-session render still happens (it has more `{FROMCA_*}` markers),
but the BASE directives come from the same file the long-lived inner
reads.

### Why

- The equivalence test will catch known auth-critical directives, but
  not subtle ones added later. One template, one truth.
- Operator override mechanism becomes cleaner: edit one file at one
  point.

### LOC estimate

- ~100 lines: refactor `ca/templates.py` to load from the same source
  file at startup; update tests.

### Connects to

- Bug #8 in `archive/closedbugs/`.
- `test_template_equivalence.py` (current detector).

---

## 24. Multi-server group lab coverage

**Status:** Test gap. Found during the 2026-05-19 docs/CLI alignment
review.

### Background

The adhoc lab provisions 4 servers — `acct`, `sales`, `hr`, `eng` —
each in **exactly one group of one server**. The "group" abstraction
(set of servers under a named group, policies target groups) is
present in code but never exercised with multi-member groups.

This obscures the value of group-based policy and leaves real-world
multi-server-per-group bugs uncaught.

### Idea

The lab should provision e.g. 2 `acct` servers (`srv-acct-1`,
`srv-acct-2`) so the `accounting` group has actual member set
behavior. Plus the `server groups <name> --add X --remove Y` CLI
work (item §25? or expanded into this entry) makes group-membership
changes exerciseable end-to-end.

### Compose with

- Building `mssh-admin server groups ...` CLI (open work).
- Adding a `srv-acct-2` to `SERVERS` in test_setup_only_msshd.py.
- Asserting policies that target `accounting` group authorize against
  BOTH `srv-acct-1` and `srv-acct-2`.

### LOC estimate

- ~40 lines test framework + ~40 lines CLI + ~20 lines API endpoint
  for `PUT /v1/admin/server/{name}/groups` (already in api.md but not
  implemented).

---

## How items relate

```
                    ┌────────────────────────────────────┐
                    │ 4. HTTPS / browser entry to wrapper │
                    └─────────────┬──────────────────────┘
                                  │
                  ┌───────────────┼─────────────────┐
                  ▼               ▼                 ▼
   ┌──────────────────┐ ┌──────────────────┐ ┌─────────────────┐
   │ 2. PIV/PKCS#11   │ │ 7. WebAuthn/     │ │ 5. CA mints     │
   │    smart cards   │ │    passkeys      │ │    other certs  │
   └────────┬─────────┘ └────────┬─────────┘ └─────────────────┘
            │                    │
            └────────┬───────────┘
                     ▼
         ┌─────────────────────────┐
         │ 6. 2FA for high-priv    │
         │    roles                │
         └─────────────────────────┘

   ┌──────────────────────┐   ┌──────────────────────┐
   │ 1. Per-connection    │   │ 3. Shared protocol   │
   │    ephemeral sshd    │   │    module (drift     │
   │  (Phase 2 priority)  │   │    prevention)       │
   └──────────────────────┘   └──────────────────────┘

   ┌──────────────────────┐   ┌──────────────────────┐
   │ 8. ~/.mssh/ replaces │   │ 9. Migration runbook │
   │    ~/.ssh/ (CA-       │──▶│   (operator-facing  │
   │    managed client    │   │    doc, ties both    │
   │    config)           │   │    ends together)    │
   └──────────────────────┘   └──────────────────────┘
```

Items 1 and 3 are **wrapper internal architecture** — independent of
each other, both worth doing in Phase 2.

Items 2, 5, 6, 7 are **identity / authentication enhancements** —
they compose; the right pattern is to design 2 + 7 + 6 together as
a coherent identity layer, not piecemeal.

Item 4 is a **scope expansion** — msshd becomes a multi-protocol
authorization proxy, not just an SSH gateway. Decide before it whether
that's the project's direction.

Item 10 (browser-based xterm.js terminal) is a **client-side
expansion** that builds on item 4's HTTPS listener: the bastion
serves a web SSH client to anyone with the right mTLS cert in their
browser. Composes naturally with item 7 (passkeys, where browser
cert handling is painful) and item 8 (centralized client config, to
feed the terminal UI's target picker).

Items 11, 13, 14 are the **operator-adoption block** — each tackles
a different obstacle to "we'd like to deploy this but the migration
looks scary":
  - **11 (debug_sshd swap-in + sideband audit)** gives the operator
    a "what is the CA actually deciding?" inspection tool when
    something looks wrong in production.
  - **13 (legacy capture + dual-enforce)** removes the
    re-translate-everything-from-scratch tax and makes the migration
    auditably non-disruptive.
  - **14 (tutorial)** is the operator-facing doc that ties the
    adhoc lab to a guided walkthrough of every feature.

Item 12 (MCP interface to the CA) is **orthogonal** to all of the
above — a different surface (LLM-driven) onto the same CA data
model. Mostly read-only diagnostics are the obvious starting point;
trusted-AI writes are a second milestone with their own trust
discussion.

---

## When this doc gets cleaned up

When an item is promoted to active work, move it to a dedicated design
doc (`design/mssh-detailed-<feature>.md`) and replace its
section here with a one-line "→ moved to <file>" pointer.
