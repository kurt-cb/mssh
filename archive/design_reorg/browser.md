# mssh — browser-based access (design exploration)

**Status:** Captured discussion, no commitment to build. Companion
to [future-ideas.md](future-ideas.md) items 4 (HTTPS proxy),
7 (WebAuthn / passkeys), and 10 (xterm.js bastion). Promote to a
build-ready design before any implementation work begins.

> **2026-05-20 update:** the "Admin portal — feasible" section
> below was written assuming the portal must be reachable at a
> public hostname (`ca.example.com`) and therefore needs MDM-pushed
> per-domain trust pinning to constrain browsers to the mssh CA.
> [future-ideas §26](future-ideas.md#26-admin-web-portal-via-mssh-tunneled-localhost)
> proposes an alternative: bind the portal to `127.0.0.1` on the CA
> host, reach it from admin laptops via an mssh local-port-forward
> (`mssh-admin web` opens the tunnel; admin opens
> `https://localhost:8443/`). The browser never resolves a public
> hostname for this connection, so the public-CA attack surface
> doesn't apply — no MDM dependency, no per-domain pinning required.
> The MDM-pinned discussion below remains relevant only if the
> portal must also be reachable from devices that can't run the
> mssh CLI. End-user browser access (the "ruled out" section) is
> unchanged.

Browser-based access to mssh services — a web admin portal for the
CA, or a web-SSH terminal for end users — would extend the same
CA-mediated authorization model to clients that don't run the
`mssh` CLI. This document captures the security analysis we walked
through, the choices that flow from it, and the scope split we'd
take if we built this.

---

## The two-sided TLS problem

Any browser ↔ mssh connection has two TLS validation paths. Only
one carries the public-CA risk:

  - **Browser → msshd (server cert).** Browsers ship trusting
    ~150 public CAs by default. Any one of them — DigiCert,
    Let's Encrypt, a state CA, etc. — can issue a cert for
    `msshd.example.com`. Historical examples (DigiNotar 2011,
    Symantec misissuances 2017) confirm this isn't theoretical.
    An attacker with DNS or BGP control can MITM the gateway
    with a fraudulent-but-publicly-valid cert.
  - **msshd → browser (client cert).** Not affected. msshd
    specifies its own trust roots in its TLS config; only certs
    signed by the mssh CA are accepted. The public CA store
    doesn't get a vote.

So the worry — "any public CA could fake your system" — applies
specifically to the server-cert path.

### Adding a root is not the same as restricting trust

A natural misreading: "users will install the mssh CA root in
their browser, so the browser will only trust the mssh CA for
this connection." That's wrong. Installing a root is **additive,
not exclusive.** After the user imports the mssh root, the
browser trusts mssh-CA-signed certs **AND** DigiCert AND
Let's Encrypt AND GlobalSign for `msshd.example.com`. The public
CAs don't get removed; they sit alongside yours. So importing your
root does not, on its own, prevent a public-CA-signed forgery
from impersonating msshd.

To actually constrain a browser to *only* the mssh CA for a
specific connection, the options are limited:

  - **Enterprise managed browser policy** (Chrome ADM / Firefox
    enterprise policies via MDM). Lets the operator push per-domain
    trust pinning to managed devices. Works for company laptops;
    impossible for arbitrary user devices.
  - **HPKP** — removed from Chrome in 2019, deprecated in Firefox.
    Dead.
  - **Expect-CT** — Chrome stopped enforcing in 2023. Dead.
  - **DANE/TLSA via DNSSEC** — no mainstream browser support.
  - **Don't use a browser** — the `mssh` CLI controls its own
    trust store and pins to the mssh CA root by configuration.
    This is what the CLI already does correctly.

The accepted approach for mssh is **enterprise managed browser
policy** with mssh-CA-only pinning, on devices the operator
controls. The naive "issue msshd's cert with a public CA and rely
on CAA + Certificate Transparency monitoring" path is **rejected
by requirement** — it preserves the public-CA attack surface, and
the project's position is that doing so increases attack vectors
without compensating gain. Any browser-based feature must
guarantee mssh-CA-only server-cert trust at the device.

### Implication

A user-installed root cert is **not** sufficient to meet the
requirement on its own. The full chain to satisfy the requirement
is: enterprise-managed browser + MDM-pushed per-domain trust
pinning + mssh-CA-issued server cert. If any link is missing, the
public-CA attack surface remains and the connection shouldn't be
exposed.

---

## Identity / authentication options

### mTLS client cert in browser — the obvious-but-flawed path

Browsers natively present client certs during the TLS handshake.
The mssh CA already mints client certs. In principle, mssh client
certs go straight into the browser keystore, no protocol changes
required.

In practice:

  - **Cert import UX varies wildly.** PKCS#12 export from the CA,
    passphrase handoff, OS-keychain import — each browser/OS has
    its own quirks.
  - **Mobile is awkward at best.** iPad/iPhone require a
    Configuration Profile workflow; mobile Chrome on Android
    handles client certs poorly; mobile Safari surfaces them
    awkwardly.
  - **Not origin-bound.** TLS client certs do not bind to the
    server origin the way WebAuthn credentials do. A user tricked
    into picking the wrong cert in a browser prompt is a real
    failure mode.

Desktop-only mTLS is workable. Adding mobile as a target pushes us
elsewhere.

### WebAuthn with hardware-only authenticators — the cleaner path

WebAuthn solves the mobile problem and adds phishing resistance,
**if** we constrain it carefully. The key is to reject every
authenticator class that could be considered "poorly implemented":

  - **Accept:** External hardware tokens (YubiKey 5-series,
    SoloKey 2, Feitian A4B, etc.) — non-extractable secure-element
    keys, device-bound, no sync. Works on macOS, Windows, Linux,
    **iPad via USB-C / Lightning / NFC**, and Android.
  - **Accept:** Windows Hello with TPM 2.0 + device-bound
    attestation.
  - **Accept:** Android with StrongBox + non-synced credential.
  - **Reject:** iCloud Keychain passkeys — synced via Apple's HSM
    cluster, not strictly device-bound. Not necessarily insecure,
    but the trust model now includes Apple's escrow.
  - **Reject:** Google Password Manager passkeys — same shape.
  - **Reject:** Software-only passkeys on systems without TPM or
    Secure Enclave — extractable if OS is compromised.

Enforcement is via **WebAuthn attestation**, evaluated at
registration time. The CA's registration endpoint validates the
attestation statement and rejects authenticators not on an
explicit AAGUID allowlist, with `userVerification: required`
and `authenticatorAttachment: cross-platform` (external hardware
only, no platform credentials).

```python
# CA registration policy (pseudocode)
allowed_aaguids = [
    YUBIKEY_5_USB, YUBIKEY_5_NFC, YUBIKEY_5C,
    SOLOKEY_2,
    FEITIAN_A4B,
    # plus any approved enterprise tokens
]

if registration.attestation.aaguid not in allowed_aaguids:    reject
if registration.attestation.fmt == "none":                    reject
if registration.user_verification != "required":              reject
if registration.authenticator_attachment != "cross-platform": reject
```

The result: every credential in the system is on hardware the
operator has vetted, requires user verification per use, and was
generated on-device with the private key non-extractable.

### Passkeys / synced credentials — explicitly out

The "passkey" branding covers a spectrum from genuinely
hardware-bound (YubiKey) to cloud-escrowed (iCloud Keychain). For
mssh's threat model we accept only the hardware-bound end. The
reasoning:

  - The mssh core property is "stolen credential is useless
    off-network." Phishing resistance — passkeys' headline win —
    is partially redundant given the CA-unreachability property.
  - Synced credentials shift trust to Apple/Google's HSM clusters,
    a dependency we don't otherwise have.
  - The implementation surface for "accept synced passkeys but
    not unsynced platform credentials" is precisely the kind of
    subtle attestation parsing where libraries have historically
    shipped CVEs.

Cleaner to reject the whole synced tier and document the rejection
than to thread the needle.

### Smart cards / PIV / PKCS#11

A separate hardware path with its own pros and cons; see
[future-ideas.md](future-ideas.md) §2. Works fine on desktop
Chrome/Firefox/Safari via OS keychain integration. **Does not
work in mobile Safari** — iPad/iPhone browsers can't use PIV
smart cards. If mobile is a target, this path doesn't help.

---

## The "stolen device" scenario

A common worry: if the user's phone or laptop is stolen, doesn't
the attacker get every credential on it?

Three layers of mitigation, in combination:

  1. **`userVerification: required`** — every WebAuthn assertion
     requires biometric or device PIN at the moment of use, not
     just at device unlock. A stolen unlocked device still demands
     biometric/PIN per authentication.
  2. **Hardware-bound, non-extractable keys** — passive malware
     on the device cannot exfiltrate the credential for later
     replay. The attacker must operate the device in real time.
  3. **mssh CA-unreachability property** — even granting the
     attacker active use of the device, they still need to reach
     the CA from a network position the CA accepts. Stolen device
     off-network authorizes nothing.

This isn't unique to passkeys. A laptop with `~/.mssh/key.pem` and
an unlocked screen has the same exposure, minus layer 2 (the cert
file is passively exfiltrable). The combination of (1) + (2) + (3)
is strictly stronger than the current mTLS-on-disk model.

The residual risk — coerced biometric use, "wrench attack" — is
the same residual risk every authentication scheme has. Not
solvable at the protocol layer.

---

## Hardware-only enrollment ceremony

The CA controls enrollment. WebAuthn's protocol model says the
authenticator generates the keypair on-device; there is no
"inject this credential" message. The operational outcome the
operator wants — "CA decides who gets enrolled; user receives a
pre-bound hardware token" — is achievable as an in-person
ceremony:

  1. User shows up at the admin station with their hardware token.
  2. Admin opens the CA's enrollment portal in a browser, logged
     in with their admin credentials.
  3. User plugs in their token. The portal initiates a WebAuthn
     registration ceremony.
  4. User touches the token (and enters PIN if configured).
  5. CA validates the attestation against the AAGUID allowlist,
     records the public key bound to the user's enrollment record,
     hands the token back to the user.

The token leaves the admin station already enrolled. No
credentials transit any other channel.

---

## Browser plugin path — what it can and can't fix

A plugin could in principle ease the credential / trust UX. In
practice the layering limits what it can do.

  - **Cannot** override TLS server-cert validation, inject CA
    roots, or intercept the TLS handshake. Browser extension APIs
    have never exposed the TLS validation path — the TLS layer is
    the browser's, not the extension's. The "public-CA could
    fake you" worry cannot be fixed via plugin.
  - **Can** manage credentials at the application layer (the
    1Password / Bitwarden pattern), sign custom challenges, render
    auth UI, talk to the page over message-passing APIs.

Two larger problems with the plugin path:

  - **Per-browser engineering.** Chrome, Firefox, and Safari each
    have distinct extension models; Safari's is the strictest. A
    serious plugin is three implementations.
  - **No mobile.** iOS Safari extensions are limited to content
    blockers and lightweight content scripts; they cannot run a
    credential-bearing auth protocol. Android Chrome has no
    user-installable extension model at all. If iPad/iPhone is a
    target — and it is, since that's the original driver — plugins
    don't help.

A browser plugin that holds an mssh credential and signs a custom
challenge over HTTPS is roughly the engineering cost of writing a
custom client app per platform, at which point the existing `mssh`
CLI is doing the same job with less surface area.

---

## Scope decision

The trust requirement above — *mssh-CA-only server-cert trust at
the device* — is satisfiable only on enterprise-managed browsers
with MDM-pushed pinning policy. That's a hard precondition for
**any** browser-based mssh feature. It splits cleanly:

### Admin portal — feasible

  - **Audience:** CA operators, admins, auditors. Small user
    count, all on employer-provisioned laptops the operator's IT
    team manages.
  - **Trust distribution:** mssh CA root pre-installed by IT
    during machine provisioning, **plus** MDM-pushed Chrome ADM /
    Firefox enterprise policy that pins `ca.example.com` to the
    mssh CA only (removing public CAs from trust for that domain).
    Without the pinning policy this feature does not ship.
  - **Authentication:** WebAuthn with hardware-token attestation
    allowlist (as designed above). Admins bring an enrolled
    hardware token to log in.
  - **Functionality:** what `mssh-admin` exposes today —
    enrollment management, policy editing, audit log search, cert
    minting — with a web UI rather than CLI.
  - **Trust scope:** the portal talks only to the CA, not to
    msshd hosts. No proxy-jump complexity. The CA already speaks
    mTLS; this just adds a browser-friendly entry point.
  - **Mobile:** desktop-only. iOS/Android can't push per-domain
    cert pinning to mobile browsers cleanly, and admin operations
    benefit from the larger screen anyway.

### End-user browser access — ruled out by trust requirement

[future-ideas.md](future-ideas.md) items 4 (HTTPS-app-proxy) and
10 (xterm.js bastion) compose into "any employee with a browser
can reach internal services." The trust requirement makes this
unworkable: the operator does not, in general, control every user
device, so the operator cannot guarantee MDM-pushed per-domain
cert pinning is in place. Without that, exposing msshd to a
browser preserves the public-CA attack surface, which the project
rejects.

This is **not deferred** — it's removed from scope by the
trust requirement. Comparable products (Cloudflare Access,
Pomerium, Teleport) accept the public-CA attack surface; mssh
deliberately doesn't. End users on arbitrary devices stay on the
`mssh` CLI, which controls its own trust store.

If at some point a per-site trust restriction becomes available
to web operators without enterprise MDM — a new browser API, a
revived form of cert pinning, etc. — this decision could be
revisited.

---

## Open questions

  - **Admin portal session lifetime.** Today admin certs are mTLS
    for `mssh-admin` CLI. Browser-portal sessions need their own
    lifetime model — session cookies, re-auth interval, etc.
  - **Audit semantics.** A web admin doing a 10-click workflow
    should produce a coherent audit trail, not 10 disconnected
    entries. Group by session ID.
  - **AAGUID allowlist maintenance.** New hardware tokens come
    out routinely. Who updates the allowlist; how do operators
    add a newly-purchased token model without a code change.
  - **Recovery for lost hardware tokens.** Today the answer is
    "admin re-enrolls." For a browser portal this means a separate
    bootstrap admin who can re-enroll the primary admin — a
    multi-person bootstrap. Design before the feature ships.
  - **MDM pinning policy distribution.** Concrete deployment
    story: which Chrome ADM key pins `ca.example.com` to the mssh
    CA only? What's the equivalent for Firefox enterprise
    policies? Edge? Safari (does enterprise pinning even exist
    for Safari)? An MDM-deployable bundle (JSON for Chrome, JSON
    for Firefox, .mobileconfig for Safari) should ship with the
    admin portal so the IT team has one-shot push material.
  - **Detecting the policy is in effect.** Before the portal
    serves any sensitive page, can it verify (via a JS probe,
    a custom header, anything) that the browser actually has the
    pinning policy applied? If the policy is missing the
    connection should be refused, not silently downgraded.
