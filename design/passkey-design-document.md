# Passkey Authentication: Design Document

*QR Code Cross-Device Login with Zero-Trust Server Architecture*

---

## Executive Summary

This document evaluates four architectural approaches to implementing passkey-based authentication where a user logs into a public-facing or untrusted device (kiosk, shared computer) using their phone via a QR code handshake.

The primary design goals are:

- Minimize trust placed in the public-facing web server
- Never expose user private keys to the network or server storage
- Avoid the need for a custom phone application
- Maintain cryptographic soundness against replay, phishing, and key-theft attacks

**After evaluation, this document recommends Option 2 (WebAuthn in mobile browser) as the default implementation. Option 4 (Layered: WebAuthn + Encrypted Vault) is recommended for high-security applications (financial services, healthcare, government) where defense in depth justifies the added complexity.**

---

## Background and Trust Model

### Core Passkey Mechanism

Passkeys use asymmetric public-key cryptography (ECDSA or EdDSA). At registration, the user's device generates a keypair. The public key is sent to the server; the private key never leaves the device. At authentication, the server sends a random challenge; the device signs it with the private key; the server verifies the signature with the public key.

No password is sent over the network, and the server never stores a secret that could be used to impersonate the user. Public keys are not sensitive — even if stolen, they cannot be used to forge signatures.

### QR Code Cross-Device Flow

When a user wants to authenticate on a public or untrusted device, the following high-level pattern is used:

- **Step 1:** Public device displays a QR code containing a unique session identifier.
- **Step 2:** User's trusted phone scans the QR code and opens the corresponding URL.
- **Step 3:** Phone establishes a back-channel connection (WebSocket) to the server using the session ID.
- **Step 4:** Phone performs the cryptographic operation (signing) using its private key.
- **Step 5:** Server relays the result to the public device and grants access.

### Trust Model Summary

The following table summarizes which components require trust in this architecture:

| Component | Trust Required | Why |
|-----------|----------------|-----|
| Phone hardware | High | Stores private keys in Secure Enclave / Keystore |
| Phone OS (iOS/Android) | High | Mediates access to the secure enclave |
| Mobile browser | Medium | Calls WebAuthn API; handles origin binding |
| Your web server | Low | Stores public keys (safe to leak); validates signatures with library |
| Network (HTTPS) | Medium | TLS protects the WebSocket; origin matters for WebAuthn |
| Third-party CA/MDS | Optional | Only required if using device attestation (skip if not needed) |

**Key insight:** the web server acts primarily as a message broker and signature validator. It never stores or sees private keys. Even if compromised, an attacker cannot forge signatures or impersonate users, because the private keys live in hardware-backed enclaves on user devices.

---

## Option 1: Self-Contained JavaScript Cryptography

### Overview

In this approach, all cryptographic operations happen in client-side JavaScript using the Web Crypto API (`crypto.subtle`). The server acts purely as a dumb message relay with no validation responsibilities. Private keys are stored client-side, encrypted with a user-chosen PIN.

### Architecture

- **Key generation:** Phone JavaScript generates an ECDSA keypair using `crypto.subtle.generateKey()`
- **Key storage:** Keypair is encrypted locally with AES-GCM using a hash of the user's PIN as the key, then stored in localStorage or sent as an encrypted blob to the server
- **Authentication:** User enters PIN; JavaScript decrypts the keypair locally; signs the challenge; transmits only the signature
- **Validation:** Performed by JavaScript on the public device, which has received the public key via the secure channel
- **Server role:** Generate session IDs, relay messages between devices, store encrypted keypair blobs (optional)

### Strengths

- Server is genuinely zero-trust — it never touches keys or validates anything
- Compromise of the server does not leak usable cryptographic material
- Full control over the implementation; portable across devices
- No dependency on browser WebAuthn API availability
- Educational value — every byte is auditable

### Weaknesses

- Private keys live in JavaScript memory during signing operations — not protected by hardware enclave
- Vulnerable to malicious JavaScript injection (XSS), browser extensions, or compromised dependencies
- PIN must be entered each time, which is a user experience burden and a phishable secret
- Higher implementation complexity — you are responsible for correct cryptographic implementation
- Less phishing resistance — no origin binding like WebAuthn provides
- Custom code that must be independently audited

### When Option 1 Makes Sense

- Targeting environments where browser WebAuthn is not available (rare today)
- Educational or research projects exploring the underlying cryptography
- Use cases requiring portable, exportable keypairs across arbitrary devices
- Internal tools where the threat model excludes XSS and malicious extensions

---

## Option 2: Browser-Native WebAuthn (Recommended Default)

### Overview

This approach uses the WebAuthn API built into all modern mobile browsers (Safari on iOS, Chrome on Android). When invoked, the browser delegates key generation, storage, and signing to the operating system's hardware-backed secure enclave (Apple Secure Enclave or Android Keystore). User authorization is performed via native biometric prompts (Face ID, Touch ID, fingerprint).

Crucially, this requires **no phone app installation**. The user simply opens the URL embedded in the QR code in their mobile browser, and the browser handles the rest.

### Architecture

- **Key generation:** Browser calls `navigator.credentials.create()` which invokes the OS secure enclave; keypair is generated in hardware
- **Key storage:** Private key is stored in the secure enclave (Apple Secure Enclave, Android Keystore); never exposed to JavaScript or the OS at large
- **Authentication:** Browser calls `navigator.credentials.get()` with a challenge; user authorizes via Face ID / Touch ID / fingerprint; enclave signs the challenge
- **Validation:** Server uses a well-audited WebAuthn validation library (e.g., `@simplewebauthn/server`, `py_webauthn`, `webauthn4j`) to verify the signature
- **Server role:** Generate challenges, store public keys, validate signatures, manage sessions

### Strengths

- Hardware-backed key storage — private keys are physically protected by dedicated security chips
- No phone app required — works in any modern mobile browser
- Native biometric UX — fast, familiar, and resistant to PIN phishing
- Origin binding — WebAuthn signatures include the originating domain, making phishing attacks impossible without DNS-level compromise
- Battle-tested standards — implements FIDO2/WebAuthn specifications used by Apple, Google, Microsoft, and the financial industry
- Minimal server code — validation is a single library call
- Strong resistance to OS compromise — even root access cannot extract enclave-bound keys
- Counter-based clone detection — authenticators include a monotonic counter that detects key cloning

### Weaknesses

- Server must store public keys and validate signatures — slightly more trust than pure relay
- Trusts Apple/Google implementations of the secure enclave (but these are heavily audited)
- Cannot export keys between devices easily (mitigated by iCloud Keychain / Google Password Manager sync, if desired)
- Requires HTTPS in production (a baseline requirement anyway)
- Device theft of an unlocked phone could allow authentication unless biometric is required per operation

### Server Hardening Requirements

Although the server's role is minimal, it must be implemented carefully:

- **Challenge generation:** Use cryptographically random bytes; store with a short TTL (60 seconds typical); enforce one-time use
- **Signature validation:** Always use a maintained WebAuthn library; never implement signature verification manually
- **Origin validation:** Verify the Origin and RP ID match expected values to prevent cross-origin abuse
- **Counter validation:** Track and validate the authenticator's monotonic counter to detect cloned credentials
- **Session binding:** After successful auth, issue a session token bound to the user and device
- **Rate limiting:** Limit authentication attempts per IP, per username, per device
- **HTTPS only:** WebAuthn requires a secure context; browsers will refuse to run it over HTTP
- **Logging and monitoring:** Log auth attempts and alert on anomalies; never log signatures or challenges themselves

### Sample Validation Code (Node.js)

```javascript
const { verifyAuthenticationResponse } = require("@simplewebauthn/server");

const verification = await verifyAuthenticationResponse({
  response: clientResponse,
  expectedChallenge: storedChallenge,
  expectedOrigin: "https://example.com",
  expectedRPID: "example.com",
  authenticator: {
    credentialID: userCredID,
    credentialPublicKey: userPublicKey,
    counter: userCounter,
  },
});

if (verification.verified) {
  // Issue session token, increment counter
} else {
  // Reject
}
```

### Why Option 2 Is the Recommended Default

- It achieves the design goal of minimizing trust while gaining hardware-backed security
- Implementation effort is the lowest of the four options
- It aligns with industry standards (FIDO2/WebAuthn)
- It is the path Apple, Google, and major banks have invested in
- Phishing resistance is genuinely strong (not just theoretical)
- The codebase is small and easy to audit — most of the security lives in the browser and OS, both of which are independently scrutinized

---

## Option 3: Hybrid (QR Bootstrap + WebSocket + WebAuthn)

### Overview

Option 3 combines elements of Options 1 and 2. The QR code is used to bootstrap a session, but a WebSocket then carries the subsequent communication. The actual cryptographic signing uses WebAuthn under the hood, but the orchestration is custom.

This is essentially Option 2 with a more elaborate session-binding mechanism, useful when you need fine-grained control over how the public device and phone communicate.

### Architecture

- **Bootstrap:** Public device displays QR code containing a session ID and WebSocket endpoint URL
- **Phone connects:** Phone scans QR, opens URL, establishes WebSocket using the session ID
- **Bidirectional channel:** Server now routes messages between the public device and phone over their respective WebSocket connections
- **Crypto operation:** Phone invokes WebAuthn (or pure JS crypto if preferred) to sign challenges
- **Result delivery:** Signature flows back through the WebSocket; server validates; public device is notified of success

### Strengths

- Single user action (one QR scan) for the entire flow — better UX than multi-QR handshakes
- Bidirectional communication enables real-time feedback ("phone connected," "awaiting biometric," etc.)
- Flexibility to use WebAuthn, pure JS crypto, or both depending on the use case
- Session-level isolation — each QR scan creates an independent ephemeral session
- Compatible with edge cases like delegated authentication, transaction signing, or multi-party approvals

### Weaknesses

- More moving parts than Option 2 — more code to write, test, and maintain
- WebSocket infrastructure adds operational complexity (sticky sessions, connection management, scaling)
- Custom orchestration layer must itself be hardened against session hijacking and replay
- Marginal security gain over Option 2 in most deployments

### When Option 3 Makes Sense

- You need real-time bidirectional communication beyond simple authentication (e.g., live transaction approval)
- You want to support both WebAuthn-capable and non-WebAuthn-capable devices in the same system
- You need to coordinate multiple parties (e.g., requesting approval from a co-signer)
- You have already invested in WebSocket infrastructure for other purposes

---

## Option 4: Layered (WebAuthn + Encrypted Vault)

### Overview

Option 4 combines WebAuthn (Option 2) with a server-stored, PIN-encrypted vault (a refinement of Option 1) to create two independent trust anchors. The user must demonstrate possession of both factors to authenticate, providing defense in depth that neither approach offers alone.

The encrypted vault holds the user's authentication policy and supplementary cryptographic material. The vault is encrypted client-side with a key derived from the user's PIN using Argon2id, then stored on the server as an opaque blob. WebAuthn provides a hardware-backed second signature using the phone's secure enclave.

### Architecture

- **Vault structure:** JSON document containing user policy, supplementary keypair, and WebAuthn credential metadata, encrypted with AES-256-GCM using an Argon2id-derived key
- **Vault storage:** Server holds the encrypted blob; cannot decrypt without the user's PIN
- **Two factors required:** Both PIN-vault signature and WebAuthn signature must validate for authentication to succeed
- **Policy in vault:** User-controlled authentication policy is signed and stored within the encrypted vault, preventing server-side tampering
- **Server enforces a floor:** Server requires a minimum policy regardless of vault contents to prevent downgrade attacks

### Registration Flow

- User scans QR code on public device
- Phone generates a supplementary vault keypair locally
- Phone invokes WebAuthn to create a hardware-backed credential (Face ID/Touch ID enrollment)
- Phone constructs a vault containing both keys plus user policy
- User chooses a PIN; phone derives encryption key via Argon2id
- Phone encrypts vault with AES-256-GCM; uploads encrypted blob to server
- Server stores: (a) encrypted vault blob, (b) WebAuthn public key, (c) Argon2id parameters

### Authentication Flow

- User scans QR code on public device
- Server sends: encrypted vault blob, fresh WebAuthn challenge, fresh vault challenge
- User enters PIN; phone decrypts vault locally
- Phone signs vault challenge with vault keypair (proves PIN)
- Phone invokes WebAuthn to sign WebAuthn challenge (proves hardware possession)
- Both signatures sent to server
- Server validates both signatures against stored public keys
- Server enforces user policy and grants access if both pass

### Strengths

- Two independent trust anchors — server breach, phone theft, or PIN compromise alone are insufficient
- Phishing resistance from WebAuthn's origin binding combined with vault portability from Option 1
- User-controlled, cryptographically protected policy — server cannot downgrade authentication requirements
- Recovery is built in — losing a device does not lock the user out, as long as PIN and recovery codes survive
- Supports tiered security — different operations can require different combinations of factors
- Resists offline brute-force of the vault — even if the encrypted vault leaks, the attacker still needs the WebAuthn private key (hardware-bound)
- Cross-device portability — vault can move between devices while WebAuthn remains anchored to the original hardware

### Weaknesses

- Highest implementation effort of all four options
- Two ceremonies required per authentication (PIN entry + biometric) — increased UX friction
- Recovery flows multiply: lost PIN, lost device, lost both — each needs distinct handling
- Argon2id parameters must be tuned carefully; getting them wrong weakens the entire vault
- Vault format requires careful versioning and migration as parameters or schemas change
- Both factors must be cryptographically independent — implementation errors that cross-contaminate them collapse the security model to single-factor

### Threat Resistance Matrix

The following table shows how each approach resists common attack scenarios:

| Threat | PIN Vault Alone | WebAuthn Alone | Layered |
|--------|-----------------|----------------|---------|
| Server breach | Protected | Protected | Protected |
| Phone theft (locked) | Protected | Protected | Protected |
| Phone theft (unlocked) | Protected | Vulnerable | **Protected** |
| Phishing site | Vulnerable | Protected | **Protected** |
| Shoulder-surfed PIN | Vulnerable | Protected | **Protected** |
| Offline vault brute force | Depends on PIN entropy | Protected (no vault) | **Protected (needs hw too)** |
| Malware in JS / browser | Vulnerable | Partially protected | Partially protected |

**The Layered column is strictly better than either single-factor approach. The combination covers each individual factor's weaknesses.**

### Critical Implementation Requirements

- **Argon2id parameters:** Minimum 64MB memory, 3 iterations, 4 parallelism — tune higher if your client devices can handle it
- **Unique per-user salt:** Generated server-side at registration, included in vault metadata, prevents rainbow tables
- **Authenticated encryption:** AES-256-GCM (not CBC) so the server cannot tamper with ciphertext
- **Policy signing:** User policy embedded in vault must be signed by the vault keypair so the server cannot modify it
- **Independent factors:** WebAuthn credential ID must not be derivable from vault contents, and vice versa — true independence
- **Server-side floor policy:** Server enforces minimum requirements independent of vault contents to prevent vault-based downgrade attacks
- **Vault versioning:** Include schema version in vault; support migration when parameters change
- **Replay protection:** Both challenges must be one-time-use with short TTL

### Variant: OAuth as a Binding Signal (Not as the PIN)

A natural question is whether OAuth tokens (from Google, Microsoft, etc.) could replace the user's PIN as the vault decryption key. This is **not recommended**, for several reasons:

- OAuth tokens are bearer credentials — anyone who obtains the token can decrypt the vault, breaking the zero-knowledge property
- OAuth tokens rotate (typically 1 hour), creating either a re-encryption burden or a permanent stable identifier that defeats the purpose
- Trust shifts from the user's secret to the OAuth provider's honesty — the provider could in principle replay tokens
- Network interception, malicious browser extensions, or provider compromise become vault-compromise vectors

However, OAuth can serve as an **additional binding signal** within the layered model — proving "this is the same Google account that registered this vault." In this variant:

- OAuth identity confirms account ownership at the server level
- PIN still decrypts the vault locally (vault remains zero-knowledge to the server)
- WebAuthn still anchors the authentication to specific hardware
- OAuth becomes a third weak factor, useful for account recovery flows and anti-abuse checks but not for vault encryption

**This is a sound use of OAuth in a layered model. Using OAuth as the vault key itself is not.**

### When Option 4 Makes Sense

- High-security applications: financial services, healthcare records, government services, cryptocurrency wallets
- Compliance-driven requirements (PSD2 strong customer authentication, FFIEC multi-factor guidance)
- Use cases where device theft and phishing are both significant threats
- Applications requiring tiered security (low-risk reads vs. high-risk writes)
- Cross-device portability is required while still wanting hardware-backed credentials
- User base expects and accepts higher friction in exchange for stronger security

### When Option 4 Is Overkill

- Consumer applications with low individual transaction value
- Use cases where UX friction is the primary churn driver
- Internal tools where the threat model does not include sophisticated attackers
- Teams without the engineering capacity to maintain a vault format and recovery flows

---

## Comparative Analysis

The following table compares all four options across key criteria:

| Criterion | Opt 1: JS Crypto | Opt 2: WebAuthn | Opt 3: Hybrid | Opt 4: Layered |
|-----------|------------------|-----------------|----------------|-----------------|
| Phone app required | No | No | No | No |
| Hardware-backed | No | **Yes** | Yes | **Yes** |
| Server trust | Minimal | **Low** | Low | Low |
| Phishing resistance | Weak | **Strong** | Strong | **Strongest** |
| Device theft resistance | Strong (PIN) | Moderate | Moderate | **Strongest** |
| Recovery support | Vault re-download | Re-enroll device | Re-enroll device | **Vault + re-enroll** |
| Portability | **High** | Low | Low | **High** |
| Implementation effort | High | **Low** | Medium | Highest |
| UX friction | Medium (PIN) | **Low (biometric)** | Low (biometric) | High (both) |

### Decision Guide

Use the following heuristics to select between the options:

- **Choose Option 1 if:** You need cross-platform portability, lack browser WebAuthn support, or are exploring the underlying mechanics. Rarely the right choice for production.
- **Choose Option 2 if:** You want strong security with minimal complexity. This is the right answer for most consumer applications, internal tools, and SaaS products.
- **Choose Option 3 if:** You need real-time bidirectional communication between the phone and public device beyond simple authentication.
- **Choose Option 4 if:** You operate in a regulated industry, handle high-value transactions, or face threat models that include both sophisticated phishing and device theft.

---

## Recommendation

**Implement Option 2 (Browser-Native WebAuthn) as the default. Implement Option 4 (Layered) when defense in depth is justified by the threat model.**

Rationale:

- **Option 2 covers most use cases:** Hardware-backed security, phishing resistance, and minimal server trust are achieved with low implementation cost and excellent UX. For consumer apps, SaaS, and internal tools, this is the right answer.
- **Option 4 covers high-stakes use cases:** When the threat model includes device theft, sophisticated phishing, or regulatory requirements for multi-factor authentication, the layered model provides defense in depth that single-factor approaches cannot match.
- **Option 1 and Option 3 are situational:** Option 1 is useful for portability and education but lacks hardware backing. Option 3 is useful when bidirectional communication is needed beyond authentication.

For the QR code cross-device flow described in this document, start with Option 2 to validate the end-to-end experience and infrastructure. If the threat model warrants it, evolve to Option 4 by adding the encrypted vault layer without disrupting the existing WebAuthn flow.

---

## Implementation Plan

### Phase 1: Server Infrastructure (Option 2 Foundation)

- Set up HTTPS-only web server with valid TLS certificate
- Choose and integrate a WebAuthn library (e.g., `@simplewebauthn/server` for Node.js)
- Design database schema for users, credentials (public key, credential ID, counter), and challenges
- Implement challenge generation with cryptographic randomness and TTL enforcement
- Implement rate limiting and abuse monitoring

### Phase 2: Registration and Authentication Flows

- Build registration endpoint that returns WebAuthn creation options
- Build verification endpoint that validates the registration response and stores the public key
- Build QR code generation logic that encodes a session ID and URL
- Build authentication endpoint that returns WebAuthn request options
- Build signature verification endpoint that validates and increments the counter
- Build session token issuance after successful authentication
- Test on iOS Safari and Android Chrome with real devices

### Phase 3: Hardening (Option 2 Production-Ready)

- Conduct security review and penetration testing
- Implement comprehensive logging and alerting
- Add multi-device support (multiple credentials per user)
- Add fallback / recovery mechanisms (backup codes, secondary device enrollment)
- Document operational procedures for credential revocation and incident response

### Phase 4: Optional Layered Upgrade (Option 4)

- Design vault schema with versioning
- Select and benchmark Argon2id parameters for target client devices
- Implement client-side vault encryption/decryption (Web Crypto API)
- Add vault storage endpoints to the server (opaque blob handling)
- Implement user policy mechanism with vault-side signing
- Implement server-side floor policy enforcement
- Build recovery flows for: lost PIN, lost device, lost both
- Conduct second security review focused on the layered model
- Gradually enroll users with opt-in or risk-based prompts

---

## Risks and Mitigations

- **Risk: Lost phone.** Mitigation: support multi-device enrollment; allow users to register two or more devices so loss of one does not lock them out. In Option 4, vault portability provides additional recovery path.
- **Risk: Browser bugs in WebAuthn implementation.** Mitigation: monitor security advisories; require minimum browser versions; provide a fallback authentication path for affected users.
- **Risk: Server compromise leading to public key tampering.** Mitigation: store public keys with integrity checks; use a write-only credential log. In Option 4, the vault's signed policy prevents policy downgrade attacks.
- **Risk: User social-engineered into registering an attacker's device.** Mitigation: require existing authentication to register a new device; require a cool-down period or out-of-band confirmation for new device enrollment.
- **Risk: Replay of captured signatures.** Mitigation: enforce one-time-use challenges with short TTL; counter validation detects cloned authenticators.
- **Risk (Option 4): Vault leaks and is brute-forced offline.** Mitigation: Argon2id with strong parameters; require high-entropy PIN or supplementary device-stored secret; rotate vault encryption on parameter upgrades.
- **Risk (Option 4): Both factors become entangled, collapsing to one.** Mitigation: enforce cryptographic independence between vault and WebAuthn; audit that vault contents cannot derive WebAuthn material and vice versa.

---

## Conclusion

Passkey-based authentication via WebAuthn provides a strong combination of security, usability, and implementation simplicity. For most applications, Option 2 (WebAuthn alone) is the right choice — it eliminates passwords, resists phishing, requires no phone app, and minimizes server trust.

For high-security applications, Option 4 (Layered) adds a PIN-protected encrypted vault as a second factor, providing defense in depth against device theft and offline attacks while preserving the phishing resistance of WebAuthn. The added complexity is justified when the threat model warrants it.

Option 1 remains viable as a portable, cross-platform approach when WebAuthn is unavailable. Option 3 is the right answer when bidirectional real-time communication is required beyond simple authentication.

The fundamental security insight remains: in all four options, the server never holds private keys. Even a complete server compromise cannot impersonate users, because the cryptography happens on devices the server never touches. The four options differ primarily in where the keys live (JavaScript memory, hardware enclave, or both) and how many independent factors must succeed for authentication to complete.
