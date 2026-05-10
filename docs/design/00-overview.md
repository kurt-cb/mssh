# 00. Overview

## What mssh is

A specification for a certificate-first variant of the SSH protocol. The on-wire framing of SSH is preserved; the authentication, trust, and lifecycle layers are replaced.

An mssh server is an SSH server that:

1. Refuses password authentication unconditionally.
2. Authenticates clients via X.509 certificates conforming to the mssh cert profile.
3. Validates each cert against a configured trust root and against extension-encoded policy (source-address binding, time windows, hop delegation, etc.).
4. Validates the full chain of intermediate hops when reached through `ProxyJump`-equivalent forwarding, and rejects connections whose identity has been silently rewritten in transit.
5. Supports mid-session certificate rotation and time-extension requests, brokered by an external CA over a defined mTLS REST interface.
6. Falls back to classic SSH (key-based, no certs) only when the operator has explicitly enabled legacy mode for a specific peer.

An mssh client is the symmetric counterpart: presents a cert, validates the server's cert, participates in rotation, and refuses to connect to legacy peers unless explicitly configured to.

## Goals

- **Eliminate passwords from the SSH ecosystem.** Not deprecate. Remove. Unconditionally, including in legacy modes.
- **Be deployable without abandoning existing SSH keys.** Users keep their `id_ed25519` / `id_rsa` / etc. The mssh cert is a CA-attested wrapper around the user's existing public key, not a replacement. SSH agents, key files, third-party services (GitHub, etc.) all continue to work unchanged.
- **Make certificate-based access the easy path.** A small operator with two hosts should be able to bootstrap a working CA, enroll a handful of users, and have everything Just Work. An enterprise with thousands of hosts should be able to plug in their existing PKI through a defined interface.
- **Make multi-hop SSH safe.** Today, `ssh -J jump1,jump2 dest` gives the destination no way to verify the chain. mssh makes the chain part of the authenticated identity.
- **Make access time-bounded by default.** Certs carry validity windows measured in hours to days, not years. Mid-session extensions are a first-class operation. Expired sessions terminate cleanly.
- **Keep the on-wire protocol small.** mssh rides on the existing SSH `publickey` userauth method with extended algorithm names; hop chain and lifecycle events add a handful of message types. The wire-level change is genuinely small.
- **Stay implementable on small systems.** Dropbear-class implementations are a first-class target, not an afterthought. A constrained cert profile is defined explicitly to keep parser and validation code small.
- **Defer extension to extension points.** Authenticated channels (VPN, database proxy, app gateways, etc.), LDAP/AD integration, advanced CA policy — all live behind defined interfaces, not in the core.

## Non-goals

- A new transport protocol. mssh uses SSH-TRANS as defined in RFC 4253. KEX, ciphers, MACs unchanged.
- A new file transfer subsystem. SFTP and SCP are untouched.
- A new VPN, database proxy, kubernetes gateway, or any other application-layer service. The authenticated-channel plugin protocol is defined; only a trivial `echo` reference plugin ships.
- A new DNS validator. The system resolver is used.
- A replacement for password authentication. There is no replacement. Passwords are gone.
- A replacement for existing SSH keys. Existing keys are wrapped in certs, not replaced. The cert is metadata; the key remains the credential.
- A flag-day migration. Coexistence with classic SSH is supported via the legacy bridge in both directions (server-side and client-side), with mandatory sunset dates so coexistence doesn't become permanent.

## Threat model summary

The full threat model is in `12-threat-model.md`. In brief:

**In scope:**
- Theft or compromise of long-lived user credentials. (Mitigated by short-lived certs and mandatory rotation.)
- Lateral movement via stolen SSH keys. (Mitigated by source-address binding and chain validation.)
- Impersonation across hop boundaries. (Mitigated by hop chain attestation.)
- Compromised intermediate hops attempting to redefine user identity. (Mitigated by chain validation at the destination.)
- Stale or revoked certs being replayed. (Mitigated by short validity, in-session rotation, and revocation checks at issuance and connection.)
- Coercion of a CA into issuing non-conforming certs. (Mitigated by the conformance program and sshd-side profile validation.)

**Out of scope:**
- Endpoint compromise. If the client machine is fully owned, the attacker has the smartcard PIN session and the cert. We do not attempt to defend against this beyond requiring smartcards to limit key extraction.
- Compromise of the root CA. If the root signing key is stolen, the deployment must be rebuilt. We provide rotation and revocation primitives but no magic.
- Side-channel attacks on the crypto library. Out of scope; defer to library choice.
- Quantum attacks. Algorithm agility is built into the cert profile, but no PQ algorithms are mandated in v1.

## Reading order

The design documents are numbered in the order they're best read:

- `00-overview.md` — this document
- `01-architecture.md` — components and process boundaries
- `02-cert-profile.md` — the X.509 cert profile
- `03-conformance.md` — CA conformance and attestation
- `04-handshake-and-hop-chain.md` — the on-wire protocol changes
- `05-rotation-2fa-lifetime.md` — cert lifecycle within a session
- `06-ca-rest-api.md` — the CA REST API
- `07-embedded-ca.md` — the in-tree CA for small deployments
- `08-legacy-bridge.md` — coexistence with classic SSH
- `09-channel-plugin-interface.md` — authenticated channel framework
- `10-dnssec-and-sshfp.md` — DNS-layer defenses
- `11-embedded-implementations.md` — Dropbear-class targets
- `12-threat-model.md` — what mssh defends against
- `13-name-resolution-and-identity.md` — how mssh handles non-DNS names and IPs
- `14-debuggability.md` — operational visibility and the end of "permission denied (publickey)"
- `15-ssh-key-compatibility.md` — how mssh works with the SSH keys you already have, and the user-enrollment migration story

The normative wire-level specification is in `../spec/mssh-protocol.md`.

## Glossary

- **mssh** — The variant of SSH defined by this document set.
- **Classic SSH** — Pre-mssh SSH as defined by RFC 4251–4254 and OpenSSH's extensions.
- **Cert** — Unless otherwise qualified, an X.509 certificate conforming to the mssh constrained profile.
- **CA** — Certificate authority. Issues certs.
- **External CA** — A CA implemented as a separate daemon, reachable over the defined mTLS REST API.
- **Embedded CA** — A minimal CA built into the sshd binary for small deployments.
- **Trust root** — A self-signed root CA cert configured as trusted by sshd or the client.
- **Constrained profile** — The subset of X.509 that small implementations must implement.
- **Full profile** — The complete mssh cert profile, including revocation, AIA, and other extensions that constrained implementations may skip.
- **Hop chain** — The sequence of intermediate mssh hops a connection traverses, attested by signed messages.
- **Source-address binding** — A cert extension that restricts which network address(es) may use the cert.
- **Legacy peer** — A peer that speaks classic SSH, not mssh.
- **Legacy mode** — A per-host opt-in mode that allows talking to a specific legacy peer.
- **ACPP** — Authenticated Channel Plugin Protocol. The JSON-RPC-over-Unix-socket interface for channel plugins. VPN, TCP proxy, kubernetes API gateway, and similar uses are all built as ACPP plugins.
- **2FA** — Second factor authentication. In mssh, performed at the CA at cert issuance time, not at sshd at connection time.
