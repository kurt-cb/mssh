# 11. Embedded Implementations

This document is the implementer's guide for Dropbear-class mssh implementations: embedded devices, initramfs recovery shells, OpenWrt routers, containers measured in megabytes, IoT gear with kilobytes of RAM to spare for SSH. The goal is that the constrained cert profile and a careful library choice make these implementations practical, not heroic.

## What constrained means in practice

A constrained implementation:

- Validates only the constrained profile (`02-cert-profile.md`).
- Does not chase CRL Distribution Points or OCSP. Revocation is by short validity.
- Does not perform path-building over arbitrary CA hierarchies. The trust root is a single pinned cert (or a very small set), and chains are at most 2 deep (root → intermediate → leaf).
- Does not implement the full conformance test suite for itself. It validates received certs against the profile rules but does not act as a CA, so the issuance-side conformance tests are not relevant.
- Cannot host the embedded CA. CA work is too heavy for these targets.
- Cannot serve as a hop in a chain (it can be an endpoint, but not relay).
- Supports cert rotation only as a client side initiator, not as a server-side issuer. Server-side rotation involves CA traffic, which constrained servers do not have the bandwidth or resources for.

The result is an implementation that can authenticate cert-bearing users to a small device, and that can authenticate the device to a larger network with a CA-issued machine cert. Both functions are achievable in well under 200 KB of binary on top of Dropbear's existing size.

## Library choice

Three realistic options:

**mbedTLS.** Mature, widely deployed in embedded space, has X.509 support that is intentionally a subset of full X.509 — which lines up well with the constrained profile. Approximately 60 KB stripped for the core, plus X.509 modules.

**BearSSL.** The most minimal; the X.509 implementation is the smallest of the actively maintained libraries. Constant-time crypto. Approximately 40 KB stripped. Less ecosystem support than mbedTLS but a cleaner codebase.

**OpenSSL with build-time trimming.** Possible but painful — even with `no-deprecated`, `no-tls`, `no-comp`, etc., OpenSSL's X.509 still drags in hundreds of KB. Not recommended for constrained targets unless OpenSSL is already on the system for other reasons.

**Recommendation for new constrained implementations:** mbedTLS. Best balance of size, X.509 capability, and community support. BearSSL is a reasonable choice when size pressure is extreme.

## What's needed from the library

A constrained validator needs the library to provide:

- DER X.509 parsing (cert, extensions).
- Signature verification (ECDSA, Ed25519, RSA-PSS — at least one).
- Cert chain validation against a pinned root.
- Public key extraction (for computing fingerprints and verifying handshake signatures).
- GeneralizedTime parsing.

A constrained validator does *not* need:

- CRL parsing.
- OCSP client.
- AIA chasing.
- Name constraints validation.
- Policy constraints / policy mappings.
- Subject Alternative Name handling beyond `dNSName` and `iPAddress`.

This matches mbedTLS's `MBEDTLS_X509_USE_C` mode with most optional features disabled. The build trims to roughly the necessary set.

## Key storage

Constrained devices typically don't have smartcards. The realistic options:

- **Local keystore in flash.** Encrypted with a device-unique key derived from hardware (e.g., TPM-backed, or a hardware-fused per-device secret). Reasonable for routers and appliances.
- **TPM-backed.** Where the device has a TPM, store the cert private key sealed to TPM PCRs so it's available only when the device is in expected state.
- **PKCS#11 if available.** OpenWrt and similar full-featured embedded Linux distros may have PKCS#11 modules for HSMs or secure elements. mssh supports these unchanged from the full implementation.

The threat model assumes a device with a software keystore is less secure than one with hardware-backed keys. Operators choose accordingly.

## Cert acquisition

How does a constrained device get its cert? Three patterns:

**Pre-provisioned.** During device manufacture or initial deployment, the operator runs a provisioning step that generates a keypair on the device, submits a CSR to the CA, receives a cert, and installs it. The device then runs with that cert until it expires; renewal is similarly out-of-band.

For long-running embedded gear (a year+ between updates), this means machine certs at the long end of the validity range (30–90 days for `machine` type) with scheduled renewal. The device dials home to the CA over its own network connection to renew.

**Bootstrapped via a co-located full implementation.** A more capable host nearby (a management gateway, a controller) holds an admin cert and provisions the embedded device. This is common for IoT fleets — a fleet management system handles cert lifecycle on behalf of devices that don't have the resources to do it themselves.

**Self-renewing.** The device itself holds an admin-grade cert capable of requesting new device certs. This is dangerous (the admin cert is now on the device, where it can be stolen) and only appropriate where the device's security boundary is strong.

## Validation simplifications

Because constrained validators don't follow CRL or OCSP, they rely on:

1. **Short cert validity.** A cert valid for 30 days is "revoked" within 30 days by simply not being renewed. This is the principal revocation mechanism.
2. **Immediate cert reissuance on suspected compromise.** When a device is suspected to be compromised, the operator revokes the cert at the CA (so other parts of the deployment honor the revocation) and provisions a fresh cert to the device. The device's currently-deployed cert remains valid until expiry, but any host *talking to* the device performs full revocation check and refuses.

This means a compromised constrained device with a stolen cert can continue to abuse the cert until its validity expires. The mitigation is short validity. For a `machine` cert valid 7 days (well within the 30-day max), the worst-case exposure window is 7 days.

For high-security deployments where this is insufficient, the answer is to use a full implementation on the device, with proper revocation checking. The constrained profile is a deliberate compromise — small code, strong-enough-for-most-cases security.

## Hop chain validation: constrained role

Constrained implementations can be the **destination** of a hop chain (e.g., an admin reaches an OpenWrt router through corporate jumphosts), but cannot be **hops themselves**. This is because being a hop requires:

- Authenticating an inbound connection (manageable).
- Opening an outbound connection to another sshd (manageable).
- Verifying a cert and signing a hop attestation (manageable).
- Holding a `hop-eligible` cert with the right `mssh-hop-deleg` extension (manageable).
- Carrying the operational burden of being on the critical path for other people's sessions (the real cost).

The last item — being a hop is operationally serious — is the reason constrained implementations don't take this role. A flaky router that drops connections every few hours might be acceptable as an endpoint but unacceptable as a hop.

Destination role: the constrained sshd receives the hop chain message, validates each hop's cert against the trust root, validates signatures, and applies the user cert's hop-deleg policy. All operations within reach of a constrained validator.

## Channel plugins: constrained role

Constrained implementations typically do not host channel plugins. The plugin model assumes process management, IPC, and per-plugin user accounts — concepts available on full Linux but often absent on constrained systems.

Where a constrained server needs an application-layer capability (e.g., a small VPN function), the recommended pattern is to compile the function directly into sshd as a hard-coded "channel type" handler. The cert's `mssh-channel-policy` still gates access; the difference is that the handler is built-in rather than a separate process. This trades flexibility for simplicity, which is the constrained design tradeoff in general.

## Recovery and reset

A constrained device whose cert has expired and which cannot reach its CA is, by design, locked out. The recovery is physical: console access, factory reset, fresh provisioning. This is uncomfortable but correct — a deployment that allows network-only recovery of cert state must trust *something* over the network, and the right thing to trust is the cert. There is no password fallback; there cannot be.

For deployments where physical recovery is prohibitive, the operator should either:

- Provision longer-validity certs (still bounded by the profile maximums) to reduce the chance of expiry without renewal.
- Maintain redundant management paths (out-of-band serial console, IPMI) accepting that those paths have their own trust model.
- Use a full mssh implementation that can locally cache trust state and rotate certs from longer-lived material.

## Footprint targets

Reference targets for a constrained mssh implementation on top of Dropbear:

| Component                   | Size (stripped) |
|-----------------------------|----------------:|
| Dropbear, classic            | ~250 KB         |
| Plus mbedTLS (X.509 subset)  | +60 KB          |
| Plus mssh cert profile val  | +25 KB          |
| Plus hop chain validation    | +10 KB          |
| Plus rotation client logic   | +15 KB          |
| **Total**                    | **~360 KB**     |

For comparison, OpenSSH + OpenSSL on a typical embedded Linux is on the order of 2-3 MB. The constrained mssh footprint fits in flash budgets that classic Dropbear already targets.

## Testing constrained implementations

The conformance suite (`03-conformance.md`) is divided into mandatory tests (every implementation must pass) and CA-only tests (only CAs need to pass). Constrained implementations must pass the validation tests — accepting valid certs, rejecting invalid ones — but are exempt from the issuance and policy tests.

A planned addition to the conformance harness is a "constrained profile" mode that runs only the relevant test subset and reports pass/fail accordingly. Mbed TLS and BearSSL reference builds are tested against this subset as part of the mssh reference distribution's CI.

## Implementation languages

The mssh protocol is implementation-language-agnostic. The wire format is defined in terms of bytes; the cert format is standard X.509; the cryptographic primitives are standard. Any language with a competent crypto library can implement mssh.

The project's intent is to support multiple reference implementations rather than blessing exactly one.

### Reference implementation: C with Mbed TLS

The primary reference implementation targets C, linking Mbed TLS (Apache 2.0, compatible with mssh's license). This choice reflects:

- **Embedded reach.** Mbed TLS is widely used in embedded space. A C implementation of mssh can be ported to Dropbear-class targets without language-portability gymnastics. Vendors who ship classic SSH today predominantly ship C; adoption is easier when the language matches.
- **Library compatibility.** Mbed TLS, OpenSSL, and the other realistic crypto libraries are all C. A C implementation links directly without FFI overhead, marshalling, or impedance mismatches.
- **Operational familiarity.** Engineers who maintain OpenSSH and Dropbear are C engineers. They can read and extend mssh in C without learning a new ecosystem.

The C implementation is held to modern memory-safety practice, not 1999 C:

- Bounded readers for every parser, with explicit length checks before every read.
- No allocation in the authentication hot path. Static arenas sized at startup; out-of-arena is a fatal error, not silent corruption.
- Fuzz targets for every parser. CI runs AFL or libFuzzer continuously. Coverage tracked.
- Static analysis mandatory: clang-tidy, scan-build, and a third-party analyzer (Coverity, CodeQL) in CI.
- ASan, UBSan, and MSan builds in CI on every PR.
- The OpenSSH-style privsep model preserved: the network-facing code runs as an unprivileged child.

This discipline matters more than the language choice. A C implementation written this way is substantially safer than OpenSSH's organically-grown codebase, which carries 25 years of accumulated technical debt.

### Other reference implementations

The project welcomes additional reference implementations in other languages. Two are explicitly anticipated:

**Python.** Useful for prototyping, conformance testing, and education. Python is a natural choice for the CA's reference implementation (where embedded constraints don't apply) and for tools that exercise the protocol against C-based servers. The slow performance and large binary size of Python are not concerns for these uses. A Python implementation also serves as a "second opinion" that catches places where the spec is ambiguous — implementers in different languages frequently make different interpretations of the same spec text, and the disagreements are bug reports against the spec.

**Rust.** Increasingly the language of choice for new security-critical infrastructure. Rust's memory safety story addresses the largest class of CVEs that have plagued C-based SSH implementations. The embedded story is improving — `no_std` Rust is real, embedded-hal is mature — though Dropbear-class targets (8 MB flash, 32 MB RAM) remain practically out of Rust's reach in v1. A Rust implementation for full-feature deployments is welcome and would be a meaningful contribution.

The project's posture: ship a C reference that runs everywhere, encourage additional implementations in safer languages for full-featured deployments, accept that the embedded targets are C-dominated and design accordingly.

### Interoperability is the test

The conformance test suite is the contract between implementations. An implementation in any language that passes the suite is a conformant mssh implementation. The suite itself is language-agnostic — it consists of test vectors (binary blobs, expected behaviors, expected error codes) that any implementation can be evaluated against.

For the first year of the project, the reference C implementation and the Python prototype will be developed in lockstep, with the test suite serving as the interoperability check between them. This catches both implementation bugs and spec ambiguities. Once the protocol has stabilized, the Python implementation may be retired or maintained as a teaching tool; the C implementation continues as production-grade.
