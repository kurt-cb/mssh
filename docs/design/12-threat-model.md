# 12. Threat Model

This document states explicitly what mssh defends against, what it does not, and the assumptions underlying both. It is informative — the normative protocol behavior is in the other documents — but it is load-bearing for design review.

## Adversary types

**Network adversary (passive).** Can observe all packets between endpoints. Cannot inject, modify, or replay. mssh defends fully against passive adversaries via TLS-level transport encryption (per SSH-TRANS) and signed cert exchange. This is unchanged from classic SSH.

**Network adversary (active).** Can observe, modify, inject, drop, and replay packets. May operate at any point in the network path. mssh defends against active adversaries via the same SSH-TRANS protections plus cert chain validation. The session id binding makes replay of auth messages or hop attestations into different sessions impossible.

**DNS adversary.** Can poison DNS responses, redirect lookups to controlled servers, or block legitimate responses. mssh defends with mandatory DNSSEC validation (`10-dnssec-and-sshfp.md`). The fallback in non-DNSSEC zones is `DnssecException` configuration, which makes the trust extension explicit.

**Compromised intermediate hop.** A jumphost the user transits whose cert is validly held but whose operator is hostile or whose process is compromised. mssh defends by validating the user's auth signature at the destination — the hop cannot rewrite the user identity. It defends partially by requiring the user cert's `mssh-hop-deleg` to explicitly permit this hop. It does *not* defend against the hop logging the session contents — once bytes pass through a hop, the hop sees them. This is fundamental to forwarded sessions and is not unique to mssh.

**Stolen cert key.** An attacker has obtained the cert's private key (extracted from a software keystore, intercepted during provisioning, etc.). mssh defends by:
- Short cert validity (worst-case exposure measured in hours for user certs).
- Source-address binding (the stolen cert is useless from a different network).
- Hop delegation rules (a stolen cert cannot acquire hop privileges it did not have).
- Smart card / HSM key storage where supported (prevents extraction in the first place).
- Revocation (in full-profile deployments with online checks).

**Compromised legitimate user.** The user themselves is acting maliciously, or coerced. mssh defends weakly here: an authenticated user can do everything their cert permits. Defense in depth requires the cert to be narrowly scoped (least privilege), audit logging at the CA and at each sshd, and time-window restrictions to limit the window of misuse.

**Compromised CA (intermediate).** An attacker has obtained an intermediate CA's signing key. They can mint arbitrary certs under that intermediate. mssh defends partially with:
- Name constraints in the intermediate, restricting the certs it can issue.
- Path-length constraints, restricting depth.
- Revocation of the compromised intermediate at the root, after which its certs cease to validate.
- Audit logs at the CA may surface unauthorized issuance.

**Compromised CA (root).** The root signing key is stolen. This is catastrophic — the attacker can mint a replacement intermediate and issue any cert under it. mssh provides no in-band recovery; deployment must be rebuilt with a new root and all peers reconfigured to trust it. The mitigation is operational: keep the root key offline, accessed only for the rare intermediate-signing ceremony, ideally with hardware backing (HSM, smart card, air-gapped machine).

**Compromised host (server side).** A host running sshd is compromised. The attacker has the server's cert key and any in-memory session state. mssh limits damage by:
- Sessions are bound to specific server cert; revoking the cert invalidates the host's identity going forward.
- Server cert is short-lived; even without explicit revocation, it expires.
- The attacker cannot impersonate other hosts (cert subject is bound).
- The attacker sees only the sessions currently traversing this server; cannot access past sessions.

A compromised server can, however, harvest credentials of users currently logged into it, log session contents, and act as a hostile hop for sessions it relays. This is inherent to server compromise and not unique to mssh.

**Endpoint compromise (client side).** The user's machine is compromised. The attacker has the smartcard PIN session (if a smartcard is in use) and can use the cert until the session ends or the cert expires. mssh does not attempt to defend against this beyond:
- Requiring smartcards to prevent key *extraction* (the attacker can use the key while on the machine but cannot exfiltrate it).
- Short cert validity limits the duration of misuse.
- Source binding limits the network locations of misuse.

A motivated attacker with full endpoint compromise has won; no SSH variant fixes this.

**Insider with admin access.** Someone with legitimate CA admin or sshd admin access misuses it. mssh defends with audit logging — every cert issuance, revocation, and admin operation is logged with the actor's cert identity. Detection is human; prevention is operational (separation of duties, approval workflows, etc.).

## Assumptions

These are the assumptions on which mssh's security claims rest. If they fail, claims fail.

**A1: The crypto library is correct.** mbedTLS, OpenSSL, BearSSL — implementations are presumed correct in their cryptographic primitives. Known CVEs in past versions are patched. Side channels in the library are out of scope for mssh's design.

**A2: The kernel is honest.** The host operating system is presumed not to actively betray sshd or the mssh client — i.e., we are not defending against the kernel exfiltrating keys, lying about syscall results, etc. Hardware that subverts the OS (malicious firmware) is also out of scope.

**A3: Clocks are reasonably synchronized.** Cert validity windows depend on agreement about the current time. Default clock skew tolerance is zero; deployments may set a small skew (minutes) if operationally necessary. Hosts whose clocks are off by hours fail cert validation. This is correct — large clock skew is a security signal.

**A4: The trust root is genuinely trusted.** The root CA cert(s) configured on each host and client are presumed to represent the actual organizational authority. Mechanisms for distributing trust roots are out of scope — typically configuration management or initial provisioning.

**A5: The CA's authentication of users is sufficient.** Whatever 2FA, smartcard PIN, etc., the CA requires is presumed to actually verify the user. If the CA accepts weak 2FA, the deployment inherits that weakness.

**A6: Audit logs are reviewable.** mssh generates extensive audit logs but does not analyze them. The deployment must have processes for reviewing logs to detect misuse.

**A7: Operators read warnings.** mssh issues operational warnings (DNSSEC exceptions, legacy hosts, weak configurations). The model presumes operators read and act on warnings, not that warnings prevent misconfiguration.

## Specific defenses, in catalog form

**Against credential theft of long-lived keys:** No long-lived keys exist for user auth in the cert path. The user's smartcard or local keystore key is the only long-lived material on the user side; the cert that key signs is short-lived. Theft of the cert without the key is useless; theft of the cert key requires endpoint compromise (which mssh does not defend against, by A2-extension).

**Against lateral movement via reused keys:** Source-address binding prevents a stolen cert from being used from a different network. Hop delegation rules prevent a stolen cert from being used to reach hosts the original cert did not target.

**Against impersonation across hops:** The user's auth signature is computed over the session id and forwarded verbatim. No hop can forge it. The destination validates against the user's cert directly, bypassing any tampering at hops.

**Against stale or revoked cert replay:** Short validity, in-session rotation, and revocation checks at sufficiently capable deployments.

**Against compromised CAs issuing non-conforming certs:** Runtime profile validation at sshd. A non-conforming cert is rejected regardless of which CA issued it.

**Against weak 2FA at issuance:** sshd policy can require specific 2FA method OIDs and freshness windows, refusing certs that don't meet the bar.

**Against DNS poisoning:** Mandatory DNSSEC validation; SSHFP cross-check where available.

**Against TOFU host-key acceptance attacks:** Eliminated. There is no TOFU in mssh — host identity is cert-validated.

## Specific things we do not defend against

**Endpoint compromise.** Stated explicitly.

**Cryptanalysis of selected primitives.** If ECDSA P-256 is found broken, deployments must rotate to a different algorithm via the profile's algorithm agility. mssh does not protect against the algorithm being broken in itself; it provides a path to recover.

**Quantum computers.** Same answer. Algorithm agility is in place; PQ algorithms are not mandated in v1.

**Side-channel attacks on smartcards or HSMs.** Out of scope; smartcard vendors' problem.

**Coercion of legitimate users.** Rubber-hose attacks succeed against any system. mssh does not defend.

**Confidentiality of session contents from hops.** Forwarded sessions are visible to forwarders. Not unique to mssh.

**Availability attacks.** mssh makes no special claim about resistance to DoS, including against the CA, against sshd, or against the DNS resolution path. Operators are expected to deploy with standard DoS mitigations.

**Supply chain attacks on mssh itself.** A compromised mssh binary defeats mssh. Standard supply chain hygiene (reproducible builds, signed releases, audited distributions) applies but is out of scope for this design.

## What an attacker still might do

A useful exercise. Given everything above, what can a determined attacker still achieve?

- Compromise a user's endpoint, ride the smartcard session, behave as the user until the next 2FA refresh requirement.
- Compromise a hop, log session contents passing through, log who connected to whom.
- Compromise the CA's logs to delete evidence of their malicious issuances (the append-only Merkle chain helps detect this but doesn't prevent it).
- Coerce a user into authenticating, then use their session.
- Phish a user into installing a malicious mssh client that exfiltrates session contents.
- Conduct a long, slow attack with one stolen short-lived cert at a time, each used carefully within source-bind, building toward an objective.

These are not new. They are the residual risk in any access management system. mssh's goal is to make them harder than they were under classic SSH, not to make them impossible.

## What mssh does that classic SSH does not

A summary of where the threat model materially improves:

- TOFU host-key acceptance is gone. Host identity is cert-validated against a chain.
- Password authentication is gone. The largest residual attack surface in classic SSH is removed.
- Long-lived user keys are gone. Worst-case exposure of any user credential is the cert's validity window, typically hours.
- Hop chain integrity is enforced. A user's identity cannot be silently rewritten at hops.
- Source-address binding is first-class. Stolen credentials are constrained to the network they were issued for.
- 2FA freshness is observable in the cert and enforceable by sshd policy. The "I 2FA'd six months ago" problem disappears.
- Revocation has a defined story (CRL or OCSP for full deployments; short validity for constrained).
- DNS is part of the threat model. DNSSEC is required, SSHFP is a cross-check.

These are gains. The cost is operational complexity — the CA must be run, certs must be issued and rotated, and policy must be encoded. mssh's design tries to minimize this cost (embedded CA, simple REST API, in-session rotation) but does not eliminate it. There is no free lunch.
