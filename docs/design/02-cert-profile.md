# 02. Certificate Profile

This document defines the X.509 profile that every mssh certificate conforms to. It is the most important document in this set: every implementation is bound by it, the CA conformance program (`03-conformance.md`) tests against it, and the security properties of mssh follow from it.

## Profile levels

Two levels are defined:

- **Constrained profile.** The minimum set of X.509 features any implementation must understand. Targets Dropbear-class implementations, embedded systems, and constrained CAs. A constrained validator can fully evaluate a constrained-profile cert.
- **Full profile.** A superset that adds features useful for larger deployments (CRL distribution points, OCSP, AIA chasing, name constraints, policy mappings). Full validators must also accept constrained-profile certs.

Every cert declares its profile level explicitly via the `mssh-profile` extension. A validator MUST refuse a cert whose declared profile exceeds its capability.

## OID arc

A private arc is used for mssh extensions. The actual arc number is TBD pending assignment; this document uses the placeholder `1.3.6.1.4.1.RESERVED.1` and sub-OIDs underneath. All mssh-defined extensions live under this arc.

Within the mssh arc:

```
1.3.6.1.4.1.RESERVED.1                       mssh root
1.3.6.1.4.1.RESERVED.1.1                     Extensions
1.3.6.1.4.1.RESERVED.1.1.1   mssh-profile        Profile level declaration
1.3.6.1.4.1.RESERVED.1.1.2   mssh-source-bind    Source address binding
1.3.6.1.4.1.RESERVED.1.1.3   mssh-time-window    Fine-grained time window
1.3.6.1.4.1.RESERVED.1.1.4   mssh-hop-deleg      Hop delegation rules
1.3.6.1.4.1.RESERVED.1.1.5   mssh-cluster-scope  Cluster / host group scope
1.3.6.1.4.1.RESERVED.1.1.6   mssh-channel-policy Authenticated channel grants (VPN, proxy, etc.)
1.3.6.1.4.1.RESERVED.1.1.7   mssh-identity-type  user | machine | domain | ca
1.3.6.1.4.1.RESERVED.1.1.8   mssh-2fa-evidence   2FA verification evidence
1.3.6.1.4.1.RESERVED.1.1.9   mssh-ca-conformance CA conformance attestation
1.3.6.1.4.1.RESERVED.1.2                     Policy OIDs
1.3.6.1.4.1.RESERVED.1.2.1   mssh-policy-v1      v1 of the mssh issuance policy
```

A registry document tracks any future additions. Third parties may define their own extensions under their own OID arcs; mssh implementations MUST ignore unrecognized non-critical extensions and MUST reject certs containing unrecognized critical extensions (this is standard X.509 behavior).

## Required fields (constrained profile)

Every cert MUST contain:

### Standard X.509 fields

- **Version**: v3 (integer value 2). v1 and v2 certs are rejected.
- **Serial number**: positive, non-zero, at most 20 octets, unique within the issuing CA.
- **Signature algorithm**: one of the algorithms in the "Permitted algorithms" section below.
- **Issuer**: the DN of the issuing CA. MUST match the subject DN of an in-chain CA cert.
- **Validity**: `notBefore` and `notAfter`. `notAfter - notBefore` MUST NOT exceed the limits in "Validity windows" below.
- **Subject**: the identity. Format defined in "Subject naming" below.
- **Subject Public Key Info**: one of the key types in "Permitted algorithms".

### Standard extensions

- **Basic Constraints** (critical): `cA=FALSE` for leaf certs, `cA=TRUE` with a `pathLenConstraint` for CA certs.
- **Key Usage** (critical): for leaf certs, exactly `digitalSignature`. For CA certs, `keyCertSign` and `cRLSign` only.
- **Extended Key Usage** (critical): for leaf certs, exactly the mssh EKU OID `1.3.6.1.4.1.RESERVED.1.3.1` (`mssh-client` or `mssh-server` or both). No other EKUs permitted. This prevents an mssh cert from being used as a TLS or S/MIME cert and vice versa.
- **Subject Key Identifier**: SHA-256 of the subject public key.
- **Authority Key Identifier**: matches the issuer's SKI.

### mssh extensions

- **mssh-profile** (critical): integer indicating `1` (constrained) or `2` (full).
- **mssh-identity-type** (critical): one of `user`, `machine`, `domain`, or `ca`.
- **mssh-source-bind** (critical for leaf certs of type `user`): a SEQUENCE of one or more `IPAddressOrPrefix` entries. The connecting IP must match at least one entry. May contain the wildcard `0.0.0.0/0` only if the issuing CA's policy explicitly permits it.
- **mssh-time-window** (non-critical): a more fine-grained window than the cert's outer Validity. May specify recurring windows ("weekdays 09:00–17:00 UTC"), absolute extension policy, and maximum total session duration. If absent, the outer Validity governs.

## Optional fields (full profile only)

Certs declaring `mssh-profile = 2` MAY additionally contain:

- **CRL Distribution Points**: URLs for CRL retrieval. Full validators check these; constrained validators ignore.
- **Authority Information Access**: OCSP responder URL and CA issuers URL.
- **Name Constraints** (in CA certs): permitted and excluded name subtrees. Used to limit what an intermediate CA may issue.
- **Policy Constraints, Policy Mappings, Certificate Policies**: standard X.509 policy machinery.
- **mssh-hop-deleg**: defined in `04-handshake-and-hop-chain.md`.
- **mssh-cluster-scope**: list of host group identifiers the cert is valid for. Hosts that are not in any listed group reject the cert.
- **mssh-channel-policy**: defined in `09-channel-plugin-interface.md`. A list of typed channel grants, each with a channel-type identifier, channel-type-specific scope, optional duration, and constraints.
- **mssh-2fa-evidence**: a signed statement from the CA describing what 2FA was performed at issuance, when, and by what method. Allows downstream policy to require, for example, "must have been issued after a TOTP step within the last hour."

A constrained validator encountering a full-profile cert MUST reject it.

## Forbidden constructs

The following X.509 features are not permitted in any mssh cert. CAs MUST NOT issue certs containing them; validators MUST reject certs containing them.

- **Wildcards in subject DN or SAN.** No `CN=*.example.com`. Names are exact.
- **DNS names in SAN for user certs.** User identity is encoded in `mssh-identity-type` and the subject DN. DNS-name SAN is reserved for `machine` and `domain` certs.
- **IP addresses in SAN.** Source-address binding lives in `mssh-source-bind`, not SAN.
- **otherName, ediPartyName, x400Address, registeredID, directoryName in SAN.** Only `rfc822Name` (for user contact, informational) and `dNSName` (for machine/domain) are permitted.
- **Negative serial numbers.** Standard X.509 forbids them but some libraries accept them; mssh explicitly does not.
- **Serial numbers longer than 20 octets.** Standard X.509 limit.
- **Indirect CRL.** CRLs MUST be issued by the same CA that issued the cert.
- **Delta CRL only.** A full CRL MUST be available.
- **Certificate Transparency embedded SCTs.** Out of scope; mssh does not use CT.
- **Algorithm parameters that are not the empty parameters or absent**, except where required by the algorithm spec (e.g., RSA-PSS).
- **MD2, MD5, SHA-1 in signature algorithms.** Not even as transitional. See "Permitted algorithms".
- **RSA keys shorter than 2048 bits.** EC keys shorter than 256 bits. Ed25519 is permitted at its native size.
- **DSA.** Removed entirely.
- **Encrypted private keys delivered to clients.** The CA delivers only certs; private keys are generated client-side and never leave the smartcard or keystore.
- **Any extension not in the mssh registry, marked critical.** Unrecognized non-critical extensions are tolerated and ignored.

## Permitted algorithms

Signature algorithms on certs:

- `ecdsa-with-SHA256` over P-256.
- `ecdsa-with-SHA384` over P-384.
- `ed25519`.
- `rsassa-pss` with SHA-256 and salt length 32.

Subject public key algorithms (same set):

- ECDSA P-256, P-384.
- Ed25519.
- RSA 2048, 3072, 4096.

PQ algorithms are not mandated in v1 but the cert format allows future algorithms to be added without changing the profile structure. A future mssh-profile version (`mssh-profile = 3`) is anticipated to add ML-DSA / Dilithium when the X.509 OID assignments stabilize.

### Compatibility with existing SSH public keys

The permitted algorithms above are the same algorithms used by classic SSH for public-key authentication. This is deliberate: a user's existing SSH public key — whatever its algorithm — can be wrapped in an mssh cert without modification.

Specifically:

- An Ed25519 SSH key (`ssh-ed25519`) corresponds directly to an Ed25519 subject public key in the cert. The same key bytes, the same algorithm, the same signing operations. The mssh cert merely adds CA attestation and policy.
- An ECDSA P-256 SSH key (`ecdsa-sha2-nistp256`) corresponds directly to an ECDSA P-256 cert.
- An RSA SSH key (`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`) corresponds to an RSA cert, with the cert's signature scheme matching the algorithm-name family chosen at issuance (`rsa-sha2-256` or `rsa-sha2-512`).

A user enrolling an existing SSH key submits a PKCS#10 CSR carrying the public key portion of that key. The CA verifies proof-of-possession (the CSR is self-signed by the user's private key) and issues a cert binding the user's existing public key to their identity. The user's private key never leaves their machine.

This compatibility is what makes mssh deployable. See `15-ssh-key-compatibility.md` for the full migration model.

## Validity windows

The cert's outer Validity (`notBefore` to `notAfter`) MUST fall within these maximums:

| Identity type | Max validity |
|---------------|-------------:|
| user          | 24 hours     |
| machine       | 30 days      |
| domain        | 90 days      |
| ca (intermediate) | 1 year   |
| ca (root)     | 10 years     |

These are upper bounds. A deployment may use shorter windows; the CA conformance program does not enforce a minimum. The intent is short-lived user certs (single workday) and slightly-less-short machine certs (renewable on each boot). Domain and CA certs are longer because they are issued less frequently and their compromise is more visible.

If `mssh-time-window` is present, the effective validity is the intersection of the outer Validity and the time-window's constraints.

## Subject naming

The subject DN format is fixed per identity type. CAs MUST NOT issue certs with subject DNs in any other format.

**User**:
```
CN=<username>, OU=users, O=<organization>, C=<country>
```
`<username>` is the system login name. No spaces, no special characters beyond `.` `-` `_`.

**Machine**:
```
CN=<fqdn>, OU=machines, O=<organization>, C=<country>
```
`<fqdn>` is the fully qualified domain name. Must also appear in SAN as `dNSName`.

**Domain**:
```
CN=<domain>, OU=domains, O=<organization>, C=<country>
```
Used for fleet certs that authenticate any host within a DNS domain. Hosts in the domain identify themselves with machine certs; domain certs are used for cross-realm trust.

**CA (intermediate or root)**:
```
CN=<ca-name>, OU=ca, O=<organization>, C=<country>
```

`O` and `C` are required and serve as a tenancy boundary — a deployment defines its `O` and `C` values, and certs from other `O`/`C` combinations are rejected by default unless explicit cross-trust is configured.

## Critical-bit policy

The criticality of each extension is fixed by this profile. CAs MUST set the critical bit exactly as specified:

| Extension                | Critical |
|--------------------------|:--------:|
| BasicConstraints         | yes      |
| KeyUsage                 | yes      |
| ExtendedKeyUsage         | yes      |
| mssh-profile            | yes      |
| mssh-identity-type      | yes      |
| mssh-source-bind (user) | yes      |
| mssh-time-window        | no       |
| mssh-hop-deleg          | no       |
| mssh-cluster-scope      | no       |
| mssh-channel-policy     | no       |
| mssh-2fa-evidence       | no       |
| mssh-ca-conformance     | yes      |
| Subject/Authority KI     | no       |
| CRL Distribution Points  | no       |
| Authority Info Access    | no       |
| Name Constraints (CA)    | yes      |

Setting criticality differently from this table is itself a profile violation. A validator that sees an mssh extension marked critical when this table says non-critical MUST reject the cert.

## Why all this rigidity

The profile is rigid because rigidity is what makes X.509 safe in this context. The historical CVE pattern in X.509 is: a parser accepts a weird construct, a validator does not anticipate it, an attacker exploits the gap between them. By forbidding the weird constructs at issuance time and validating profile conformance at use time, the attack surface shrinks dramatically.

This is the same approach the WebPKI's CA/Browser Forum baseline takes. It works. We are copying it deliberately.
