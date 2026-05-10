# mssh Protocol Specification

**Status:** Draft  
**Date:** 2026-05-10  
**Editors:** TBD

## Abstract

This document specifies the wire protocol for mssh, a certificate-first variant of the Secure Shell (SSH) protocol. mssh retains the SSH transport layer of [RFC4253], the connection protocol of [RFC4254], and the user authentication framing of [RFC4252], extending the `publickey` userauth method with new algorithm names that carry mssh certificates in place of bare public keys. This document defines the algorithm names, certificate profile, validation algorithms, hop chain attestation, and supporting protocols (CA REST API, authenticated channel plugin protocol) required for interoperable implementation.

## 1. Introduction

### 1.1 Conventions

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in [RFC2119] and [RFC8174].

### 1.2 Terminology

See `00-overview.md` in the mssh design document set for the complete glossary. Key terms summarized:

- **mssh cert**: an X.509 certificate conforming to the mssh cert profile (Section 3).
- **Constrained profile**: the minimum mssh cert profile features all implementations must support.
- **Full profile**: a superset adding revocation and additional extensions.
- **Hop chain**: the sequence of intermediate mssh hops a connection traverses, attested by signed messages.
- **ACPP**: Authenticated Channel Plugin Protocol — the JSON-RPC interface between sshd and channel plugins.

### 1.3 Relationship to existing SSH protocols

mssh uses SSH-TRANS [RFC4253], the connection protocol [RFC4254], and the user authentication framing of [RFC4252] without structural changes. The mssh-specific protocol elements are:

1. Extended `publickey` algorithm names (`mssh-cert-*-v01`) that carry mssh certs, defined in Section 4.
2. A new hop chain attestation message defined in Section 5.
3. New rotation and time-extension messages defined in Section 6.
4. New channel-open type and supporting messages for authenticated channels (Section 7).

Implementations MAY accept classic bare-key `publickey` auth alongside the mssh-cert algorithms per operator configuration, providing a compatibility path for unenrolled users. Other auth methods (`password`, `keyboard-interactive`, `hostbased`, `gssapi-*`) MUST be refused unconditionally.

All other SSH messages, semantics, and behaviors are inherited from the cited RFCs.

## 2. Message Number Assignments

The following SSH message numbers are assigned by this specification. All assignments are within the user authentication range (50-79) per [RFC4250].

| Number | Mnemonic                            | Direction      |
|-------:|-------------------------------------|----------------|
| 60     | `SSH_MSG_USERAUTH_SERVER_IDENTITY`  | server→client  |
| 61     | `SSH_MSG_USERAUTH_HOPCHAIN`         | client→server  |
| 62     | `SSH_MSG_USERAUTH_ROTATE`           | client→server  |
| 63     | `SSH_MSG_USERAUTH_ROTATE_ACCEPT`    | server→client  |
| 64     | `SSH_MSG_USERAUTH_ROTATE_REJECT`    | server→client  |
| 65     | `SSH_MSG_USERAUTH_SERVER_ROTATE`    | server→client  |
| 66     | `SSH_MSG_USERAUTH_EXTEND_REQUEST`   | client→server  |
| 67     | `SSH_MSG_USERAUTH_EXTEND_GRANT`     | server→client  |
| 68     | `SSH_MSG_USERAUTH_EXTEND_DENY`      | server→client  |
| 69     | `SSH_MSG_USERAUTH_EXPIRED`          | server→client  |

Channel-open type `mssh-channel` (Section 7) does not consume a new message number; it uses the existing `SSH_MSG_CHANNEL_OPEN` (90) with a new type string.

## 3. Certificate Profile

### 3.1 OID Arc

mssh extensions live under the private arc reserved for this protocol:

```
mssh OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) RESERVED 1 }
```

Sub-arcs:

```
mssh-ext     OBJECT IDENTIFIER ::= { mssh 1 }   -- Extensions
mssh-policy  OBJECT IDENTIFIER ::= { mssh 2 }   -- Policy OIDs
mssh-eku     OBJECT IDENTIFIER ::= { mssh 3 }   -- Extended Key Usage
mssh-method  OBJECT IDENTIFIER ::= { mssh 4 }   -- 2FA method types
```

Extension OIDs:

```
id-mssh-profile           OBJECT IDENTIFIER ::= { mssh-ext 1 }
id-mssh-source-bind       OBJECT IDENTIFIER ::= { mssh-ext 2 }
id-mssh-time-window       OBJECT IDENTIFIER ::= { mssh-ext 3 }
id-mssh-hop-deleg         OBJECT IDENTIFIER ::= { mssh-ext 4 }
id-mssh-cluster-scope     OBJECT IDENTIFIER ::= { mssh-ext 5 }
id-mssh-channel-policy    OBJECT IDENTIFIER ::= { mssh-ext 6 }
id-mssh-identity-type     OBJECT IDENTIFIER ::= { mssh-ext 7 }
id-mssh-2fa-evidence      OBJECT IDENTIFIER ::= { mssh-ext 8 }
id-mssh-ca-conformance    OBJECT IDENTIFIER ::= { mssh-ext 9 }
```

EKU OIDs:

```
id-mssh-client            OBJECT IDENTIFIER ::= { mssh-eku 1 }
id-mssh-server            OBJECT IDENTIFIER ::= { mssh-eku 2 }
id-mssh-hop-eligible      OBJECT IDENTIFIER ::= { mssh-eku 3 }
```

The placeholder `RESERVED` in the arc denotes an enterprise OID assignment to be obtained from IANA when mssh progresses past draft.

### 3.2 Required ASN.1 Definitions

```asn1
MsshProfile ::= INTEGER {
    constrained (1),
    full        (2)
}

MsshIdentityType ::= ENUMERATED {
    user      (0),
    machine   (1),
    domain    (2),
    ca        (3)
}

SourceBind ::= SEQUENCE SIZE (1..MAX) OF IPAddressOrPrefix

IPAddressOrPrefix ::= CHOICE {
    ipv4     [0] OCTET STRING (SIZE (4)),
    ipv6     [1] OCTET STRING (SIZE (16)),
    ipv4Cidr [2] SEQUENCE { addr OCTET STRING (SIZE (4)), prefixLen INTEGER (0..32) },
    ipv6Cidr [3] SEQUENCE { addr OCTET STRING (SIZE (16)), prefixLen INTEGER (0..128) }
}

TimeWindow ::= SEQUENCE {
    absoluteStart   GeneralizedTime OPTIONAL,
    absoluteEnd     GeneralizedTime OPTIONAL,
    recurring       RecurringWindow OPTIONAL,
    maxTotalSeconds INTEGER OPTIONAL,
    extensionPolicy ExtensionPolicy OPTIONAL
}

RecurringWindow ::= SEQUENCE {
    daysOfWeek     BIT STRING { sun(0), mon(1), tue(2), wed(3),
                                thu(4), fri(5), sat(6) },
    startOfDayUtc  INTEGER (0..86399),   -- seconds from 00:00 UTC
    endOfDayUtc    INTEGER (0..86399)
}

ExtensionPolicy ::= SEQUENCE {
    maxExtensions       INTEGER DEFAULT 0,
    perExtensionSeconds INTEGER OPTIONAL,
    hardMaxSeconds      INTEGER OPTIONAL
}

HopDelegationUser ::= SEQUENCE {
    allowedIntermediates SEQUENCE OF HopMatcher,
    maxHops              INTEGER (1..16),
    rewriteUser          BOOLEAN DEFAULT FALSE,
    maxAgeSeconds        INTEGER OPTIONAL
}

HopDelegationHop ::= SEQUENCE {
    allowedInbound  SEQUENCE OF HopMatcher,
    allowedOutbound SEQUENCE OF HopMatcher,
    maxHops         INTEGER (1..16),
    rewriteUser     BOOLEAN DEFAULT FALSE
}

HopMatcher ::= CHOICE {
    exactSubject     [0] Name,
    subjectPattern   [1] UTF8String,
    clusterId        [2] UTF8String,
    anyAuthorized    [3] NULL
}

ClusterScope ::= SEQUENCE OF UTF8String

ChannelPolicy ::= SEQUENCE OF ChannelGrant

ChannelGrant ::= SEQUENCE {
    channelType    UTF8String,
    scope          ChannelScope,
    duration       INTEGER OPTIONAL,
    maxInstances   INTEGER DEFAULT 1,
    constraints    SEQUENCE OF Constraint OPTIONAL
}

ChannelScope ::= CHOICE {
    opaqueScope     [0] OCTET STRING,
    structuredScope [1] SEQUENCE OF KeyValue
}

KeyValue ::= SEQUENCE { key UTF8String, value ANY }

Constraint ::= SEQUENCE { constraintType UTF8String, constraintValue ANY }

TwoFactorEvidence ::= SEQUENCE {
    issuedAt           GeneralizedTime,
    methods            SEQUENCE OF Method,
    parentEvidenceHash OCTET STRING OPTIONAL,
    freshnessDepth     INTEGER DEFAULT 0
}

Method ::= SEQUENCE {
    methodOID OBJECT IDENTIFIER,
    timestamp GeneralizedTime,
    keyId     OCTET STRING OPTIONAL
}

CAConformance ::= SEQUENCE {
    suiteVersion     UTF8String,
    attestedAt       GeneralizedTime,
    reportHash       OCTET STRING,
    attestorSigKey   SubjectPublicKeyInfo,
    signature        BIT STRING,
    reportUrl        IA5String OPTIONAL
}
```

### 3.3 Profile rules

The full profile rules — required fields, optional fields, forbidden constructs, validity bounds, criticality assignments — are in `02-cert-profile.md` and are normative. This spec section incorporates that document by reference. Implementers MUST treat the design document as the authoritative source pending its absorption into a future RFC text.

### 3.4 Permitted algorithms

Signature algorithms (cert signature and handshake signature):

- `ecdsa-with-SHA256` over P-256.
- `ecdsa-with-SHA384` over P-384.
- `id-Ed25519` (Ed25519, RFC 8410).
- `id-RSASSA-PSS` with SHA-256 and salt length 32.

Public key algorithms:

- ECDSA over P-256 or P-384.
- Ed25519.
- RSA with modulus 2048, 3072, or 4096 bits.

All others are forbidden.

## 4. User Authentication

### 4.1 Method and algorithm names

mssh user authentication uses the SSH `publickey` method as defined in [RFC4252] Section 7, with extended algorithm names that carry mssh certs in place of bare public keys. Implementations MUST support the following algorithm names:

| Algorithm name                | Underlying key      | Signature scheme       |
|-------------------------------|---------------------|------------------------|
| `mssh-cert-ed25519-v01`       | Ed25519             | Ed25519                |
| `mssh-cert-ecdsa-p256-v01`    | ECDSA P-256         | ecdsa-sha2-nistp256    |
| `mssh-cert-ecdsa-p384-v01`    | ECDSA P-384         | ecdsa-sha2-nistp384    |
| `mssh-cert-rsa-sha256-v01`    | RSA (≥2048)         | rsa-sha2-256           |
| `mssh-cert-rsa-sha512-v01`    | RSA (≥3072)         | rsa-sha2-512           |

The `-v01` suffix permits future algorithm version increments without retiring the older format.

Implementations MAY accept bare-key `publickey` auth using the standard algorithm names (`ssh-ed25519`, `ecdsa-sha2-nistp256`, etc.) per local configuration. Bare-key auth does not engage mssh policy enforcement; it is a compatibility mode for unenrolled users. See `15-ssh-key-compatibility.md` for the deployment model.

Other auth methods — `password`, `keyboard-interactive`, `hostbased`, `gssapi-*` — MUST be refused unconditionally.

### 4.2 Cert blob format

A `publickey` userauth request using one of the `mssh-cert-*-v01` algorithm names carries a cert blob in the "public key blob" field, encoded as:

```
string    "mssh-cert-v01"             ; format identifier
string    cert serial number          ; hex string
string    leaf cert DER               ; X.509 leaf
uint32    chain length N              ; 0 ≤ N ≤ 8
   N times:
   string  intermediate cert DER      ; ordered leaf-issuer first
uint32    flags                       ; bit 0: rotation-requested
                                      ; bit 1: hop-chain-follows
                                      ; bit 2: channel-request-follows
                                      ; bits 3-31 reserved, MUST be zero
```

The `flags` field uses the bit assignments described in `04-handshake-and-hop-chain.md`.

The userauth request signature is computed as in [RFC4252] Section 7, over the same bytes a classic SSH `publickey` signature would cover, using the private key corresponding to the cert's subject public key. The signature algorithm matches the algorithm name's signature scheme column above.

### 4.3 Server validation

The server MUST perform the validation steps enumerated in `04-handshake-and-hop-chain.md` Section "Server validation" under "The mssh-cert-* algorithm family", in the order specified. The first failing check determines the failure; subsequent checks are not performed.

On any validation failure, the server MUST send `SSH_MSG_USERAUTH_FAILURE` listing only the methods the server supports for this user (typically `publickey` only) and the partial-success flag false. The specific reason is logged server-side using a stable error code (see error registry in Section 9) but MUST NOT be transmitted to the client.

Servers MAY linger after auth failure for 500 ms to 5 s before disconnecting, to discourage scanning. Servers MUST NOT close the connection immediately after USERAUTH_FAILURE if other auth attempts are configured to be permissible — the client may legitimately retry. However, a client whose `mssh-cert-*` auth was rejected MUST NOT automatically downgrade to bare `publickey` auth; doing so silently downgrades security. Such retries require explicit client configuration.

### 4.4 Server identity

Following successful client cert validation, before sending `SSH_MSG_USERAUTH_SUCCESS`, the server MUST send `SSH_MSG_USERAUTH_SERVER_IDENTITY`:

```
byte      SSH_MSG_USERAUTH_SERVER_IDENTITY (60)
string    server cert            ; DER X.509
string    cert chain             ; intermediates
string    signature
```

`signature` is computed over:
```
string    session identifier
byte      SSH_MSG_USERAUTH_SERVER_IDENTITY
string    server cert
string    cert chain
```

The signature uses the algorithm of the server cert's subject public key.

The client MUST validate the server cert with the same checks the server applies to the client cert, plus:

- The server cert's `mssh-identity-type` MUST be `machine` or `domain`.
- The hostname the client used to connect MUST appear in the server cert's `CN` (for `machine`) or fall within the domain scope (for `domain`), and MUST match a `dNSName` SAN if any are present.
- If SSHFP records were retrieved (Section 8), the cert's subject public key SHA-256 fingerprint MUST match at least one SSHFP record.

On client-side validation failure, the client MUST close the connection. The client SHOULD log a specific error locally; it MUST NOT inform the server of the specific failure reason.

### 4.5 Successful authentication

On mutual success the server MUST send `SSH_MSG_USERAUTH_SUCCESS` (number 52, per [RFC4252]). The connection then proceeds to the connection protocol [RFC4254].

## 5. Hop Chain

### 5.1 Wire format

When the client (or a forwarding hop) sets `hop-chain-follows` in the auth request, it MUST send `SSH_MSG_USERAUTH_HOPCHAIN` immediately after the auth request and before the server's response:

```
byte      SSH_MSG_USERAUTH_HOPCHAIN (61)
uint32    hop count N            ; 1 ≤ N ≤ 16
   N times:
   string  hop cert              ; DER X.509
   string  hop cert chain        ; DER intermediates
   string  inbound-from hostname
   string  next-hop hostname
   uint64  hop timestamp
   string  hop signature
```

Each hop signature is computed over:

```
string    session identifier     ; of the user's original transport leg
string    hop cert SKI           ; from the hop's own cert
string    inbound-from hostname
string    next-hop hostname
uint64    hop timestamp
```

The signature uses the algorithm of the hop's cert public key.

### 5.2 Validation

The destination MUST perform the validation steps enumerated in `04-handshake-and-hop-chain.md` Section "Destination validation", in order. Failure handling is as in Section 4.2.

### 5.3 Hop forwarding model

A node acting as an mssh hop MUST:

1. Authenticate the inbound mssh connection per Section 4.
2. Verify its own cert's `mssh-hop-deleg` (hop variant) permits the forward.
3. Open a new TCP connection to the next hop.
4. Initiate KEX with the next hop and obtain a session identifier for the *new* leg.
5. Construct an extended hop chain by:
   - Taking the inbound hop chain (if any) plus the inbound auth request.
   - Appending its own hop attestation entry, signed over the *user's original* session identifier (which the hop received from the previous hop or, if it is the first hop, from its own KEX).
6. Send to the next hop: a copy of the user's auth request (byte-identical to what was received), followed by the extended hop chain.

The user's auth request bytes pass through hops unchanged. Hops never resign or modify the user's auth request. This is what preserves end-to-end identity.

## 6. Rotation and Extension

The rotation and extension messages (60-69 per Section 2) are formatted as specified in `05-rotation-2fa-lifetime.md` Section "Rotation: the protocol" and "Time extension: the protocol". This spec section incorporates those formats by reference.

A server receiving `SSH_MSG_USERAUTH_ROTATE` MUST validate the new cert using the same checks as initial authentication, plus the cross-cert checks (matching identity, parent-evidence linkage, freshness depth) defined in the design document.

A server receiving `SSH_MSG_USERAUTH_EXTEND_REQUEST` MUST consult its policy and the issuing CA per its configuration before responding. The server SHOULD respond within 30 seconds; if no response is possible within that time, the server SHOULD send `SSH_MSG_USERAUTH_EXTEND_DENY` with reason `extension-pending-timeout`.

Cert expiry handling: when a cert's `notAfter` (or `mssh-time-window` end) is reached without a successful extension or rotation, the server MUST send `SSH_MSG_USERAUTH_EXPIRED` with a grace deadline at most 60 seconds in the future. At the grace deadline, the server MUST close all channels and disconnect.

## 7. Authenticated Channels

### 7.1 Channel open

Authenticated channels use the standard `SSH_MSG_CHANNEL_OPEN` (90) with type `mssh-channel`:

```
byte      SSH_MSG_CHANNEL_OPEN
string    "mssh-channel"
uint32    sender channel
uint32    initial window size
uint32    maximum packet size
string    channelType            ; e.g. "echo", "tcp-proxy"
string    channelParameters      ; plugin-defined, typically JSON
```

The server MUST:

1. Look up `channelType` in its plugin configuration. If no plugin is configured, refuse the open with `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` and a description.
2. Check the client cert's `mssh-channel-policy`. If no matching `ChannelGrant`, refuse the open.
3. Negotiate with the plugin via ACPP (Section 7.2). If the plugin rejects, refuse the open with the plugin's reason.
4. Open the channel on success.

### 7.2 ACPP (Authenticated Channel Plugin Protocol)

Transport: Unix domain socket, owner sshd user, mode 0600.

Framing: newline-delimited JSON. Each line is a complete JSON object per JSON-RPC 2.0.

Methods sshd invokes on plugin:

- `helo` — version handshake at sshd startup.
- `negotiate` — request to accept or reject a channel.
- `establish` — channel approved by SSH, hand off data socket.
- `teardown` — channel closing.

Methods plugin invokes on sshd:

- `requestAuxChannel` — open a parallel channel back to the client.
- `log` — emit an audit log entry.
- `policyQuery` — evaluate a policy question against the cert.

Full parameter and result schemas are in `09-channel-plugin-interface.md` Section "The JSON-RPC protocol". This spec section incorporates them by reference.

### 7.3 Channel data flow

After successful negotiate and establish, sshd MUST relay SSH channel data bytes verbatim to/from the plugin's data socket. sshd MUST honor SSH flow control (window adjust messages) per [RFC4254] but MUST NOT inspect, modify, or filter the data stream.

## 8. DNSSEC and SSHFP

### 8.1 Name resolution

Implementations MUST resolve hostnames using a DNSSEC-validating resolver and MUST check the AD bit on responses. Responses without AD MUST be treated as untrusted.

An implementation MAY honor a per-name configuration directive (`DnssecException`) to accept non-AD responses for specifically listed names. Such exceptions SHOULD be logged at every use.

`/etc/hosts` and platform equivalents are trusted as locally configured; DNSSEC requirements do not apply.

### 8.2 SSHFP cross-check

After name resolution and before completing the cert chain validation, an implementation SHOULD query SSHFP records for the target name. SSHFP records MUST be DNSSEC-validated.

If at least one SSHFP record is retrieved:

- The implementation MUST compute the SHA-256 fingerprint of the server cert's subject public key.
- The fingerprint MUST match at least one SSHFP record with algorithm matching the cert's key algorithm and hash type 2 (SHA-256).
- SSHFP records with hash type 1 (SHA-1) MUST be ignored.

If no SSHFP records exist, the cert is the sole authority and the connection MAY proceed.

If SSHFP records exist but none match, the connection MUST be refused.

## 9. Error Registry

Error codes used in protocol messages and CA REST API responses. Codes are stable across protocol versions.

| Code | Name                          | Used in                       |
|-----:|-------------------------------|-------------------------------|
| 1001 | `CERT_INVALID_SIGNATURE`      | userauth, hopchain            |
| 1002 | `CERT_EXPIRED`                | userauth, hopchain            |
| 1003 | `CERT_NOT_YET_VALID`          | userauth                      |
| 1004 | `CERT_REVOKED`                | userauth, hopchain            |
| 1005 | `CERT_PROFILE_VIOLATION`      | userauth, hopchain            |
| 1006 | `CHAIN_INCOMPLETE`            | userauth                      |
| 1007 | `CHAIN_UNTRUSTED_ROOT`        | userauth                      |
| 1008 | `CA_CONFORMANCE_MISSING`      | userauth                      |
| 1009 | `CA_CONFORMANCE_UNTRUSTED`    | userauth                      |
| 1010 | `SOURCE_BIND_MISMATCH`        | userauth                      |
| 1011 | `TIME_WINDOW_VIOLATION`       | userauth                      |
| 1012 | `CLUSTER_SCOPE_MISMATCH`      | userauth                      |
| 1013 | `HOST_IDENTITY_MISMATCH`      | userauth (client side)        |
| 1014 | `SSHFP_MISMATCH`              | userauth (client side)        |
| 1015 | `DNSSEC_VALIDATION_FAILED`    | resolution                    |
| 2001 | `HOPCHAIN_INVALID_SIGNATURE`  | hopchain                      |
| 2002 | `HOPCHAIN_TIMESTAMP_INVALID`  | hopchain                      |
| 2003 | `HOPCHAIN_PATH_DISCONTINUITY` | hopchain                      |
| 2004 | `HOPCHAIN_DELEG_DENIED`       | hopchain                      |
| 2005 | `HOPCHAIN_TOO_DEEP`           | hopchain                      |
| 3001 | `ROTATE_IDENTITY_MISMATCH`    | rotation                      |
| 3002 | `ROTATE_FRESHNESS_INSUFFICIENT` | rotation                    |
| 3003 | `EXTEND_DENIED_POLICY`        | extension                     |
| 3004 | `EXTEND_DENIED_HARD_MAX`      | extension                     |
| 3005 | `EXTEND_PENDING_TIMEOUT`      | extension                     |
| 4001 | `ALGO_FORBIDDEN`              | CA REST                       |
| 4002 | `EXTENSION_FORBIDDEN`         | CA REST                       |
| 4003 | `VALIDITY_TOO_LONG`           | CA REST                       |
| 4004 | `REQUIRED_EXTENSION_MISSING`  | CA REST                       |
| 4005 | `CRITICALITY_VIOLATION`       | CA REST                       |
| 4006 | `SUBJECT_MALFORMED`           | CA REST                       |
| 4007 | `TENANCY_VIOLATION`           | CA REST                       |
| 4008 | `2FA_INSUFFICIENT`            | CA REST                       |
| 4009 | `SOURCE_NOT_AUTHORIZED`       | CA REST                       |
| 5001 | `CHANNEL_TYPE_NOT_CONFIGURED` | channel open                  |
| 5002 | `CHANNEL_NOT_GRANTED`         | channel open                  |
| 5003 | `CHANNEL_PLUGIN_REJECTED`     | channel open                  |
| 5004 | `CHANNEL_PLUGIN_UNAVAILABLE`  | channel open                  |
| 9001 | `LEGACY_HOST_NOT_CONFIGURED`  | connection                    |
| 9002 | `LEGACY_HOST_EXPIRED`         | connection                    |
| 9003 | `LEGACY_HOST_FINGERPRINT_MISMATCH` | connection               |

Additional codes may be added in future revisions of this specification. Implementations MUST tolerate receiving unknown error codes and treat them as opaque identifiers.

## 10. Security Considerations

The full security analysis is in `12-threat-model.md`. Key normative points:

- Implementations MUST refuse password authentication regardless of configuration.
- Implementations MUST reject SSH transport configurations that disable MAC or encryption.
- Implementations MUST enforce all profile rules at validation time, not only at issuance time.
- Implementations MUST fail closed on DNSSEC validation failures unless explicit exception is configured.
- Implementations MUST treat unknown critical X.509 extensions as cause for rejection (standard X.509 behavior, restated for clarity).
- Implementations SHOULD use short cert validity windows. The maximums in this spec are upper bounds, not recommendations.
- Implementations MUST NOT extend a session beyond the cert's `mssh-time-window` hard maximum.

## 11. IANA Considerations

This specification requests:

- Assignment of an enterprise OID arc to replace the placeholder `RESERVED 1`.
- Reservation of SSH message numbers 60-69 (Section 2).
- Reservation of channel type string `mssh-channel`.

## 12. References

### 12.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC4250] Lehtinen, S. and Lonvick, C., "The Secure Shell (SSH) Protocol Assigned Numbers", RFC 4250, January 2006.
- [RFC4251] Ylonen, T. and Lonvick, C., "The Secure Shell (SSH) Protocol Architecture", RFC 4251, January 2006.
- [RFC4252] Ylonen, T. and Lonvick, C., "The Secure Shell (SSH) Authentication Protocol", RFC 4252, January 2006.
- [RFC4253] Ylonen, T. and Lonvick, C., "The Secure Shell (SSH) Transport Layer Protocol", RFC 4253, January 2006.
- [RFC4254] Ylonen, T. and Lonvick, C., "The Secure Shell (SSH) Connection Protocol", RFC 4254, January 2006.
- [RFC5280] Cooper, D. et al., "Internet X.509 PKI Certificate and Certificate Revocation List (CRL) Profile", RFC 5280, May 2008.
- [RFC6960] Santesson, S. et al., "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP", RFC 6960, June 2013.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", RFC 8174, May 2017.

### 12.2 Informative

- [RFC4255] Schlyter, J. and Griffin, W., "Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints", RFC 4255, January 2006.
- [RFC6238] M'Raihi, D. et al., "TOTP: Time-Based One-Time Password Algorithm", RFC 6238, May 2011.
- [RFC6698] Hoffman, P. and Schlyter, J., "The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA", RFC 6698, August 2012.

## Appendix A: Worked example

A complete worked example — a user connecting through one hop to a destination, with full message traces and validation steps — is provided as a companion artifact to this specification. Implementers are encouraged to use it for interoperability testing.

## Appendix B: Differences from classic SSH

For implementers porting classic SSH code:

1. **Extend the `publickey` algorithm dispatch.** Add handlers for `mssh-cert-*-v01` algorithm names. The cert blob is parsed in place of a raw public key; everything else in the `publickey` flow (signature computation, signature verification) is unchanged. Reject `password`, `keyboard-interactive`, `hostbased`, and `gssapi-*` unconditionally regardless of configuration.
2. **Add cert chain validation.** For mssh-cert algorithms, validate the cert chain against a configured trust root. For bare-key algorithms (if accepted), preserve the existing `authorized_keys` lookup path.
3. **Add the mssh message handlers** (numbers 60-69 per Section 2) for hop chain, rotation, extension.
4. **Wire up the CA REST client** for rotation and revocation.
5. **Configure plugin sockets** for any channel types you want to support.
6. **Replace the DNS path** with a DNSSEC-aware resolver call.
7. **Remove password and other auth method code paths** entirely. Configurations enabling these must produce a fatal error, not a silent ignore.
8. **Add `AuthenticationMode` configuration** to control whether bare-key auth is accepted alongside mssh-cert auth.

The connection protocol layer ([RFC4254]) needs no changes. SFTP, SCP, port forwarding, agent forwarding, X11 — all work as before once auth completes.
