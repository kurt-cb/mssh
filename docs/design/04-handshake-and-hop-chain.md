# 04. Handshake and Hop Chain

The mssh wire protocol is SSH-TRANS as defined by RFC 4253, with the user authentication phase (RFC 4252) replaced. This document defines the modified authentication message exchange and the new hop chain attestation message. These are the only on-wire protocol changes in mssh.

## Transport layer

Unchanged from classic SSH. KEX, key derivation, MACs, ciphers — all per RFC 4253 with the algorithm set restricted as in modern OpenSSH (chacha20-poly1305, aes256-gcm, curve25519-sha256, etc.). No new transport primitives are introduced.

The transport-layer host key signature continues to bind the KEX result to a specific server private key. The difference from classic SSH is that the host key is no longer trusted via TOFU and `known_hosts`; it is trusted because the server presents a cert chain that binds the host key's public component to a CA-attested identity. See "Mutual authentication" below.

## User authentication: replaced

Classic SSH negotiates among `password`, `publickey`, `keyboard-interactive`, `hostbased`, and others. mssh supports exactly one method:

- **`mssh-cert`** — Mutual cert-based authentication.

Any `SSH_MSG_USERAUTH_REQUEST` with a method name other than `mssh-cert` is rejected; the server sends `SSH_MSG_USERAUTH_FAILURE` listing only `mssh-cert` as an available method, then disconnects after a small linger if the client does not switch.

`mssh-cert` is also offered in legacy mode for mssh-aware peers, with classic methods accepted as a fallback only when the connecting host is listed in `LegacyHost` configuration. See `08-legacy-bridge.md`.

## The mssh-cert method

After KEX completes and a service request for `ssh-userauth` is acknowledged, the client sends:

```
byte      SSH_MSG_USERAUTH_REQUEST
string    user name
string    service name           ; always "ssh-connection"
string    method name            ; "mssh-cert"
string    client cert            ; DER-encoded X.509 leaf
string    cert chain             ; DER-encoded X.509 intermediates,
                                 ; leaf-issuer first, root excluded
uint32    flags                  ; bit 0: rotation-requested
                                 ; bit 1: hop-chain-follows
                                 ; bit 2: channel-request-follows
                                 ; bits 3-31 reserved, MUST be zero
string    signature              ; over session id || preceding fields
```

The signature is computed over the SSH session identifier (per RFC 4252) concatenated with all preceding fields of this message, signed with the private key corresponding to the client cert's subject public key.

If `hop-chain-follows` is set, the client (or the most recent mssh hop forwarding on its behalf) MUST send `SSH_MSG_USERAUTH_HOPCHAIN` (defined below) immediately after this message and before any server response. If `channel-request-follows` is set, the client intends to request one or more authenticated channels after auth succeeds (see `09-channel-plugin-interface.md`).

The server validates, in order:

1. **Chain to trust root.** The cert chain terminates at a configured trust root. Path-building follows RFC 5280 §6.1 with the restrictions in `02-cert-profile.md`.
2. **Profile conformance.** Every cert in the chain (including the leaf) conforms to its declared `mssh-profile`, with criticality, extensions, and constraints exactly as specified. Re-runs the issuance-time profile validation against the received bytes.
3. **CA conformance attestation.** Every CA cert in the chain carries a valid `mssh-ca-conformance` extension. sshd's configured `TrustedAttestor` set must include the signer of each attestation.
4. **Validity window.** The leaf's `notBefore` ≤ now ≤ `notAfter`. Wall clock skew tolerance is configurable but defaults to zero — clocks must be synchronized.
5. **Source-address binding.** The leaf's `mssh-source-bind` includes the connecting peer's IP. For connections arriving via a hop chain, the relevant IP is the one in the hop's `next-hop hostname` resolution, not the final TCP peer address; see "Source binding and hops" below.
6. **Time window.** If the leaf has `mssh-time-window`, the current time falls within an allowed window. If not within a window but within an extension-eligible band, the server records this for the rotation/extension logic in `05-rotation-2fa-lifetime.md`.
7. **Cluster scope.** If the leaf has `mssh-cluster-scope`, the server is a member of one of the listed clusters. Cluster membership is locally configured on the server.
8. **Revocation.** For full-profile certs, CRL or OCSP per the cert's distribution points. For constrained-profile certs, revocation is implied by the short validity window and no online check is performed.
9. **Signature.** The signature in the auth message is valid under the leaf cert's public key.

If any check fails, the server sends `SSH_MSG_USERAUTH_FAILURE` listing no methods (signaling no recovery) and disconnects after the linger. The specific failure reason is logged server-side with a stable error code from the registry in the protocol spec, but is **not** communicated to the client. This is deliberate: detailed failure feedback would be an oracle for an attacker probing what kind of cert the server expects.

## Mutual authentication

On client validation success, the server sends:

```
byte      SSH_MSG_USERAUTH_SERVER_IDENTITY
string    server cert            ; DER-encoded X.509 leaf
string    cert chain             ; intermediates
string    signature              ; over session id || preceding fields,
                                 ; signed with server cert private key
```

This message is also a binding artifact: the signature ties the server's cert key to this specific SSH session, preventing replay of a server's cert into another session.

The client validates the server cert chain with the same rules as the server-side check above, plus:

- **Hostname binding.** The leaf's `mssh-identity-type` is `machine` or `domain`. The hostname the client connected to (after DNSSEC resolution, per `10-dnssec-and-sshfp.md`) MUST match the cert's `CN` for `machine` type, or fall within the domain scope for `domain` type. SAN `dNSName` entries are checked as additional permitted names; the connection hostname must match exactly one of them.
- **Optional SSHFP cross-check.** If the connecting client retrieved a DNSSEC-validated SSHFP record for the host, the SHA-256 fingerprint of the cert's subject public key MUST match an SSHFP entry. This is a defense-in-depth check; a missing SSHFP record is not an error if the cert validates.

`SSH_MSG_USERAUTH_SERVER_IDENTITY` is assigned a message number from the user-authentication range (60-79); the exact value is defined in the protocol spec.

## Successful authentication

On mutual success, the server sends `SSH_MSG_USERAUTH_SUCCESS`. The connection proceeds to the connection protocol (RFC 4254) for channel opens, just as in classic SSH. Standard channel types (`session`, `direct-tcpip`, `forwarded-tcpip`) and the SFTP subsystem work unchanged.

The user's identity for authorization purposes is the leaf cert's subject `CN`. Mapping to a local UNIX account is the responsibility of the sshd configuration (a `CertMap` directive replaces the role of `AuthorizedKeysFile` in this regard; the default is a 1:1 match between `CN` and local username).

## Hop chain attestation

When a client reaches a destination through one or more intermediate mssh hops, the chain is attested through `SSH_MSG_USERAUTH_HOPCHAIN`, sent immediately after `SSH_MSG_USERAUTH_REQUEST` when its `hop-chain-follows` flag is set.

### The hop relay model

An mssh hop is a host running sshd that has been authenticated to by the client (or a previous hop), and that is forwarding a connection to the next hop or to the destination. Critically, an mssh hop does not behave like a classic `ProxyJump` TCP forwarder. It:

1. Authenticates the inbound connection as a normal sshd auth.
2. Reads the user's request to forward to the next hop.
3. Verifies that its own cert's `mssh-hop-deleg` extension authorizes it to act as a hop for this user's request.
4. Opens a new TCP connection to the next hop.
5. Performs mssh auth to the next hop, presenting its own cert and the **extended** hop chain.

The chain extension is the new part. The hop appends one entry describing its participation, signs it with its own cert key, and forwards the user's original `SSH_MSG_USERAUTH_REQUEST` (verbatim, signature intact) plus the new chain to the next hop.

The destination thus receives:

- The user's original cert and original auth signature, untampered.
- A chain of hop attestations, one per intermediate hop, each cryptographically signed and ordered.

The destination can independently verify both the user's identity and the path the connection took. No hop can rewrite the user identity, because the destination checks the original auth message's signature against the user's cert directly.

### Wire format

```
byte      SSH_MSG_USERAUTH_HOPCHAIN
uint32    hop count N            ; 1 ≤ N ≤ 16, see "Limits" below
   repeat N times, ordered origin → last-intermediate:
   string  hop cert              ; DER X.509 leaf for this hop
   string  hop cert chain        ; intermediates for this hop's cert chain
   string  inbound-from hostname ; the hostname the hop received from
                                 ; (the client's source, or the previous hop)
   string  next-hop hostname     ; the hostname the hop forwarded to
                                 ; (the next hop or the destination)
   uint64  hop timestamp         ; seconds since epoch, when this hop forwarded
   string  hop signature         ; over: session id of the user's leg
                                 ; || hop cert SKI
                                 ; || inbound-from || next-hop
                                 ; || timestamp
                                 ; signed by hop's cert key
```

Note that each hop signs over the **session id of the user's original transport leg** — the session id from the first leg, not the leg between this hop and the next. This is what binds the chain to the user's actual SSH session and prevents a hop from harvesting a signature in one user's session and replaying it into another.

To make this work, each hop receives the user's session id as part of the forwarded auth state from the previous hop. The first hop knows it directly (it was the user's KEX partner); subsequent hops receive it as part of the inbound chain data.

### Destination validation

The destination, on receiving `SSH_MSG_USERAUTH_HOPCHAIN`, validates:

1. **Each hop cert is valid.** Same profile, conformance, validity, source-binding, revocation checks as for the user's cert, evaluated at the time indicated by the hop's timestamp (not now). This allows the chain to remain valid for the lifetime of the session even after some hop certs have expired or rotated.
2. **Each hop signature is valid.** Over the indicated fields, under the hop cert's public key.
3. **Timestamps are monotonically non-decreasing**, and the most recent timestamp is within a configurable skew (default 5 minutes) of now.
4. **Path continuity.** The first hop's `inbound-from` is the client's hostname or IP (matched against the user cert's source-bind). For each subsequent hop, `inbound-from` matches the previous hop's `next-hop`, and the previous hop's `next-hop` matches this hop's cert subject. The final hop's `next-hop` matches the destination's own hostname.
5. **Delegation authorization at the user cert.** The user's leaf cert's `mssh-hop-deleg` extension permits this specific chain — that is, each listed intermediate hop, in order, is permitted by the user's cert.
6. **Delegation authorization at each hop.** Each intermediate hop's own cert's `mssh-hop-deleg` extension permits the hop to act as a relay in this kind of position (with this kind of inbound and outbound).
7. **Hop count ≤ maxHops** from the user cert.

If any check fails, `SSH_MSG_USERAUTH_FAILURE` and disconnect. Server-side log records the specific failure.

### The mssh-hop-deleg extension

Carried in a user cert, the extension means "this user, with this cert, may be forwarded through hops matching the following rules":

```
HopDelegation ::= SEQUENCE {
   allowedIntermediates   SEQUENCE OF HopMatcher,
   maxHops                INTEGER (1..16),
   rewriteUser            BOOLEAN DEFAULT FALSE,
   maxAge                 INTEGER OPTIONAL  -- seconds; rejects chains
                                             -- older than this
}

HopMatcher ::= CHOICE {
   exactSubject     [0] Name,
   subjectPattern   [1] UTF8String,    -- glob-form on CN within
                                       -- the cert's O
   clusterId        [2] UTF8String,    -- match any hop in cluster
   anyAuthorized    [3] NULL           -- match any hop holding a
                                       -- hop-eligible cert
}
```

Carried in a hop cert, the same extension means "this host, with this cert, may participate as a hop subject to":

```
HopDelegation ::= SEQUENCE {
   allowedInbound         SEQUENCE OF HopMatcher,  -- who may forward to me
   allowedOutbound        SEQUENCE OF HopMatcher,  -- who I may forward to
   maxHops                INTEGER (1..16),         -- max chain length I
                                                    -- may be a member of
   rewriteUser            BOOLEAN DEFAULT FALSE
}
```

`rewriteUser` defaults false. When false (the common case), the user identity carried in the chain is the original client's; the hop cannot present itself as a different user to the next hop. When true (rare; for explicit gateway scenarios), the hop may substitute its own user identity, but only if the user's cert also has `rewriteUser=true`. Both ends must opt in.

### Why this is safe

The protocol's safety property is: **the destination authorizes the original user, on a chain it can verify, with no party in the chain able to silently substitute identity or path.**

This holds because:

- The user's auth signature is over the session id and forwarded verbatim. No hop can forge it without the user's cert key.
- The chain is built from append-only signed entries. A hop can only add its own entry; it cannot remove or modify earlier entries without invalidating their signatures.
- Path continuity is verified at the destination. A hop cannot claim to have received from someone it did not.
- Both the user cert and each hop cert independently authorize the hop's participation. Mutual policy must hold.
- The `rewriteUser` flag requires bilateral opt-in, making identity rebinding an explicit ceremony rather than a silent feature.

### Source binding and hops

A user cert's `mssh-source-bind` lists IPs from which the cert may be used. In a hop scenario, the question is "which IP is checked against source-bind?"

The answer: the user's actual originating IP. The first hop in the chain knows this (it is its own inbound TCP peer). The first hop records this IP in its hop entry's `inbound-from` field. The destination, validating the chain, uses this `inbound-from` of the first hop as the IP to match against the user cert's `mssh-source-bind`.

This means a user with a tightly bound source-bind (e.g., `10.0.0.0/24`) can still legitimately reach distant destinations through a chain of hops, as long as the user's actual machine is on `10.0.0.0/24`. The user is not punished for having to hop. But a stolen cert cannot be used from a different network because the first hop's truthful recording of the originating IP would fail source-bind validation at the destination.

A malicious first hop could lie about the inbound IP. This is acknowledged in the threat model (`12-threat-model.md`): the first hop is a trust anchor of sorts. The mitigations are:

- The first hop's own cert is CA-issued and presumably under organizational control.
- The first hop's behavior is auditable: a tampered chain that fails downstream validation is logged at the failure point.
- For very high security deployments, source-bind can use `clusterId` matchers instead of IPs, evaluated by the destination using its own cluster knowledge rather than trusting hop reports.

## Limits

To bound resource use and limit attack surface:

- **Max hop count: 16.** Long enough for any realistic admin topology, short enough that DoS via deep chains is bounded. Configurable downward.
- **Max chain message size: 256 KB.** Each hop entry is roughly 4–8 KB; 16 hops fit easily.
- **Max client cert chain depth: 8.** Plus the trust root, that's enough for any reasonable hierarchy.
- **Max single cert size: 16 KB.** Reasonable for X.509 with several extensions.

These are protocol limits. Deployments may set lower limits in configuration.

## Algorithm agility

All cryptographic operations in the handshake (transport KEX, host key signature, cert chain validation, user auth signature, hop signatures) use the algorithms permitted by the cert profile (`02-cert-profile.md`). When a new algorithm is added in a future profile version, the handshake itself does not change — the cert algorithms drive what is signed and verified, and the SSH transport already negotiates its own KEX/cipher set independently.

This deliberate separation means transport-layer crypto and cert crypto evolve on different schedules. A deployment can use ECDSA P-256 certs today and migrate to ML-DSA certs later without touching the transport, or vice versa.

## What does not change

The connection protocol (RFC 4254) is fully preserved. Channel opens, `pty-req`, `exec`, `subsystem`, `direct-tcpip`, `forwarded-tcpip`, `tcpip-forward`, `cancel-tcpip-forward`, X11 forwarding, agent forwarding, the SFTP subsystem — all of these work exactly as in classic SSH. The auth identity established by `mssh-cert` is simply the identity those channels run as.

The only new connection-protocol concept is the **authenticated channel** of `09-channel-plugin-interface.md`, which is requested via a new `channel-open` type. It coexists with classic channels; a session may have both a `session` channel running a shell and an authenticated channel running, say, a kubernetes proxy, simultaneously.
