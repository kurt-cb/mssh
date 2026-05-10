# 05. Rotation, 2FA, and Session Lifetime

mssh certs are short-lived. A user cert may be valid for hours; a machine cert for days. This is by design — it means revocation happens by expiry rather than by online lookup, which keeps the system robust and the constrained validators simple. But short validity only works if rotation is cheap and routine. This document defines how.

## Three lifecycle events

Three things can happen during a session that involve cert lifecycle:

1. **Rotation.** Either party's cert is approaching expiry. A new cert is obtained from the CA and signaled to the peer. The session continues with the new cert.
2. **Time extension.** The user requests more session time. The server consults its policy (and possibly the CA) and either grants an extension by signing a refreshed cert, or refuses, in which case the session ends at the original expiry.
3. **New-location rebinding.** The user's source IP has changed (laptop moved to a new network, NAT rebinding, VPN switched). The cert's `mssh-source-bind` no longer matches. The user is offered the chance to obtain a re-issued cert from the CA, gated by whatever 2FA the CA requires.

All three are voluntary on the user side and policy-driven on the CA side. None of them require killing and restarting the SSH session, except in the failure case.

## 2FA: where it actually happens

There is exactly one place where 2FA is performed in mssh: **at the CA, at cert issuance time.** sshd never asks for a TOTP code, an SMS code, a hardware token press, or anything else interactive from the user during a session.

The reason is architectural cleanliness. sshd's job is to validate certs. If 2FA were performed at sshd, sshd would need a 2FA backend, secret storage, recovery flows, and lockout policy — none of which are sshd's business. By moving 2FA to the CA, sshd remains a small, stateless validator. Operational complexity lives in the CA, which is where it belongs.

This has a useful consequence: 2FA evidence is carried in the cert itself, in the `mssh-2fa-evidence` extension. A cert can attest "this user completed TOTP within the last 60 minutes" or "this user touched a hardware token in the last 5 minutes" or "this cert was issued from a session that itself was issued under TOTP and is now in its 4th derived issuance." sshd policy can require a minimum freshness or method type for certain operations.

Three scenarios make this concrete:

**Routine work.** User comes in for the day, authenticates to the CA with smartcard PIN + TOTP, receives a cert valid for 8 hours. `mssh-2fa-evidence` records the methods used and the timestamp. Connects to servers all day; servers accept the cert without further 2FA. At end of day, the cert expires and they're done.

**Sensitive operation.** Some servers' policy requires 2FA evidence within the last 15 minutes. When the user tries to connect, the server inspects `mssh-2fa-evidence`, sees the timestamp is 4 hours old, refuses with a specific error. The user goes back to the CA, re-authenticates with TOTP (smartcard is still unlocked, no PIN re-entry needed), receives a fresh cert with a new evidence timestamp, retries. The friction is real but localized.

**New location.** User opens their laptop at a coffee shop. Existing cert's `mssh-source-bind` is `10.0.0.0/24` (the office). The first mssh connection from the new IP fails source-bind validation. The client detects this — it knows the cert's source-bind contents and the local IP — and prompts the user to re-issue. The user re-authenticates to the CA (this time the CA's policy may require stronger 2FA because the request originates from an unbound IP), receives a new cert that includes the new IP in source-bind. The session can now proceed.

## The mssh-2fa-evidence extension

```
TwoFactorEvidence ::= SEQUENCE {
   issuedAt           GeneralizedTime,
   methods            SEQUENCE OF Method,
   parentEvidenceHash OCTET STRING OPTIONAL,
                      -- SHA-256 of the parent cert's evidence,
                      -- if this cert was issued during rotation
                      -- without re-presenting 2FA
   freshnessDepth     INTEGER DEFAULT 0
                      -- 0 = this cert was issued under fresh 2FA
                      -- N = this cert is the Nth derived issuance
                      --     from a 2FA root
}

Method ::= SEQUENCE {
   methodOID    OBJECT IDENTIFIER,
   timestamp    GeneralizedTime,
   keyId        OCTET STRING OPTIONAL  -- e.g., the public key of
                                       -- the hardware token used
}
```

`freshnessDepth` is the key field for rotation. When a session rotates without requiring the user to re-authenticate to the CA, the new cert is issued with `freshnessDepth = parent.freshnessDepth + 1` and `parentEvidenceHash` set to the parent cert's evidence hash. This forms a chain of derived issuances anchored to a real 2FA event.

sshd policy can require `freshnessDepth ≤ N` for certain operations, capping how far a cert can be "rolled forward" without re-presenting 2FA. The CA's policy independently controls the max depth it will issue at — typically 0 for high-security operations (forcing 2FA on every issuance) and unbounded for routine work within the same workday (rotation chains freely).

Method OIDs are registered. A non-exhaustive starting set:

- `1.3.6.1.4.1.RESERVED.1.4.1` — TOTP (RFC 6238)
- `1.3.6.1.4.1.RESERVED.1.4.2` — WebAuthn / FIDO2
- `1.3.6.1.4.1.RESERVED.1.4.3` — Smart card PIN (with cert-bound PIN attestation)
- `1.3.6.1.4.1.RESERVED.1.4.4` — Out-of-band push approval (e.g., enterprise mobile app)
- `1.3.6.1.4.1.RESERVED.1.4.5` — Hardware biometric (fingerprint, attested by platform)

## Rotation: the protocol

Rotation can be initiated by either party.

**Client-initiated.** The client notices its cert is approaching expiry (configurable; default: 25% of total validity remaining). It contacts its CA via the REST API, obtains a new cert, and signals the server:

```
byte      SSH_MSG_USERAUTH_ROTATE
string    new cert        ; DER X.509 leaf
string    new chain       ; intermediates
string    signature       ; over session id || new cert || new chain
                          ; signed with the new cert's private key
```

The server validates the new cert with the same checks as initial auth (profile, conformance, validity, source-bind, etc.) and additionally requires:

- The new cert's subject matches the existing session's authenticated identity (same user, same `CN`).
- The new cert's issuing CA is one the server trusts (typically the same CA the original cert was from, but cross-CA rotation is permitted if the trust roots allow).
- The new cert's `freshnessDepth` does not exceed the policy maximum for this server.
- The new cert's `mssh-2fa-evidence` `issuedAt` is not older than the policy maximum.

On acceptance, the server sends:

```
byte      SSH_MSG_USERAUTH_ROTATE_ACCEPT
uint64    new effective-from time
```

From `effective-from` onward, the new cert is the session identity. The old cert is discarded.

On rejection, the server sends:

```
byte      SSH_MSG_USERAUTH_ROTATE_REJECT
uint32    reason code
```

Reason codes are from the same registry as auth failures. The session continues under the old cert until expiry; the client may retry rotation (with a different cert) or accept that the session will end.

**Server-initiated.** Less common but supported. If the server's own cert is approaching expiry, it sends:

```
byte      SSH_MSG_USERAUTH_SERVER_ROTATE
string    new server cert
string    new chain
string    signature       ; over session id || new cert || new chain
                          ; signed with the new server cert's key
```

The client validates and responds with accept or reject, same shape as above. A failed server rotation is more serious — the client must decide whether to continue the session under a known-expiring server cert or to disconnect.

**Concurrent rotation.** If both sides try to rotate at once, the rotations are independent. Each side's identity rotates separately. The protocol does not require synchronization between them.

## Time extension: the protocol

Time extension is a special case of rotation where the new cert differs from the old only in `notAfter` and possibly `mssh-time-window`.

The client sends:

```
byte      SSH_MSG_USERAUTH_EXTEND_REQUEST
uint64    requested new notAfter
string    justification    ; UTF-8, max 256 bytes, may be empty
```

The server's response depends on policy:

- If the server has authority to extend on its own (configured `LocalExtensionPolicy` permits it), it consults the CA (or its embedded CA) to issue a refreshed cert, then sends `SSH_MSG_USERAUTH_EXTEND_GRANT` containing the new cert. The client validates and adopts it.
- If the server requires CA approval, it forwards the request to the CA via REST. The CA evaluates policy, possibly invokes an approval workflow (out-of-band push to a mobile app, email to a manager, etc.), and either signs a refreshed cert or declines. The server passes the result back to the client.
- If extension is forbidden, the server sends `SSH_MSG_USERAUTH_EXTEND_DENY` with a reason code. The session ends at the original expiry.

```
byte      SSH_MSG_USERAUTH_EXTEND_GRANT
string    refreshed cert
string    refreshed chain
string    signature        ; same shape as rotation

byte      SSH_MSG_USERAUTH_EXTEND_DENY
uint32    reason code
string    detail           ; human-readable, may be empty
```

Time extension respects an absolute maximum total session duration encoded in the cert's `mssh-time-window` extension. A cert may say "valid 8 hours, extensible to a hard max of 12 hours total." Once the hard max is reached, no further extension is possible — the user must obtain a wholly new cert (which means re-authenticating to the CA, including 2FA).

This caps the "extend forever" attack: even if a user can extend their session indefinitely, the cert says how far that can go.

## Session termination on cert expiry

When a cert's `notAfter` (or `mssh-time-window` end-of-window) is reached without successful extension:

- The server sends `SSH_MSG_USERAUTH_EXPIRED` with a 30-second grace warning.
- After the grace period, the server closes all channels and disconnects.

The grace period is small but non-zero so the user can save work and close cleanly. It is not extensible without an extension grant. The grace period itself does not require cert validity — the session is winding down, not authenticating new activity.

Server-side, the cert's expiry is enforced by a single timer per session. There is no expensive periodic re-validation; the timer fires once, the session ends.

## Source-address rebinding

When a client's source IP changes mid-session, the client SHOULD initiate a rebinding flow rather than letting the session drift. The flow is essentially rotation with a new cert that has updated `mssh-source-bind`.

If the new IP would not be granted by the CA's policy (e.g., it's a known-bad network, the user is roaming internationally without explicit travel permission, etc.), the CA refuses to issue, and the session continues from the old IP only — any TCP-level connection failures from the IP change become hard session failures.

Source-address rebinding is the most likely trigger for 2FA re-presentation in practice. CA policy commonly requires "for the first cert from a previously-unseen IP, require fresh 2FA." Subsequent connections from the same IP can roll forward without re-presenting 2FA, up to the freshness-depth cap.

A client-side helper detects IP changes (interface up/down events, DHCP renewal moving the gateway, etc.) and triggers rebinding before sshd notices a TCP issue. This is a quality-of-life feature, not a security primitive — the security guarantee is that all cert validation requires the *current* IP to match source-bind, so a mid-flight IP change without rebinding will fail at the next validation.

## Rotation across hops

When a session traverses a hop chain, rotation has additional considerations:

- The user can rotate their own cert mid-session. The new cert is signaled to the destination directly; intermediate hops are not informed (they do not have an authoritative view of the session identity anyway — they are forwarders).
- A hop's own cert may expire. When a hop's cert is approaching expiry, the hop rotates *its own* cert with its CA, and the hop's `mssh-hop-deleg` is updated in the new cert. Existing sessions traversing the hop are not affected (the hop's contribution to a chain is the signed entry at hop-time, which remains valid). New sessions from this point on use the rotated hop cert.
- If a hop's cert is revoked mid-session, the session terminates at the destination on the next cert validation pass (which the destination triggers periodically, not just at session start, for the hop attestations specifically). Existing sessions through a revoked hop are not allowed to live to natural expiry.

## What is deliberately not here

- **No keepalive-based renewal.** Some protocols treat liveness as license to extend session validity automatically. mssh does not. Liveness is not authorization. A session whose cert is about to expire must explicitly rotate or end; it cannot drift past expiry by being chatty.
- **No "session bind" tokens.** The session identity *is* the cert. There is no separate session token that outlives or extends the cert.
- **No password fallback "in emergencies."** If a user's cert expires and they cannot reach the CA, the session ends. The recovery is to obtain a new cert via whatever recovery path the CA defines (which may be slow and involve human approval — that is the point).
