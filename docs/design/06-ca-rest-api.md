# 06. CA REST API

The mssh CA exposes an HTTPS REST interface over mutual TLS. Every interaction between sshd or an mssh client and the CA goes through this interface. This document defines the wire-level API; the policy logic behind it is the CA implementer's choice.

## Transport requirements

- **HTTPS only.** Plain HTTP is forbidden. A CA that listens on port 80 with redirect-to-443 is acceptable; one that serves the API over plain HTTP is not.
- **TLS 1.3 minimum.** TLS 1.2 is permitted only when explicitly enabled for legacy client compatibility, and only with the same restricted cipher set OpenSSH uses for its own transport.
- **Mutual TLS.** The CA presents a server cert. Clients (sshd, the mssh client, automated provisioning tools) present client certs. Both are validated against the deployment's trust root.
- **No public CA validation.** The CA's server cert MUST chain to the deployment's private trust root, not to any public CA. Likewise, the CA only accepts client certs from the private trust root. WebPKI is not used.
- **Client cert identity drives authorization.** The CA does not have its own user database for API access. The client cert's subject is the API identity; the CA's policy uses that identity to decide which endpoints the client may call.

## Base URL and versioning

The base URL is operator-chosen, e.g., `https://ca.example.internal:8443/`. All endpoints live under `/v1/`. Future protocol revisions use `/v2/`, etc.

A CA MUST also expose `/.well-known/mssh-ca` returning a JSON document describing its capabilities:

```json
{
  "version": "1",
  "supportedProfiles": ["constrained", "full"],
  "supportedAlgorithms": ["ecdsa-p256", "ecdsa-p384", "ed25519", "rsa-2048", "rsa-3072"],
  "ocspUrl": "https://ca.example.internal:8443/v1/ocsp",
  "crlUrl": "https://ca.example.internal:8443/v1/crl",
  "issuerSubject": "CN=Acme Intermediate, OU=ca, O=Acme, C=US",
  "issuerSki": "8c9f...",
  "conformanceAttestation": {
    "suiteVersion": "1.0",
    "attestedAt": "2026-04-10T00:00:00Z",
    "attestor": "self"
  },
  "extensionsRegistered": ["mssh-source-bind", "mssh-time-window", ...]
}
```

This endpoint is the only one that does not require client authentication, because clients use it to discover whether they want to talk to this CA at all.

## Endpoints

The full set is small. Each is described below.

### POST /v1/csr

Submit a certificate signing request. The principal use case.

**Request:**
```json
{
  "csr": "<PEM-encoded PKCS#10>",
  "requestedProfile": "constrained",
  "requestedIdentityType": "user",
  "requestedValidity": 28800,
  "requestedSourceBind": ["10.0.0.0/24", "192.168.1.42"],
  "requestedTimeWindow": { ... },
  "requestedHopDeleg": { ... },
  "requestedChannelPolicy": [ ... ],
  "requestedClusterScope": ["prod-web", "prod-data"],
  "twoFactorEvidence": {
    "methodOids": ["1.3.6.1.4.1.RESERVED.1.4.2"],
    "attestation": "<opaque method-specific blob>"
  },
  "parentCertSerial": "<hex, if this is a rotation request>",
  "justification": "<free-form, may be empty>"
}
```

The CSR carries the requested public key and a self-signature proving possession of the corresponding private key. Everything else in the request is metadata the CA uses to decide what extensions to embed in the issued cert.

The CA's policy is the final arbiter. It MAY:

- Issue exactly what was requested.
- Issue with narrower scope (shorter validity, fewer IPs in source-bind, etc.).
- Refuse entirely, with a specific error code.
- Request additional 2FA before issuing, in which case the response is `202 Accepted` with a continuation token (see `/v1/csr/{token}`).

**Successful response (200):**
```json
{
  "cert": "<PEM-encoded X.509>",
  "chain": ["<PEM-encoded intermediate>", ...],
  "serial": "<hex>",
  "notBefore": "2026-05-10T14:00:00Z",
  "notAfter": "2026-05-10T22:00:00Z",
  "actualSourceBind": ["10.0.0.0/24"],
  "actualValidity": 28800,
  "issuanceLogId": "<opaque, for audit retrieval>"
}
```

**Continuation response (202):**
```json
{
  "continuationToken": "<opaque>",
  "expiresAt": "2026-05-10T14:05:00Z",
  "requiredActions": [
    {
      "type": "totp",
      "prompt": "Enter the 6-digit code from your authenticator app"
    }
  ]
}
```

The client completes the required actions and POSTs to `/v1/csr/{continuationToken}` with the responses. See "Continuation flow" below.

**Error response (4xx/5xx):** see "Error model".

### POST /v1/csr/{continuationToken}

Continue a deferred CSR.

**Request:**
```json
{
  "responses": [
    {"type": "totp", "value": "123456"}
  ]
}
```

**Response:** same shape as `POST /v1/csr`, either successful issuance, another continuation step (multi-factor flows can chain), or error.

### POST /v1/extend

Extend the validity of an existing cert. Server-initiated during session extension flows.

**Request:**
```json
{
  "certSerial": "<hex>",
  "requestedNewNotAfter": "2026-05-10T23:00:00Z",
  "justification": "<free-form>",
  "twoFactorEvidence": { ... }
}
```

**Response:** same shape as CSR responses. A successful response contains a *new* cert with the extended validity — extensions are issued as new certs, not as modifications to an existing cert (X.509 has no in-place modification). The new cert's serial differs from the original; the original is implicitly superseded but not revoked (it expires naturally).

### POST /v1/revoke

Revoke a cert. Called by administrative tools or by sshd when it detects a compromise indicator (e.g., reused nonce, signature failure from a cert that previously validated).

**Request:**
```json
{
  "certSerial": "<hex>",
  "reason": "keyCompromise",
  "justification": "<free-form>"
}
```

Reason values follow RFC 5280 CRL reason codes: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `aACompromise`. `aACompromise` is for attribute authorities and not used by mssh; `certificateHold` should be avoided because it implies reinstatement, which complicates state.

**Response:**
```json
{
  "revoked": true,
  "revokedAt": "2026-05-10T14:30:00Z",
  "appearedInCrlAt": "2026-05-10T14:30:00Z"
}
```

The `appearedInCrlAt` is the earliest CRL refresh that will include this revocation; this is what other servers should expect to see.

### GET /v1/cert/{serial}

Retrieve a previously-issued cert by serial. Useful for audit, for re-checking validity, and for distributing certs to multiple nodes that share a cert (machine certs in clusters).

**Response:**
```json
{
  "cert": "<PEM>",
  "chain": [...],
  "status": "valid|revoked|expired",
  "revokedAt": null,
  "revocationReason": null,
  "issuanceLogId": "<opaque>"
}
```

### GET /v1/crl

Retrieve the current CRL. Returns DER bytes with `Content-Type: application/pkix-crl`. Cacheable per HTTP semantics with a short max-age (default 5 minutes). The CRL is signed by the same CA that issued the certs it lists.

### POST /v1/ocsp

OCSP responder per RFC 6960. Standard OCSP request/response. The response is `Content-Type: application/ocsp-response`.

### GET /v1/audit/{issuanceLogId}

Retrieve the audit record for an issuance. Access controlled by client cert identity — only administrators with appropriate cert extensions can fetch arbitrary records; users may retrieve their own.

**Response:**
```json
{
  "issuanceLogId": "<opaque>",
  "issuedAt": "2026-05-10T14:00:00Z",
  "issuedTo": "CN=alice, OU=users, O=Acme, C=US",
  "issuedBy": "CN=Acme Intermediate, OU=ca, O=Acme, C=US",
  "requestedFrom": "192.0.2.42",
  "twoFactorMethods": ["totp", "smartcard-pin"],
  "policyDecisions": [
    "validity narrowed: requested 86400, granted 28800",
    "source-bind narrowed: requested 0.0.0.0/0, granted 10.0.0.0/24"
  ],
  "certSerial": "<hex>",
  "parentIssuanceLogId": "<opaque, for rotation chains>"
}
```

## Continuation flow

When an issuance request requires additional 2FA or human approval, the CA returns `202 Accepted` with a continuation token and a list of required actions.

Required action types:

- `totp` — present a TOTP code.
- `webauthn` — produce a WebAuthn assertion. The action description includes the challenge and the credential ID expected.
- `push-approval` — wait for out-of-band approval (push to a mobile app, email, etc.). The client polls `/v1/csr/{token}/status` until approved or denied.
- `human-approval` — wait for a human (a designated approver) to authorize. Same polling shape.
- `wait` — simple time delay before completion. Used for rate limiting.

The client completes each action in turn by posting to `/v1/csr/{token}`. A continuation that exceeds its `expiresAt` is gone — a new CSR must be initiated.

## Error model

Errors follow RFC 7807 (Problem Details for HTTP APIs) with mssh-specific extensions.

**Generic error response:**
```json
{
  "type": "https://mssh.example/errors/algo-forbidden",
  "title": "Algorithm not permitted",
  "status": 400,
  "code": "ALGO_FORBIDDEN",
  "detail": "Requested key algorithm RSA-1024 is below the minimum permitted size 2048.",
  "instance": "/v1/csr",
  "field": "csr.publicKey.size"
}
```

The `code` field is the stable machine-readable error code from the conformance registry (`03-conformance.md`). The `field` field points to the offending request element when applicable.

Error codes are stable across protocol versions: a given numeric code always means the same thing.

## Rate limiting

CAs SHOULD rate-limit CSR submissions per client cert identity. Recommended defaults:

- 10 CSRs per minute per user identity.
- 100 CSRs per hour per user identity.
- 1000 CSRs per hour per machine identity (machines rotate more aggressively).

Rate limit exhaustion returns `429 Too Many Requests` with a `Retry-After` header.

## Pagination

Endpoints that list (e.g., `/v1/cert/list`, not defined above but expected in admin interfaces) use cursor-based pagination via `?cursor=<opaque>&limit=N`. Response includes `nextCursor` if more results exist. No offset-based pagination, no total counts.

## Idempotency

CSR submission is **not** idempotent by default. Submitting the same CSR twice produces two distinct certs with two distinct serials. Clients that need idempotency provide an `Idempotency-Key` header (RFC standardization in progress; we use the de-facto convention) and the CA records the result of the first call and returns the same result for repeated calls within a 24-hour window.

## Audit logging

Every state-changing operation (CSR, extend, revoke) is logged. The log is:

- Append-only.
- Signed (a Merkle-tree-style structure where each entry includes a hash of the previous; the tree root is periodically signed by the CA and optionally published to a transparency log).
- Retained per deployment policy. The defaults in the reference embedded CA are 1 year.

Audit log access is via `/v1/audit/{issuanceLogId}` (single record) and an admin-only `/v1/audit/range` endpoint (range queries) not detailed here.

## What is NOT in this API

- **No user/account management.** The CA does not have users in the SaaS sense; it has principals identified by client certs. Where those principals come from — LDAP, AD, a local file, a hand-curated YAML — is the CA implementer's choice and is not part of this protocol.
- **No password endpoints.** No `POST /v1/password`. No password reset. No password policy. Passwords do not exist in this system.
- **No session management.** API access is per-request; mTLS handles the identity binding. There is no login endpoint, no logout, no cookie.
- **No public registration.** A new principal must be enrolled by an existing administrator out-of-band (bootstrapping the client cert that grants API access). The CA REST API does not include a self-service enrollment endpoint; deployments that want one must build it on top.
