# 03. CA Conformance

The cert profile in `02-cert-profile.md` only has teeth if CAs actually conform to it. This document defines how that conformance is established, attested to, and verified at runtime.

## Why conformance matters

A profile is just words on a page. If a CA accidentally or maliciously issues a non-conforming cert — say, a user cert with a five-year validity, or with `mssh-source-bind` omitted, or with a forbidden algorithm — and a relying party accepts it, the profile has bought nothing.

Defense has two layers:

1. **At issuance**, the CA refuses to issue non-conforming certs. The conformance program below verifies that the CA's implementation actually does this.
2. **At connection time**, sshd (or the mssh client) re-validates every received cert against the profile. Belt and suspenders.

A non-conforming cert that escapes a buggy CA must still be rejected by sshd. A conforming cert from a trusted CA is accepted. The only certs that reach a session are those that both the CA and sshd agreed are conforming.

## The conformance test suite

A formal test suite ships with the mssh spec. It is structured as:

- **Issuance tests**: the CA under test is asked, over its REST API, to issue specific certs. The resulting certs are validated against the profile by the test harness.
- **Rejection tests**: the CA under test is asked to issue specific *bad* certs. It MUST refuse. Each refusal must include a specific error code from the defined error registry.
- **Revocation tests**: the CA must publish a CRL containing previously-revoked certs, and OCSP responses (if it advertises OCSP) must agree with the CRL.

The test suite is versioned. A new minor version of mssh may add tests; a new major version may change existing tests. A CA's conformance attestation always declares which test suite version it passed.

### Issuance test categories

Each category contains 5–30 individual cases. Numbers in parentheses are rough counts; the actual count is fixed by the test suite version.

- **Minimal valid cert per identity type** (4): one for each of `user`, `machine`, `domain`, `ca-intermediate`. Verifies the bare-minimum conforming cert in each case.
- **All required extensions** (~15): every required extension present, valid values, correct criticality. Verifies field-by-field correctness.
- **Validity boundaries** (~8): certs at the maximum allowed validity for each identity type; certs at trivially short validity; certs spanning a DST transition; certs near year-2038 if the CA uses 32-bit time.
- **Source binding variations** (~10): single IP, multiple IPs, CIDR ranges, IPv6, the wildcard `0.0.0.0/0` (only accepted if policy allows).
- **Time window variations** (~8): recurring weekly windows, one-shot windows, time-window combined with outer Validity, time-window with extension policy.
- **Algorithm coverage** (~6): one cert per permitted signature algorithm.
- **Key size coverage** (~6): minimum and maximum key sizes for each algorithm family.

### Rejection test categories

These are the more important tests. The CA must refuse and return the correct error code.

- **Forbidden algorithms** (~10): requests for MD5/SHA-1/DSA/short keys must be refused with error `ALGO_FORBIDDEN`.
- **Forbidden extensions** (~8): requests including wildcards in subject DN, IP addresses in SAN, indirect CRL, etc., must be refused with `EXTENSION_FORBIDDEN`.
- **Validity overruns** (~5): requests for validity exceeding the per-type maximum must be refused with `VALIDITY_TOO_LONG`.
- **Missing required extension** (~10): requests that would result in a cert missing a required extension must be refused with `REQUIRED_EXTENSION_MISSING`.
- **Wrong criticality** (~6): requests asking for a critical extension to be non-critical or vice versa must be refused with `CRITICALITY_VIOLATION`.
- **Malformed subject DN** (~6): subject DN that doesn't match the prescribed format must be refused with `SUBJECT_MALFORMED`.
- **Cross-O/C issuance without explicit policy** (~3): requests for a cert in a different `O`/`C` than the issuing CA must be refused unless explicit cross-trust policy is configured. Refused with `TENANCY_VIOLATION`.

### Revocation tests

- **CRL freshness** (~3): after revoking a cert, the next CRL published within the CA's stated CRL refresh interval contains the revoked cert.
- **CRL signing** (~2): the CRL is correctly signed by the issuing CA (not an indirect CRL).
- **OCSP agreement** (~3, if OCSP advertised): OCSP responses for revoked certs return `revoked`; for never-issued serials, return `unknown`; for unrevoked valid certs, return `good`.

## Error code registry

All conformance-related errors use defined codes so the test harness can verify the CA refused for the *correct* reason. The full registry lives in the protocol spec. A small excerpt:

| Code | Name | When returned |
|------|------|---------------|
| 4001 | `ALGO_FORBIDDEN` | Requested algorithm not in permitted set |
| 4002 | `EXTENSION_FORBIDDEN` | Requested cert contains an extension not allowed by profile |
| 4003 | `VALIDITY_TOO_LONG` | Requested validity exceeds per-identity-type maximum |
| 4004 | `REQUIRED_EXTENSION_MISSING` | Requested cert lacks a required extension |
| 4005 | `CRITICALITY_VIOLATION` | Requested cert has wrong critical bit on a defined extension |
| 4006 | `SUBJECT_MALFORMED` | Subject DN does not match prescribed format |
| 4007 | `TENANCY_VIOLATION` | Cross-O/C issuance without explicit policy |
| 4008 | `2FA_INSUFFICIENT` | Issuance requires 2FA evidence not provided |
| 4009 | `SOURCE_NOT_AUTHORIZED` | Requested source-address binding includes addresses CA policy forbids |

Returning a generic error (e.g. `400 Bad Request` with no code) is itself a conformance failure.

## Conformance attestation

When a CA passes the conformance suite, the test harness produces an **attestation**: a signed statement saying "CA `<dn>` passed test suite version `<v>` on `<date>` with result `<pass|fail>`."

The attestation can be:

- **Self-attested**: the CA operator runs the test suite against their own CA and signs the result with the CA's own key. Acceptable for closed deployments where the operator trusts themselves.
- **Third-party-attested**: an independent party (an auditor, a community-run testing service, the project maintainers) runs the suite and signs the result with their own key. Required for any CA that wishes to be cross-trusted across organizational boundaries.

The attestation is embedded in the CA cert itself as the `mssh-ca-conformance` extension. The extension is critical: a CA cert without it cannot be used to issue mssh certs.

The extension contains:

- Test suite version number.
- Date of attestation.
- Hash of the full test report.
- Signature over the above by the attesting party.
- URL where the full test report can be retrieved (optional, informational).

## Runtime conformance checking

When sshd receives a client cert (or the client receives a server cert), it validates:

1. The cert's signature chains to a trusted root.
2. The cert profile is one sshd supports (constrained or full).
3. The cert itself conforms to the profile (every required extension present with correct criticality, no forbidden constructs, validity within bounds, etc.). This is a re-execution of the issuance tests, just against the received cert rather than asking a CA to issue it.
4. Every CA cert in the chain carries a valid `mssh-ca-conformance` extension attesting to a test suite version sshd trusts.

If any check fails, the connection is refused with a specific error message identifying which check and why.

The runtime conformance check is fast — it's roughly a dozen field comparisons, an extension-by-extension scan, and a few signature verifications. On the order of single-digit milliseconds per cert.

## Operating the conformance program

For self-attestation, the test suite ships as part of the mssh reference distribution. A CA operator runs `mssh-conformance --target https://my-ca.example.com:8443 --client-cert ... --client-key ...` and gets a pass/fail report plus the attestation blob to embed in the CA's cert.

For third-party attestation, the project maintainers maintain a public test-runner service that any deployment can request a run from. The third-party signing key is published in the project repository. Whether to trust third-party attestations is a deployment policy choice — sshd's `TrustRoot` configuration can be augmented with a `TrustedAttestor` list.

## Profile evolution

A new minor profile version (e.g., constrained-v1.1) is added when a new optional extension is defined that does not break older validators. Older validators ignore the unrecognized non-critical extensions; the cert is still valid for them. The conformance suite adds tests for the new extension and bumps to a new suite version.

A new major profile version (e.g., constrained-v2) is added when a previously permitted construct is removed or a previously forbidden one is added. Major version bumps are rare and require coordinated deployment — older sshd cannot validate v2 certs and must be upgraded first. The `mssh-profile` extension makes this version visible in the cert itself.

## What is explicitly out of scope

- A commercial certification body. This is not a CA/Browser Forum equivalent. Attestations are self-asserted or community-asserted, not commercially audited.
- Legal frameworks. No CP/CPS document is mandated. Operators may write one if they wish, but conformance is technical, not contractual.
- Cross-recognition of attestations from non-mssh PKI programs. WebPKI conformance does not confer mssh conformance and vice versa.
