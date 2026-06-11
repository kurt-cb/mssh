# Implementation notes: PKI hierarchy + per-issuer CRLs

Working notes against Kurt's [understanding.txt](../python/tests/lxc/understanding.txt)
discussion that pivoted the CA design from single-signer to a root +
named intermediates model. Captures the target design + concrete
migration plan so this work can be picked up cleanly across sessions.

---

## The model

Today (v1): the CA has one signing key for authz certs (signs short-
lived per-session grants AND bypass certs with a marker), and a
separate TLS CA for mTLS certs (server enrollment + admin). Two
hierarchies, each single-level (root signs leaves directly).

Tomorrow (v2): a single root CA at the top, four named intermediates
underneath, each scoped to a distinct purpose:

```
root (mssh-root, self-signed, long-lived ~20 years)
 ├── user-mint    — per-session authz certs (live grants)
 ├── bypass-mint  — operator-presentable CA-bypass authz certs
 ├── host-mint    — server identities (CA TLS cert, msshd mTLS cert)
 └── auth         — admin/client mTLS certs
```

### Why these 4 specifically

- **user-mint** is the hot path. Signs every `/v1/authorize` response.
  Compromise of its key means an attacker can mint live grants —
  rotation is sensitive but routine.
- **bypass-mint** is the cold-path "operator break-glass" path. Its
  signed certs are pre-issued and stored offline. Compromise of its
  key lets an attacker mint bypass certs that bypass live CA
  control. Highest-value key in the system; should rotate rarely,
  protected most carefully.
- **host-mint** signs server identities (CA's own TLS cert, msshd's
  outbound mTLS cert when calling CA). Compromise allows
  impersonation of a CA or a server but not authz.
- **auth** signs admin / client mTLS certs (mssh-admin authenticating
  to CA, mssh client authenticating to msshd if the operator uses
  mssh-CA for the user-facing PKI). Compromise allows impersonation
  of a user; doesn't directly grant authz.

Separating these means a compromised host-mint doesn't taint authz
chains; a compromised auth doesn't taint server identities; etc.
Each role rotates independently.

### Issuer identifier format

`<short-name>:<pubkey-fp16>` — short name for human readability in
logs, pubkey fingerprint (first 16 hex of SHA256 over SPKI) for
cryptographic stability. Survives renames; differs across
rotations.

Examples:
- `user-mint:7f3c4b2a8d1e5f60`
- `bypass-mint:a1b2c3d4e5f60718`

### On-disk layout (post-bootstrap)

```
<ca_dir>/
  root-cert.pem
  root-key.pem                              (mode 600)
  intermediates/
    user-mint/
      cert.pem
      key.pem                               (mode 600)
    bypass-mint/{cert.pem, key.pem}
    host-mint/{cert.pem, key.pem}
    auth/{cert.pem, key.pem}
  crl/                                       (Phase 3)
    user-mint.jsonl
    bypass-mint.jsonl
    host-mint.jsonl
    auth.jsonl
  tls-server-cert.pem                       (leaf + host-mint chain bundle)
  tls-server-key.pem                        (mode 600)
  bootstrap-admin-cert.pem                  (leaf + auth chain bundle)
  bootstrap-admin-key.pem                   (mode 600)
  enrollment.yaml
  audit.jsonl
```

Leaf cert PEM files are CHAIN BUNDLES (leaf + intermediate concatenated).
Trust root is `root-cert.pem`; clients only need this to validate.

---

## Wire protocol changes

### Authorize request (msshd → CA)

```json
{
  "version": 1,
  "identity": {...},
  "connection": {...},
  "last_crl_seqs": {
    "user-mint:7f3c...": 42,
    "bypass-mint:a1b2...": 7
  },
  "protocol_version": "1.2",
  ...
}
```

`last_crl_seqs` is a map keyed by issuer_id. Backward-compat: if the
client sends `last_crl_seq` (singular, v1 protocol), the CA treats it
as user-mint's value for diagnostic purposes only.

### Authorize response

```json
{
  "status": "granted",
  "cert": "<base64-DER leaf + intermediate chain>",
  "serial": "abc123",
  "not_after": "...",
  "current_crl_seqs": {
    "user-mint:7f3c...": 45,
    "bypass-mint:a1b2...": 7,
    "host-mint:f7e6...": 0,
    "auth:d4c3...": 12
  },
  ...
}
```

`current_crl_seqs` lists every issuer the CA knows about + its
current sequence. msshd compares against its `last_crl_seqs`; for any
issuer where current > last, msshd fetches missing CRL entries.

### CRL fetch

```
GET /v1/crl?issuer=<issuer_id>&after=N&limit=K
```

Returns CRLs for the specified issuer only. One issuer per call.
msshd iterates over its stale issuers and fetches each.

---

## Migration story

**Big-bang.** v2 CAs are not wire-compatible with v1 msshds and vice
versa. Existing deployments do a planned fleet rebuild:

1. Stand up a v2 CA fresh (new root + 4 intermediates).
2. Re-enroll servers (`mssh-admin server add <name>`) — get fresh
   server mTLS certs signed by host-mint.
3. Re-enroll users (`mssh-admin user add <name>`) and re-add their
   pubkeys.
4. Re-issue any bypass certs from the new bypass-mint.
5. Distribute new server mTLS certs + the new `root-cert.pem` (msshd's
   `ca.ca_pubkey`).
6. Cut over msshd hosts to the new CA endpoints.

Existing v1 deployments don't really exist yet (mssh is pre-release),
so the cost of big-bang is small. If real v1 deployments emerge later,
a compat shim could be added — but the cleaner long-term shape is the
fresh v2 hierarchy.

---

## Implementation plan (commit boundaries)

Each commit is independently shippable; tests stay green at each
boundary.

**Commit 1 (this commit) — Foundation, additive only.**
- `Intermediate` dataclass + `INTERMEDIATE_ROLES` + helpers
  (`compute_pubkey_fp16`, `make_issuer_id`)
- `_self_signed_root`, `_issue_intermediate`, `_issue_leaf`
  (Intermediate-based), `issue_server_cert`, `load_intermediates`,
  `load_root_cert`
- `mint_authorization_cert` + `issue_client_cert` accept BOTH legacy
  (`signing_key`/`signing_cert` or `tls_ca_key`/`tls_ca_cert`) AND
  new (`signing=Intermediate`) calling conventions
- `BootstrapArtifacts` extended (optional new fields, legacy fields
  preserved)
- `AuthorizeContext` gains optional `intermediates` + `root_cert`
  fields (used in Phase 4+)
- `CAConfig` gains optional `ca_dir` field (used in Phase 2+)
- `bootstrap_ca` STILL writes the legacy layout — tests unchanged
- This design doc shipped

**Commit 2 — Bootstrap refactor.**
- `bootstrap_ca` creates Root + 4 intermediates + writes new layout
- Legacy alias files written too (signing-key.pem etc. as symlinks
  or copies of user-mint's pair) so callers can transition gradually
- `ca/server.py:create_app` loads intermediates if `ca_dir` is set;
  falls back to legacy single-signer paths otherwise
- Tests for the new bootstrap output (`test_cert_minter.py` extended)

**Commit 3 — Per-issuer CRL.**
- `CRLStore` refactored to one-store-per-issuer; `CRLRegistry`
  holds the dict
- CA: `cert_revoke` admin handler takes `issuer_id` (or auto-detects
  by serial lookup via audit log)
- CA: `/v1/crl?issuer=X` endpoint
- CA: authorize response includes `current_crl_seqs` map
- Backward compat: a singular `last_crl_seq` / `current_crl_seq` in
  request/response is treated as user-mint's value

**Commit 4 — msshd chain validation + per-issuer cache state.**
- msshd loads root cert + (optionally) intermediates
- `_handle_bypass_injection` does real chain validation
  (leaf → intermediate → root) before injecting
- `AuthzCache.last_crl_seq: int` becomes `last_crl_seqs: dict[str, int]`
- `CRLSync` iterates over stale issuers, fetches per-issuer
- Strict-mode gate computes total gap across all issuers

**Commit 5 — mssh-admin commands.**
- `mssh-admin intermediate list` — show all 4 intermediates + their
  issuer_ids + cert validity windows
- `mssh-admin intermediate rotate <role>` — generate a new keypair
  for one intermediate, sign with root, update on-disk layout
- `mssh-admin cert revoke --issuer <id|name>` — explicit issuer
  selection; default auto-detects via enrollment audit lookup

**Commit 6 — Backfill tests for prior commits.**
- Unit tests for `_handle_bypass_injection`
- Mocked enforce-flow tests (cache-hit / miss / CA deny / CA error
  with cache fall-back)
- Strict-mode gate tests
- `proxy_to_inner_ssh` prefetched-header tests

**Commit 7 — Doc consolidation.**
- Fold CLAUDE.md amendments into `design/security.md`,
  `design/architecture.md`, `design/api.md`, `design/ca.md`
  (append-only; preserve historical amendment sections)
- New `docs/operations.md` section: intermediate rotation procedure

---

## Pieces deferred beyond this work

These are intentionally out of scope:

- **Root key offline / HSM.** The root key today sits on disk
  alongside intermediates. Production deployments would put it in
  a hardware module or on an offline machine. Plumbing for that is
  v3+.
- **Cross-CA federation.** Multiple mssh CAs sharing a common root,
  for dev/staging/prod hierarchies. Out of scope.
- **Cert transparency / public log.** Not relevant for a
  private-network CA.
- **Multi-key-per-principal cache key.** Today `authz_cache` is
  keyed by principal; future multi-device support would key by
  `(principal, identity_fingerprint)`. The per-principal eviction
  cap is in place for that future.

---

## Amendment 2026-05-20: validation rule + External Intermediate CA

This amendment adds two pieces that the original 4-intermediate
design left implicit. Both are load-bearing for §5 (cert minting
for other applications) and §25 (`mssh-admin pki`).

### The validation rule

**mssh validates to the authoritative intermediate, not the Root.**
The Root signs intermediates; once §5 expansion exists, the Root
also indirectly signs application-level leaves (TLS server, OpenVPN
clients, code-signing). A validator that accepts "chain validates
to Root" therefore accepts those §5 leaves for mssh auth — exactly
the attack vector to close.

Concrete trust store contents per role:

| Validator | Trust anchor (intermediate cert pinned) |
|---|---|
| msshd, validating incoming user mTLS handshake | **auth** |
| msshd, validating authz cert in /v1/authorize response | **user-mint** |
| mssh, validating msshd's TLS server cert | **host-mint** |
| mssh-admin, validating mssh-ca's TLS server cert | **host-mint** |
| Anyone, validating a bypass cert presented for injection | **bypass-mint** |

The trust store file contents (one of the `/etc/mssh/*.pub` files,
or `~/.mssh/ca.pem` on the client side) is the SPECIFIC
intermediate cert. Chain validation walks leaf → intermediate
(must equal pinned cert) → Root. If the chain doesn't terminate at
the pinned intermediate, validation fails — even if the chain
correctly walks to Root through some other intermediate.

This is standard X.509 — `verify_certificate` in cryptography (and
OpenSSL's `X509_STORE_CTX_init` with the pinned intermediate as
the trust store) does the right thing. The discipline is in NEVER
putting the Root cert alone in a trust store; always pin the
intermediate.

### The External Intermediate CA tier (new)

§25 introduces a use case the original 4-intermediate model doesn't
cover: the operator wants to delegate signing authority to an
external entity who can then mint whatever leaves they want, without
giving them direct access to the mssh Root.

The shape:

```
root (mssh-root)
 ├── user-mint        (path_length=0)
 ├── bypass-mint      (path_length=0)
 ├── host-mint        (path_length=0)
 ├── auth             (path_length=0)
 └── external-<name>  (path_length >= 1, optional sub-CAs allowed)
     │
     └── anything the external entity chooses to sign
         (NOT honored by mssh for any auth decision)
```

Differences from the 4 internal intermediates:

1. **path_length.** Internal intermediates are `path_length=0` (they
   sign leaves only, never another CA). External-X carries
   `path_length=N` where N is operator-chosen — typically 1 (allow
   one sub-CA layer) or 0 (external leaves only).
2. **Marking.** External CAs carry `Organization=<entity name>` and
   `OrganizationalUnit=external`. The mssh-CA records the mint in
   its audit log with the external-X serial; revocation goes through
   the standard CRL channel.
3. **Trust-store exclusion.** No mssh validator has external-X in
   its trust store. A leaf chaining through external-X terminates
   the chain validation without a trust anchor — refused.

### The attack vector this guards against

Without intermediate-pinning OR the external tier:

  - **§5 leaves leak into auth.** Operator runs `mssh-admin cert mint
    --type tls-server --cn alice.example.com` thinking it's just a
    web cert. An attacker who controls alice's TLS server can
    present that leaf as a user mTLS handshake to msshd. msshd
    validates "chain → Root", accepts, alice impersonated.
  - **External CA mints imposter.** Operator stands up an external-X
    for a partner org. Partner mints a leaf with CN=admin-bob,
    presents to msshd → CA admin endpoint. CA validates "chain →
    Root", accepts as bootstrap-admin, full superuser privileges.

With intermediate-pinning AND external tier:

  - §5 leaves are signed by `host-mint` (TLS server) or `auth`
    (HTTPS user / OpenVPN) — distinct from `user-mint` (authz) and
    distinct from each other if needed.
  - External CAs are signed by Root but NOT trusted by msshd or
    mssh-admin for auth. msshd's trust store contains `auth`, not
    Root; chain validation walks leaf → external-X → Root, but
    external-X != auth, so the chain doesn't terminate at the trust
    anchor and validation fails.
  - The msshd validator never even consults Root.

### Implication for §5 work that has already landed

The v0.1.4 §5 commands (`cert mint --type ...`, `openvpn issue`,
`wireguard ...`) sign through the LEGACY single-signer hierarchy
(`tls-ca-key.pem`). v1 single-signer has only one root and signs
everything — there's no per-purpose intermediate yet, so
intermediate-pinning doesn't apply. The validation property
described above lands when v2 (commits 2-7 of this doc) ships.

Until then, operators issuing §5 leaves are mixing certs under one
signing key. Acceptable for small/experimental deployments,
explicitly not the production end-state.

### Open implementation question (defer)

Should `external-<name>` use `path_length >= 1` (sub-CA chain) or
`path_length = 0` (external entity mints only leaves)? Probably
operator choice via a flag on the mint command — `mssh-admin pki
external mint --name partner-x --path-length 0`. The
intermediate-pinning rule protects mssh regardless of which they
choose; the path-length controls what shape the external entity's
own infrastructure takes.

---

## Why we're shipping this in phases

The full v2 hierarchy is ~1500-2000 LOC across CA + msshd + admin +
tests + docs. Doing it as a single commit risks leaving the test
suite red in an interim state if the session can't finish.

Phased commits, each leaving tests green, lets us:
- Pick up across sessions without losing progress
- Code-review one piece at a time
- Roll back individual phases if a design issue surfaces

The trade-off is some throwaway compat-shim code in Commit 1
(legacy parameter aliases in `mint_authorization_cert` etc.) that
gets cleaned up in later commits. Acceptable cost for the
phased-deployment property.
