# 07. Embedded CA

For small deployments — a homelab, a single development team, an edge appliance — running a separate CA process is overkill. mssh includes a minimal CA implementation that sshd can host directly. This document describes what it does, what it does not do, and when to graduate to an external CA.

## Goals

- **Single binary.** sshd with the embedded CA compiled in. No additional processes to install or manage.
- **File-backed.** State lives in a small set of files under a configured directory. No database, no external dependencies beyond OpenSSL.
- **Same API.** Even though the CA runs in-process, it speaks the same REST API as the external CA, exposed on a local Unix socket. This means tooling that targets the external CA also works against the embedded one.
- **No more than 50 principals.** Past this scale, the lack of indexing and the simplistic policy engine become limiting. The embedded CA logs a warning and refuses to issue past 50.
- **Bootstrap to functional in under 5 minutes.** A new operator runs one command to generate a root, configures sshd, and is ready to issue certs.

## Non-goals

- **No LDAP/AD integration.** Principals are local-only.
- **No clustering or replication.** A single host owns the CA state. Sharing across hosts means using an external CA.
- **No complex policy engine.** Policy is a small YAML file. No rule expressions, no scripts.
- **No web UI.** Management is CLI-only.
- **No transparency log integration.** Audit log is local-only.

## File layout

```
$CA_DIR/
  config.yaml             # Policy configuration
  root.cert.pem           # Root CA cert (self-signed)
  root.key.pem            # Root CA private key (OFFLINE in serious deployments)
  intermediate.cert.pem   # Currently-active intermediate CA cert
  intermediate.key.pem    # Currently-active intermediate CA private key
  intermediate.chain.pem  # Chain from intermediate up to root
  principals.yaml         # Enrolled principals (users, machines, domains)
  issued/
    <serial>.cert.pem     # Every issued cert, indexed by serial
    <serial>.meta.json    # Metadata (issuance log)
  revoked/
    <serial>.json         # Revocation record
  crl/
    current.crl           # Latest CRL
    current.crl.sig       # Detached signature (for integrity)
  audit/
    log-<date>.jsonl      # Append-only audit log, one file per day
    chain.txt             # Merkle chain root, updated on each append
  socket
                          # Unix socket for the REST API
```

The directory's owner is the dedicated `mssh-ca` user, mode 0700. The intermediate key must be readable by sshd; the root key should be moved offline after intermediate signing, or readable only by a separate administrator user.

## The config file

```yaml
ca:
  organization: "Acme"
  country: "US"
  root_subject: "CN=Acme Root, OU=ca"
  intermediate_subject: "CN=Acme Intermediate, OU=ca"
  root_validity_days: 3650
  intermediate_validity_days: 365

profiles:
  default: constrained
  permitted: [constrained, full]

validity_defaults:
  user_seconds: 28800           # 8 hours
  machine_seconds: 2592000      # 30 days
  domain_seconds: 7776000       # 90 days

validity_maximums:
  user_seconds: 86400           # 24 hours
  machine_seconds: 2592000
  domain_seconds: 7776000

source_bind:
  require_explicit: true        # Refuse 0.0.0.0/0 source-bind
  permitted_cidrs:              # Whitelist
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "2001:db8::/32"

two_factor:
  required_for_user_issuance: true
  required_methods: [totp]      # Or webauthn, etc.
  new_source_requires_fresh: true
  freshness_max_seconds: 3600   # 1 hour
  derived_issuance_max_depth: 8 # How far rotation can chain without re-2FA

hop_delegation:
  default_max_hops: 4
  default_allow_rewrite_user: false

approval:
  required_for:
    - "validity > 14400"        # Approve any cert with > 4h validity
    - "source_bind = 0.0.0.0/0" # Approve any unbound source-bind
  approvers:
    - "CN=admin, OU=users"

revocation:
  crl_refresh_seconds: 300
  ocsp_enabled: false           # Embedded CA does not ship OCSP

audit:
  retention_days: 365
```

Every value has a documented default; the only thing an operator MUST set is the `ca.organization` and `ca.country`. Everything else can be left at defaults for a working deployment.

## Bootstrap

The CLI tool `mssh-ca init`:

1. Creates the directory layout.
2. Generates the root key and self-signed root cert.
3. Generates the intermediate key and signs the intermediate cert with the root.
4. Generates the intermediate's conformance attestation (self-signed; sufficient for small deployments).
5. Writes a default `config.yaml`.
6. Prints next steps (enrolling principals, configuring sshd).

Total time: under 30 seconds. Manual review of the generated files and config: 5 minutes.

Subsequent commands:

- `mssh-ca enroll user alice --2fa-totp` — register alice as a user, generate her TOTP secret, output QR code.
- `mssh-ca enroll machine webserver1.example.com` — register a machine.
- `mssh-ca issue --cn alice --source-bind 10.0.0.0/24` — directly issue a cert (admin override).
- `mssh-ca revoke <serial>` — revoke.
- `mssh-ca rotate-intermediate` — generate a new intermediate, sign with root, mark old as still-trusted-for-validation-but-no-new-issuance.

## Policy enforcement

The embedded CA implements every conformance rule from `03-conformance.md`. It does not have any kind of policy DSL — the rules are coded into the CA itself, parameterized by the YAML config. The configurable axes are:

- Permitted source-bind CIDRs.
- Required 2FA methods.
- Validity defaults and maxima.
- Approval thresholds.
- Hop delegation defaults.

That's it. Anything more sophisticated requires the external CA.

## Approval workflow

The embedded CA supports a minimal approval flow: if a CSR matches an `approval.required_for` condition, the request is held in a pending state, and any configured approver can approve via:

```
mssh-ca approve <pending-id>
mssh-ca deny <pending-id> --reason "..."
```

Pending CSRs expire after 1 hour by default. The CSR submitter polls via the continuation API to see status.

There is no web interface, no email notification, no integration with chat systems. An external CA that needs those builds them itself.

## Audit log

Every issuance, extension, revocation, and approval decision is appended to today's `log-<date>.jsonl`. Each entry contains:

- Timestamp.
- Operation type.
- Actor (cert subject who initiated).
- Subject (cert subject affected).
- Cert serial (for issuance/revocation).
- A SHA-256 hash of the previous entry's full content.

After each append, the chain file is updated with the new tip hash. The chain can be verified by replaying the log and confirming each entry's previous-hash matches.

The chain is not externally published (no transparency log). For deployments that need that level of audit assurance, the external CA is the answer.

## Backup

The CA directory should be backed up regularly. The root key, in particular, is irreplaceable — losing it means rebuilding the deployment from scratch (every cert ever issued becomes untrusted).

Recommended approach: after `mssh-ca init`, immediately copy `root.cert.pem` and `root.key.pem` to encrypted offline storage, then delete the local copies. The intermediate cert/key remain on the host; the root is only consulted to sign new intermediates (which happens roughly yearly). This is a poor-man's offline root.

For homelab/single-host deployments, even this is often overkill — a regular encrypted backup of the whole `$CA_DIR` is fine.

## REST API socket

The embedded CA exposes its REST API on `$CA_DIR/socket` (a Unix domain socket). sshd connects to this socket using its locally-stored client cert (also generated during `mssh-ca init`). External tools (admin CLI, scripts) connect using their own client certs.

The wire format is identical to the external CA's HTTPS REST API. Tools that work against the external CA work against the embedded CA with only the base URL changed (and HTTPS→HTTP+UnixSocket).

mTLS is enforced even over the local socket. The reason: the socket is under `$CA_DIR/` which is mode 0700 to the CA user, but defense in depth means a process running as the CA user that probably shouldn't be issuing certs (e.g., a buggy backup script) still gets caught by the lack of a valid client cert.

## When to graduate

The embedded CA is a starter implementation. Operators graduate to an external CA when any of:

- Principals exceed 50.
- Multiple sshd hosts need to share the same CA state.
- Policy needs to come from LDAP/AD/an HR system.
- Audit needs to integrate with a SIEM or transparency log.
- Approval workflows need richer features (chat integration, mobile push, ticketing).
- High availability is required.

The graduation path is straightforward: stand up the external CA, copy the trust root and intermediate cert/key, point sshd at the external CA's URL via configuration, decommission the embedded CA. Issued certs continue to validate (same trust root); new issuances come from the new CA. No SSH client changes are needed.

## What the embedded CA proves

The embedded CA exists for three reasons:

1. To make mssh deployable at small scale without operational overhead.
2. To provide a reference implementation of the REST API.
3. To test the API design — if the embedded CA can comfortably implement the API, the API is probably not over-engineered.

It is not the recommended deployment for any serious environment. Serious environments use the external CA, with whatever policy and storage layer fits their needs.
