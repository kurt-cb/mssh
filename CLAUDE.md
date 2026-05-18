# mssh

Runtime, CA-mediated SSH authorization system.

## Project summary

mssh moves SSH authorization out of the SSH protocol and into a
separate, network-restricted CA. The server contacts the CA at
every connection and gets a short-lived authorization back. The
client uses only their existing SSH key — no client changes.

The defining property: **a stolen client credential is useless if
the attacker can't reach the CA.** Put the CA on a private
network; stolen keys can't authorize from outside that network.

## Component naming

Canonical names:

- **mssh** — the client (`python/src/mssh/client.py`); `import mssh.client`
- **msshd** — the server-side gateway daemon (`python/src/mssh/msshd/`)
- **mssh-ca** — the central CA service (`python/src/mssh/ca/`)
- **mssh-admin** — operator CLI (`python/src/mssh/admin/`)
- **debug_sshd** — debug-only AsyncSSH server (`python/src/mssh/debug_sshd/`)
  — not a production tier
- **shim** (library) — shared "call the CA" code (`python/src/mssh/shim/`)

Avoid the word "wrapper" — historical, ambiguous. Use "gateway"
for msshd. The previous "Tier 1 / 2 / 3" framing is also retired;
mssh has a single production server (msshd) plus the optional AKC
shim (`python/src/mssh/akc_shim/`) for unmodified-OpenSSH compat.

## Three operating modes

msshd selects between three modes via `wrapper.yaml`:

- `fallback` — pure TCP proxy to operator's existing sshd. No CA
  call. Implemented.
- `gated` — mTLS + CA approval, but forward to operator's existing
  sshd for auth. **Deferred** (see design/future-ideas.md).
- `enforce` — mTLS + CA call + ephemeral OpenSSH cert minted +
  hermetic inner sshd. Implemented.

Operator adoption journey: fallback → gated → enforce, reversible.

## Key design decisions

- Authorization cert format: X.509 with custom extensions (settled, do not change)
- Identity proof: bare SSH public key + OpenSSH cert; X.509 client
  cert from a separate user-facing CA
- Server identity: via mTLS cert (subject), not hostname
- Raw blob forwarding: msshd does NOT parse identity certs; the CA
  does all parsing
- Two distinct cert hierarchies, intentionally separate:
  - **CA signing key** — authz certs + server/admin mTLS certs
  - **User-facing CA** — mssh client mTLS certs + msshd's TLS server cert
- **msshd's local user-CA** — third, internal key, signs ephemeral
  OpenSSH user certs for the hermetic inner sshd. Never leaves the
  msshd host.
- No password auth, ever
- Fail-closed: if CA unreachable, deny (unless emergency cert)
- Implementation language: Python today. Go on Alpine is harder
  than expected (musl support); Rust is the cleanest cross-distro
  cross-language option. See design/future-ideas.md § distro packaging.

### Amendment 2026-05-18 — authz cache + CA-bypass cert

msshd now has an **authz cache** (`python/src/mssh/msshd/authz_cache.py`).
On every connection msshd checks the cache first; on hit, no CA call.
On miss, msshd calls the CA, stores the grant, uses it. On CA deny,
the cache entry is invalidated regardless of source (CA is the
oracle when reachable). On CA unreachable + cache miss, deny.

Entries are tagged `'ca'` or `'bypass'` for diagnostic visibility.
Persistence: on-disk JSON at `<state_dir>/authz_cache.json`, mode
0600, atomic writes. Cache survives msshd restart so operators
fixing things across reboots don't have to re-inject.

The **CA-bypass cert** mechanism (`OID_CA_BYPASS` = 1.3.6.1.4.1.55555.1.8)
lets an operator pre-mint an authz cert offline (while CA is up) and
present it later — when the CA is down — to populate the msshd's
authz cache directly. The cert is a normal authz cert with one extra
critical marker extension. Presented via the mssh client's
`--inject-bypass-cert` flag, which sends the cert in an extra
`bypass_cert` field of the v1 JSON header. msshd validates (chain,
marker, validity, mTLS-principal-match), injects into the cache,
acks, closes.

Two-step operator UX:
```
mssh --inject-bypass-cert alice-bypass.crt srv-acct   # injects
mssh srv-acct -- whoami                                # cache hit, works
```

The inconvenience is the point: bypass certs live in a safe, not on
disk. Minting requires superuser on the CA:
`mssh-admin bypass-cert mint alice --pubkey ~/.ssh/alice.pub
--valid-days 90 --out alice-bypass.crt`. Operator stores the result
offline.

See [design/notes-bypass-cache.md](design/notes-bypass-cache.md) for
the design rationale (decisions on cache key, TTL, invalidation
policy, source tags) and the resolutions Kurt agreed to.

This supersedes the earlier "emergency template" scaffolding
(emergency.py + sshd_config.emergency.template), which has been
ripped. The old emergency_cert field in wrapper.yaml is preserved
for the akc_shim legacy path only.

**Known open design hole, unrelated to bypass:** the authz cache has
no eviction-on-capacity policy. Acknowledged as a TODO. With
unbounded entries + long-lived bypass certs, the cache could grow
in pathological cases. Real-world sizes are small (one entry per
active principal) so the bound matters less than the semantics.

### Amendment 2026-05-18 (b) — sequence-based CRL

The cache invalidation story (above) handled only one direction:
on a live CA deny, drop the cached entry for that principal. It
didn't propagate revocations to caches that *aren't* being touched
by a fresh connection at the moment. That gap is now closed by a
sequence-based CRL.

Pieces:

- **CA**: append-only CRL log
  ([`python/src/mssh/ca/crl.py`](python/src/mssh/ca/crl.py)). Each
  entry is `{seq, revoked_at, serials, revoked_by, reason}`.
  Persisted at `<enrollment_dir>/crl.jsonl`. Superuser-only
  endpoint `POST /v1/admin/cert/revoke` appends. Operator + auditor
  can `GET /v1/admin/crl`. msshd fetches via `GET /v1/crl`.
- **Authorize protocol**: response carries `current_crl_seq: M`.
  Request body carries msshd's `last_crl_seq: N` for audit visibility.
- **msshd**: `crl_sync.py` reacts to `M > N` by background-fetching
  `(N, M]` in `crl_fetch_limit` pages, applying each entry's serials
  via `authz_cache.invalidate_by_serial(serial)`, persisting
  `last_crl_seq` as it advances.
- **Strict-mode gate**: `ca.crl_strict_threshold` (default 50). When
  `(known_ca_seq - last_applied) > threshold`, msshd refuses cache
  hits and forces live CA calls until catch-up completes. 0 disables.

Operator UX:

```sh
mssh-admin cert revoke deadbeef --reason 'key rotation'
mssh-admin crl list --after 100 --limit 20
```

The CRL applies regardless of source tag: a revoked bypass cert is
dropped exactly like a revoked CA-grant cert. Same policy for any
cert; CA is the oracle when reachable.

Eviction-on-capacity is still open (see prior amendment). Sequence-
based CRL bounds growth-by-revocation, not growth-by-mint. A
deployment minting many long-lived bypass certs that don't get
naturally evicted by their own `not_after` could in principle still
grow without bound. Tracked separately.

See [design/notes-bypass-cache.md](design/notes-bypass-cache.md)
"Amendment 2026-05-18 (b)" for the design rationale + edge cases
(CA seq reset, multi-msshd coordination).

## Docs

### Operator-facing

- `docs/overview.md` — what mssh is, when it fits
- `docs/operations.md` — install, adopt, run, troubleshoot

### Design

- `design/architecture.md` — components, modes, hermetic inner sshd
- `design/api.md` — REST + admin API contract + enrollment YAML
- `design/security.md` — trust model + threat analysis
- `design/future-ideas.md` — deferred features (read this before
  proposing new ones — many ideas are captured here already)

### Historical (don't write new content here; reference only)

- `archive/design/` — original 12 design docs that pre-date the
  clean-room rewrite. Use older naming ("mssh", "Tier 1/2/3",
  "Phase 1/2", "PoC"). Frequently more detailed than the new docs.
- `archive/docs/` — original operator docs.

## Project structure

Top-level dir = language. Within each language, full client + server + CA.
Operator-facing artifacts (configs, scripts, systemd, OpenSSH patches)
live at the repo root and are language-neutral.

```
mssh/
├── CLAUDE.md               # this file
├── README.md
├── INSTALLATION.md
├── design/                 # clean-room design docs
├── docs/                   # operator-facing docs
├── archive/                # historical design + docs (internal reference)
├── python/                 # current Python implementation
│   ├── setup.py            # legacy-compat shim for editable install
│   ├── pytest.ini
│   ├── requirements.txt
│   ├── src/mssh/          # the mssh Python package
│   │   ├── ca/             # CA server (Flask + mTLS)
│   │   ├── admin/          # mssh-admin CLI
│   │   ├── shim/           # shared "call the CA" library
│   │   ├── debug_sshd/     # debug-only AsyncSSH server (not a tier)
│   │   ├── akc_shim/       # OpenSSH AKC entry point (Tier-3 compat)
│   │   ├── msshd/          # the gateway daemon
│   │   └── client.py       # the mssh client (single module)
│   └── tests/
├── go/                     # future — Go port (placeholder)
├── c/                      # future — C for Alpine (placeholder)
├── openssh-patches/        # upstream-targeted OpenSSH patches (AKC support)
├── config/                 # example operator configs
├── scripts/                # operator scripts
└── systemd/                # service unit files
```

## Dependencies

```
asyncssh>=2.14
cryptography>=41.0
flask>=3.0
pyyaml>=6.0
click>=8.0
requests>=2.31
```

## Style

- Author: Kurt Godwin (github.com/kurt-cb)
- Keep code simple and readable
- Comments explain why, not what
- Error messages should be specific and actionable
- All network errors fail-closed (deny access)
- Avoid the word "wrapper" — use "gateway" for msshd
- Avoid Phase / Tier / PoC framing in new docs — those were
  intermediate; reference architecture.md for the canonical view
