# mssh — reference CA + messaging schema

This document is the normative specification for the mssh CA. It is
intended to be sufficient for a clean-room re-implementation (Go,
Rust, C, etc.) without reading the reference Python code. Every wire
field is marked **required** or **optional** with its default. Every
storage shape is declared. Every endpoint is documented with status
codes and the conditions that produce each.

If you find the Python implementation diverges from this spec, file
a bug — the spec is canonical.

For supporting context, see:

  - [architecture.md](architecture.md) — components and the
    operational model.
  - [api.md](api.md) — the same wire contracts in narrative form
    (this doc is the strict / normative version).
  - [security.md](security.md) — threat model and what each control
    stops.

---

## 1. Responsibilities

A conforming CA implements four functions:

| Function | Wire surface | Section |
|---|---|---|
| **Authorize** | `POST /v1/authorize` (mTLS, server-initiated from msshd) | [§3](#3-authorize-api) |
| **Admin** | `/v1/admin/*` (mTLS, RBAC-checked) | [§4](#4-admin-api) |
| **Audit** | `/v1/admin/audit` (admin-API subset) plus on-disk JSON Lines log | [§7](#7-audit-log) |
| **Render** | called internally by Authorize; produces the per-session inner sshd config | [§5](#5-template-system) |

The CA is **the** trust authority for the authorization domain. The
CA signing key never leaves the CA host. The CA does not store
long-lived secrets for clients — all material it signs is
short-lived (minute-scale).

---

## 2. Wire protocol versioning

The CA and its clients (`msshd`, `mssh-admin`) negotiate a protocol
version on every authorize request. The current version is **1.1**.

### 2.1 Version values

  - **`1.0`** — baseline. Authorize request does **not** carry
    `protocol_version`, `inner_sshd_kind`, `inner_sshd_version`, or
    `msshd_version`. Response does **not** carry `protocol_version`
    or `inner_sshd_config`.
  - **`1.1`** — adds the four new request fields above and the
    `inner_sshd_config` response field. CA still serves `1.0`
    clients (omits the new response fields when the client doesn't
    speak `1.1+`).

### 2.2 Compatibility rules

  - **Missing `protocol_version` on request** is interpreted as
    `1.0`.
  - **CA always emits `protocol_version` in the response** at its
    own version (e.g. always `"1.1"` for a CA on 1.1), so clients
    learn what the CA speaks even when they're sending pre-1.1
    requests.
  - **CA never returns fields the client's version doesn't
    understand.** For 1.0 clients, omit `inner_sshd_config`. This
    is forward-compat for future client minor versions: CA at 1.2
    talking to msshd at 1.1 omits any 1.2-only fields.
  - **Client received unknown fields**: ignore them (forward-compat).
  - **Client received fewer fields than expected** (e.g. msshd at
    1.1 talks to a CA at 1.0): per-field handling — the absence of
    `inner_sshd_config` from a CA response means "fall back to the
    local emergency-template path" if msshd is in per-connection
    mode, or "use long-lived inner sshd as today" otherwise.

### 2.3 Version policy

  - The CA's major version is its protocol's major. A `2.x` CA
    refuses `1.x` clients with `403 protocol_too_old`.
  - Minor versions are additive: `1.2` clients work with a `1.1`
    CA (missing fields are tolerated).
  - The CA's reference Python implementation exposes its version
    via `mssh.PROTOCOL_VERSION`.

---

## 3. Authorize API

### 3.1 Endpoint

```
POST /v1/authorize
Content-Type: application/json
mTLS client cert: server enrollment cert (CN matches an enrolled server's mtls_subject)
```

### 3.2 Request body

| Field | Type | Required? | Default | Description |
|---|---|---|---|---|
| `protocol_version` | string | optional | `"1.0"` | Per [§2](#2-wire-protocol-versioning). |
| `identity` | object | **required** | — | The end-user identity to authorize. See §3.2.1. |
| `connection` | object | **required** | — | Source IP + port + timestamp. See §3.2.2. |
| `requested_channels` | list of strings | optional | `null` | Per [policy schema](#62-policy-schema). If absent, no per-channel intent expressed (CA decides). |
| `inner_sshd_kind` | string | optional | `"openssh"` | Which template variant to render. v1: only `"openssh"` is accepted. |
| `inner_sshd_version` | string | optional | `""` | The version string of the calling host's inner sshd binary (e.g. `"9.6p1"`). Used by the CA for directive-compatibility checks; logged in audit. |
| `msshd_version` | string | optional | `""` | The calling msshd's package version. Logged in audit; surfaced by `mssh-admin status`. |

#### 3.2.1 `identity` sub-object

| Field | Type | Required? | Description |
|---|---|---|---|
| `type` | string | **required** | One of `"pubkey"` or `"openssh-cert"`. |
| `data` | base64 string | **required** | Raw SSH wire-format bytes (pubkey blob, or OpenSSH cert serialization). |

#### 3.2.2 `connection` sub-object

| Field | Type | Required? | Description |
|---|---|---|---|
| `source_ip` | string | **required** | The end client's IP address (NOT msshd's). Used for source-CIDR policy. |
| `source_port` | integer | **required** | TCP source port; recorded in audit. |
| `timestamp` | RFC 3339 string | **required** | When msshd received the connection. Used for clock-skew rejection. |

### 3.3 Response body

The HTTP status is one of `200` (granted), `401` (server identity not enrolled), `403` (denied), or `500` (CA-internal error).

#### 3.3.1 On grant (`200`)

| Field | Type | Required? | Description |
|---|---|---|---|
| `status` | string | **required** | Literal `"granted"`. |
| `cert` | base64 string | **required** | DER-encoded short-lived X.509 authorization cert. |
| `serial` | hex string | **required** | The cert's serial number; matches `cert`. |
| `not_after` | RFC 3339 string | **required** | The cert's `notAfter`; matches `cert`. |
| `protocol_version` | string | **required** | The CA's protocol version. |
| `policy_summary` | object | **required** | Summary of the policy that matched. See §3.3.3. |
| `inner_sshd_config` | string | optional | Rendered per-session sshd_config. Present iff the request's `protocol_version` ≥ `"1.1"`. `{LOCAL_*}` markers are left unsubstituted (msshd's job); `{FROMCA_*}` markers are fully substituted by the CA. |

#### 3.3.2 On deny (`403`)

| Field | Type | Required? | Description |
|---|---|---|---|
| `status` | string | **required** | Literal `"denied"`. |
| `reason` | string | **required** | Machine-readable deny reason; one of the values listed in §3.3.4. |
| `detail` | string | optional | Human-readable amplification; never exposes internal state beyond what the reason implies. |

#### 3.3.3 `policy_summary` sub-object

| Field | Type | Required? | Description |
|---|---|---|---|
| `channels` | list of strings | **required** | Channels the user is authorized for. |
| `source_bound` | boolean | **required** | `true` if cert pins to `source_ip`. Always `true` in current implementation. |
| `server_bind` | string | **required** | The server's canonical name as enrolled. |
| `force_command` | string or null | optional | If set, the inner sshd will enforce this `ForceCommand`. |
| `environment` | object or null | optional | Env vars the CA wants set in the session. |

#### 3.3.4 Deny reasons

| Reason | Status | Trigger |
|---|---|---|
| `unknown_server` | 401 | mTLS subject doesn't match any enrolled server. |
| `bad_request` | 500 | Required field missing or wrong type. |
| `clock_drift` | 403 | `connection.timestamp` differs from CA's clock by more than the configured drift (default 60 seconds). |
| `invalid_identity_cert` | 403 | OpenSSH cert identity has unknown signer / expired / not-yet-valid. |
| `unknown_identity` | 403 | Identity fingerprint not enrolled at the CA. |
| `policy_mismatch` | 403 | No policy in the enrollment matches (server, channels, source CIDR, time window). |
| `source_denied` | 403 | `source_ip` outside every matching policy's `source_cidrs`. |
| `time_window` | 403 | Request outside every matching policy's `time_window`. |

#### 3.3.5 Audit

Every authorize call — granted, denied, or error — produces one audit entry per [§7](#7-audit-log). The entry includes the client version info from the request even if the request was denied.

### 3.4 Server identity

The CA identifies the calling msshd by the mTLS client cert subject. There is no `server` field in the authz body; the CA looks up the enrolled server by `mtls_subject == request_cert.subject`. A request with a cert whose subject isn't enrolled yields `401 unknown_server`.

---

## 4. Admin API

All admin endpoints share the `/v1/admin/` prefix and require:

  - mTLS client cert whose subject (`CN=…`) matches an enrolled admin's `mtls_subject`.
  - The admin's `role` permits the requested action (see §4.1).

Calls that fail authentication return `401`. Calls that authenticate but lack permission return `403 forbidden`.

### 4.1 Roles + permissions

Four roles. Permissions for each (action key in **bold**):

| Role | Permissions |
|---|---|
| **`superuser`** | All actions. |
| **`server-admin`** | **server.add**, **server.remove**, **server.groups**, **server.list**, **user.list**, **audit.read**, **template.set**, **template.unset**, **template.list**, **template.show**. |
| **`user-admin`** | **user.add**, **user.remove**, **user.key.add**, **user.key.remove**, **user.list**, **server.list**, **policy.add**, **policy.remove**, **audit.read**, **template.list**, **template.show**. |
| **`auditor`** | **user.list**, **server.list**, **admin.list**, **audit.read**, **template.list**, **template.show**. |

Note: `template.set`/`unset` is server-admin-scoped (not user-admin) because templates control inner-sshd behavior per server. `template.list`/`show` is broadly readable — user-admins and auditors need it to verify policy ↔ template alignment.

### 4.2 Endpoints (summary)

| Method | Path | Action | Body |
|---|---|---|---|
| POST | `/v1/admin/server/add` | `server.add` | `{name, groups?}` |
| DELETE | `/v1/admin/server/<name>` | `server.remove` | — |
| PUT | `/v1/admin/server/<name>/groups` | `server.groups` | `{groups: [...]}` |
| GET | `/v1/admin/server/list` | `server.list` | — (querystring: `group?`, `name?`) |
| POST | `/v1/admin/user/add` | `user.add` | `{username}` |
| DELETE | `/v1/admin/user/<username>` | `user.remove` | — |
| POST | `/v1/admin/user/<username>/key` | `user.key.add` | `{type, data: base64, key_type?, key_id?, principals?}` |
| DELETE | `/v1/admin/user/<username>/key/<fingerprint>` | `user.key.remove` | — |
| GET | `/v1/admin/user/list` | `user.list` | — (querystring: `username?`, `fingerprint?`) |
| POST | `/v1/admin/policy/add` | `policy.add` | `{username, policy: <PolicyInput>}` |
| DELETE | `/v1/admin/policy/<policy_id>` | `policy.remove` | — |
| POST | `/v1/admin/admin/add` | `admin.add` | `{name, role}` |
| DELETE | `/v1/admin/admin/<name>` | `admin.remove` | — |
| GET | `/v1/admin/admin/list` | `admin.list` | — |
| GET | `/v1/admin/audit` | `audit.read` | — (querystring: `type, since, until, username, server, decision, admin, limit, offset`) |
| POST | `/v1/admin/template/set` | `template.set` | `{scope, scope_name?, kind, content}` |
| POST | `/v1/admin/template/unset` | `template.unset` | `{scope, scope_name?, kind}` |
| GET | `/v1/admin/template/list` | `template.list` | — |
| GET | `/v1/admin/template/effective/<server>` | `template.show` | — (querystring: `kind?`) |

### 4.3 Template-admin contract

  - `scope` is one of `"default"`, `"group"`, `"server"`. `"default"`
    means the fleet-default template; `"group"` and `"server"`
    require `scope_name` (a group name or a server canonical name).
  - `kind` defaults to `"openssh"` (the only kind accepted in v1).
    Other values yield `400 bad_request`.
  - `content` (`template.set` only) is the raw template text. The CA
    validates it against the marker schema before saving; an unknown
    `{FROMCA_*}` marker yields `400 invalid_template`.
  - `template.unset` is **idempotent** — unsetting a non-existent
    override returns `200 ok`.
  - `template.effective/<server>` walks the precedence chain
    (per-server > per-server-group > fleet-default > built-in) and
    returns the chosen template plus `source` (one of `"server"`,
    `"group"`, `"default"`, `"builtin"`) and `source_detail` (the
    specific name for server/group, else `null`).

---

## 5. Template system

### 5.1 Storage

Templates are scoped by `(scope, scope_name?, kind)`:

| Scope | Cardinality | Key |
|---|---|---|
| `default` | 0 or 1 per `kind` | `kind` |
| `group` | 0 or 1 per `(group_name, kind)` | `(scope_name, kind)` |
| `server` | 0 or 1 per `(server_name, kind)` | `(scope_name, kind)` |

Implementations persist these alongside the enrollment data; the reference Python implementation stores them under a top-level `templates:` key in `enrollment.yaml` ([§6.4](#64-enrollment-yaml-shape)).

### 5.2 Resolution

For a render at session time, the CA walks:

1. **Per-server**: `templates_servers[server_name][kind]`. If set, use it.
2. **Per-group**: walk `enrollment.servers[server_name].groups` in declared order; for each, check `templates_groups[group][kind]`. First hit wins.
3. **Fleet-default**: `templates_default[kind]`.
4. **Built-in**: the CA's shipped default for this `kind` (always present for `"openssh"`).

If no built-in exists for the requested `kind` (e.g. `"dropbear"` in v1), the CA returns an error and the session is denied.

### 5.3 Marker grammar

The template body uses two namespaces of named substitution markers:

  - **`{LOCAL_*}`** — substituted by **msshd** at session-establish time. The CA does **not** substitute these; they pass through verbatim in the rendered output. msshd has the necessary local values (port, host-key path, etc.).
  - **`{FROMCA_*}`** — substituted by **the CA** from the policy evaluation result for this session.

Each marker can have an optional **default**: `{NAME:default-value}`. If the renderer can't supply `NAME`, it uses the default; if there's no default, the render fails.

Marker name production: `[A-Z][A-Z0-9_]*`.

#### 5.3.1 Known `LOCAL_*` markers (v1)

| Marker | Substituted with |
|---|---|
| `{LOCAL_PORT}` | TCP port the inner sshd will bind. |
| `{LOCAL_HOST_KEY}` | Filesystem path of the inner sshd's host key. |
| `{LOCAL_USER_CA_PUBKEY}` | Filesystem path of msshd's local user-CA pubkey. |
| `{LOCAL_BANNER_FILE}` | Filesystem path of the pre-auth banner file. |

#### 5.3.2 Known `FROMCA_*` markers (v1)

Each has a value **shape** the renderer validates against; values failing the shape yield `inner_sshd_config_error` ([§3.3.1](#331-on-grant-200)) — the cert is still granted, but no rendered config is returned.

| Marker | Shape | sshd_config directive |
|---|---|---|
| `{FROMCA_FORCE_COMMAND}` | string | `ForceCommand` |
| `{FROMCA_ALLOW_TCP_FORWARDING}` | yes/no | `AllowTcpForwarding` |
| `{FROMCA_X11_FORWARDING}` | yes/no | `X11Forwarding` |
| `{FROMCA_ALLOW_AGENT_FORWARDING}` | yes/no | `AllowAgentForwarding` |
| `{FROMCA_PERMIT_USER_ENVIRONMENT}` | yes/no | `PermitUserEnvironment` |
| `{FROMCA_SET_ENV}` | multiline | Multiple `SetEnv KEY=value` lines |
| `{FROMCA_CLIENT_ALIVE_INTERVAL}` | integer | `ClientAliveInterval` |
| `{FROMCA_CLIENT_ALIVE_COUNT_MAX}` | integer | `ClientAliveCountMax` |

### 5.4 Shape validation (injection defense)

  - **No `\r` in any value, ever.** Always rejected.
  - **`\n` allowed only in `multiline` values.** All other shapes
    reject embedded newlines so a single-line directive can't be
    appended to.
  - **`yes/no` values must be literally `"yes"` or `"no"`.**
  - **`integer` values must parse as `int(value)`.**
  - **`multiline` lines that aren't blank or comment must begin
    with an alphanumeric directive name** (`[A-Za-z0-9_-]+`).

A value failing validation does NOT deny the session — the CA returns the cert without `inner_sshd_config` and audits the error. msshd will surface the failure at its own `sshd -t` check or use the emergency template.

### 5.5 Policy → `{FROMCA_*}` mapping

The CA computes `{FROMCA_*}` values from the result of policy evaluation. The reference Python implementation centralizes this in `fromca_values_from_evaluation()`:

| Policy field | `{FROMCA_*}` |
|---|---|
| `force_command` | `FROMCA_FORCE_COMMAND` (string; `"none"` if policy omits) |
| `channels` contains `"tcp-forwarding"` | `FROMCA_ALLOW_TCP_FORWARDING` = `"yes"` else `"no"` |
| `channels` contains `"x11"` | `FROMCA_X11_FORWARDING` = `"yes"` else `"no"` |
| `channels` contains `"agent-forwarding"` | `FROMCA_ALLOW_AGENT_FORWARDING` = `"yes"` else `"no"` |
| `environment` non-empty | `FROMCA_PERMIT_USER_ENVIRONMENT` = `"yes"` else `"no"` |
| `environment` non-empty | `FROMCA_SET_ENV` = each pair as `SetEnv KEY=value`, sorted by key, newline-joined |

A re-implementation MUST produce the same mapping. The presence/absence of a key in the substitution dict, combined with the marker's default value, decides whether the directive appears in the rendered config.

### 5.6 Render contract

```
input:
  template      string
  fromca_values dict[str, str]   (CA-side values; subset of §5.3.2)
  local_values  dict[str, str]   (always empty when CA-side rendering — msshd
                                  fills these later)
  leave_unsubstituted set[str]   ({'LOCAL'} for CA-side renders)

output:
  rendered string with every marker either substituted or in
  leave_unsubstituted's namespace.

errors:
  - unknown marker (not in known LOCAL_* or FROMCA_* tables)
  - required marker missing value (no default + no supplied value)
  - shape violation per §5.4
```

CA-side render leaves `{LOCAL_*}` markers in place; msshd does the second pass before spawning sshd.

---

## 6. Enrollment storage

The reference implementation persists enrollment data to a single YAML file (`enrollment.yaml`) with the structure below. **A clean-room implementation MAY use any storage backend** as long as it preserves the semantics — atomic writes, per-key uniqueness, the listed dataclass shapes.

### 6.1 Server schema

| Field | Type | Required? | Description |
|---|---|---|---|
| `name` | string | **required** | Canonical name; key. |
| `mtls_subject` | string | **required** | The mTLS cert subject (`CN=...`) the CA matches on `/v1/authorize` requests. Unique. |
| `groups` | list of strings | optional, default `[]` | Group memberships for policy matching. |
| `enrolled_at` | RFC 3339 string | optional, set on creation | Audit. |
| `enrolled_by` | string | optional, set on creation | Admin name who created. |

### 6.2 Policy schema

Policies are owned by users (a user has 0..N policies). Each:

| Field | Type | Required? | Description |
|---|---|---|---|
| `id` | string | **required** | Generated by the CA on `policy.add`. Format `pol-<n>`. |
| `servers` | list of strings | optional, default `[]` | Server canonical names this policy authorizes. |
| `server_groups` | list of strings | optional, default `[]` | Server groups this policy authorizes. |
| `channels` | list of strings | optional, default `[]` | SSH channel names the policy grants. `"session"` required for interactive shell / exec. Other v1 values: `"tcp-forwarding"`, `"x11"`, `"agent-forwarding"`. |
| `source_cidrs` | list of strings | optional, default `[]` | IPv4 / IPv6 CIDRs. Empty = any source. |
| `time_window` | object or null | optional, default `null` | `{days, hours: {start, end}, timezone}`. Omit / null = always. |
| `max_cert_validity_seconds` | integer | optional, default `3600` | Cap on the issued cert's lifetime. The CA picks `min(this, policy.cert_validity_default)`. |
| `environment` | object | optional, default `{}` | Key/value env vars to apply in the session. |
| `force_command` | string or null | optional, default `null` | Forces a command instead of the user's request. |
| `created_at` | RFC 3339 string | optional, set on creation | Audit. |
| `created_by` | string | optional, set on creation | Admin name. |

When a user has multiple policies, the matching ones (`server in policy.servers OR groups overlap policy.server_groups`) are unioned: channels and environment merge; force_command picks the first non-null (deterministic order = enrollment order); `max_cert_validity_seconds` is the **min** across matches.

### 6.3 User + KeyBinding schema

User:

| Field | Type | Required? | Description |
|---|---|---|---|
| `username` | string | **required** | Key. |
| `keys` | list of KeyBinding | optional, default `[]` | Public keys / certs this user owns. |
| `policies` | list of Policy | optional, default `[]` | Policies attached. |
| `enrolled_at`, `enrolled_by` | string | optional | Audit. |

KeyBinding:

| Field | Type | Required? | Description |
|---|---|---|---|
| `fingerprint` | string | **required** | SHA-256 of the SSH wire blob, lowercase hex (`sha256:...`). |
| `type` | string | **required** | `"pubkey"` or `"openssh-cert"`. |
| `key_type` | string | **required** | `"ssh-ed25519"`, etc. |
| `key_id` | string | optional (cert only), default `""` | OpenSSH cert key_id; used for cert-by-key_id lookup. |
| `principals` | list of strings | optional (cert only), default `[]` | Principals in the cert. |
| `added_at`, `added_by` | string | optional | Audit. |

### 6.4 Enrollment YAML shape

Reference implementation persistence:

```yaml
servers:
  <server_name>:                    # required: at least the key
    mtls_subject: <string>          # required
    groups: [<string>, ...]         # optional, default []
    enrolled_at: <iso8601>          # optional
    enrolled_by: <string>           # optional

admins:
  <admin_name>:                     # required: at least the key
    role: <string>                  # required; in {superuser, server-admin, user-admin, auditor}
    mtls_subject: <string>          # required
    enrolled_at: <iso8601>          # optional
    enrolled_by: <string>           # optional

users:
  <username>:                       # required: at least the key
    keys:                           # optional, default []
      - fingerprint: <string>       # required
        type: <string>              # required
        key_type: <string>          # required
        key_id: <string>            # optional, default ""
        principals: [<string>, ...] # optional, default []
        added_at: <iso8601>         # optional
        added_by: <string>          # optional
    policies:                       # optional, default []
      - id: <string>                # required, generated by CA
        servers: [<string>, ...]    # optional, default []
        server_groups: [<string>, ...]  # optional, default []
        channels: [<string>, ...]   # optional, default []
        source_cidrs: [<string>, ...]   # optional, default []
        time_window: <object|null>  # optional, default null
        max_cert_validity_seconds: <int>  # optional, default 3600
        environment: <object>       # optional, default {}
        force_command: <string|null>      # optional, default null
        created_at: <iso8601>       # optional
        created_by: <string>        # optional
    enrolled_at: <iso8601>          # optional
    enrolled_by: <string>           # optional

templates:                          # optional, absent in pre-1.1 enrollments
  default:                          # optional
    <kind>: <content>               # e.g. openssh: "Port {LOCAL_PORT}..."
  groups:                           # optional
    <group_name>:
      <kind>: <content>
  servers:                          # optional
    <server_name>:
      <kind>: <content>
```

Any optional key may be omitted; absence is equivalent to its default. An empty top-level section (e.g. `servers: {}`) is also acceptable.

Atomic writes: the CA writes to a `.tmp` sibling file and `rename(2)`s into place. Concurrent readers never see a partial file.

---

## 7. Audit log

The CA writes one JSON object per line (JSON Lines) to a single append-only log. Every authorize call, every admin write, every authentication failure produces one entry.

### 7.1 Entry shape

Common fields (all entries):

| Field | Type | Required? | Description |
|---|---|---|---|
| `timestamp` | RFC 3339 | **required** | UTC. |
| `type` | string | **required** | `"authorization"`, `"admin"`, or future types. |
| `decision` | string | optional | `"granted"`, `"denied"`, `"error"` for authorization entries; `"ok"`, `"forbidden"`, `"error"` for admin entries. |

#### 7.1.1 Authorization entry

In addition to the common fields:

| Field | Type | Required? | Description |
|---|---|---|---|
| `serial` | hex | **required if granted** | Issued cert serial. |
| `identity` | object | **required** | `{type, fingerprint, username?}`. |
| `server` | object | optional | `{canonical_name, groups, mtls_subject}`. Present iff the server was identified. |
| `connection` | object | optional | `{source_ip, source_port}`. Present for entries past parse. |
| `cert_validity` | object | optional (granted only) | `{not_before, not_after}`. |
| `policy_applied` | object | optional (granted only) | `{policy_ids, channels, source_bound, force_command}`. |
| `client` | object | optional (protocol ≥ 1.1) | `{protocol_version, msshd_version, inner_sshd_kind, inner_sshd_version}`. |
| `reason` | string | **required if denied** | One of §3.3.4. |
| `detail` | string | optional | Amplification. |
| `inner_sshd_config_error` | string | optional (granted only) | Present iff template render failed. |

#### 7.1.2 Admin entry

| Field | Type | Required? | Description |
|---|---|---|---|
| `admin` | object | **required** | `{name, role, mtls_subject}`. |
| `action` | string | **required** | One of the action keys in [§4.1](#41-roles--permissions). |
| `result` | string | **required** | `"ok"`, `"forbidden"`, `"not_found"`, `"conflict"`, `"bad_request"`. |
| Additional action-specific fields | varies | varies | E.g. `template.set` includes `{scope, scope_name, kind, content_bytes}`. |

### 7.2 Retention

The CA implementation does **not** rotate or expire the audit log. Operators are expected to rotate externally (e.g. `logrotate`, syslog forwarding). The CA never modifies a written entry.

---

## 8. Cryptography

### 8.1 Signing key

  - **Algorithm**: Ed25519 (mandatory) or NIST P-256 (acceptable).
  - **Storage**: PEM-encoded private key, mode 0600. PKCS#8 preferred for compatibility.
  - **Rotation**: out of scope for v1; the operator runs a fresh `mssh-admin init` into a new directory and re-enrolls.

### 8.2 Authorization cert

X.509 v3, signed by the CA signing key. Subject CN = the enrolled username. Custom extensions (OIDs under the mssh OID arc, see [api.md](api.md)) carry:

  - `source_bind` — source IP this cert is valid from.
  - `server_bind` — server canonical name this cert authorizes.
  - `channel_policy` — encoded channel list.
  - `force_command` — string (optional).
  - `environment` — key/value pairs (optional).
  - `max_session` — integer (optional).

### 8.3 TLS material

The CA acts as a CA for two distinct hierarchies (see [architecture.md § trust model](architecture.md#trust-model)). The reference implementation uses one signing key for both, but a re-implementation MAY split them.

### 8.4 Clock policy

The CA validates `connection.timestamp` against its own clock; differences greater than `timestamp_drift_seconds` (default 60) yield `clock_drift` denials. The CA uses the host's UTC clock; no `/v1/clock` endpoint exists in v1 (see [future-ideas.md §clock-authority](future-ideas.md)).

---

## 9. Conformance checklist

A re-implementation claims v1.1 conformance if it:

  1. Accepts every required request field per [§3.2](#32-request-body); rejects with the documented status for each missing/invalid field.
  2. Returns the response shape per [§3.3](#33-response-body), including `protocol_version` on every response and `inner_sshd_config` on 1.1 grants.
  3. Implements the `{FROMCA_*}` markers in [§5.3.2](#532-known-fromca_-markers-v1) with the shape validation in [§5.4](#54-shape-validation-injection-defense).
  4. Honors the template precedence in [§5.2](#52-resolution).
  5. Implements every admin endpoint in [§4.2](#42-endpoints-summary) with the RBAC checks in [§4.1](#41-roles--permissions).
  6. Writes audit entries with the schema in [§7](#7-audit-log).
  7. Persists enrollment + templates with semantics equivalent to [§6.4](#64-enrollment-yaml-shape).
