# mssh — TESTS-TODO

Companion to [design/mssh_design_v1.md](design/mssh_design_v1.md) §17.8.
Coverage gap list — every § that does not yet have at least one test
declaring `Tests: §X.Y.Z`. Populated by the §0.5 verification pass.

**Refresh procedure**: run the verification pass; for each § in §1–§16
with no test pointing at it, append a row here.

Columns: `ref`, `what-needs-testing`, `priority` (P1–P9),
`suggested-test-file`, `notes`.

## v1 ship-gate test gaps — from 2026-05-22 verification pass

Populated from §17.7 → §17.8. Each row's `ref` ties back to a § in
the design. Priority follows the corresponding row in FEATURES-TODO.

### §s implemented but with no dedicated test surface

| ref      | what-needs-testing                                | priority | suggested-test-file                       | notes |
|----------|---------------------------------------------------|----------|-------------------------------------------|-------|
| §3.3     | mssh-admin↔CA wire contract                       | P3       | `python/tests/test_admin_wire_contract.py` | currently implicit in admin handler tests; add explicit contract assertions |
| §6.3.1   | mssh client config resolution                     | P3       | `python/tests/test_client_config_resolution.py` | env-var precedence, ~/.mssh/ layout, error paths |
| §7.3.2   | mssh-admin CLI 2FA polling loop                   | P3       | `python/tests/test_admin_2fa_cli_loop.py`  | CA-side covered by test_passkey_admin_flow; CLI loop needs its own unit test |
| §7.3.5   | mssh-admin output formatters                      | P4       | `python/tests/test_admin_formatters.py`    | human/json/quiet output shapes |
| §8.3.6   | mssh-passkey front-end variants                   | P4       | `python/tests/test_passkey_front_ends.py`  | apache vs dev modes |
| §10.3    | debug_sshd unit-level behavior                    | P4       | `python/tests/test_debug_sshd.py`          | currently covered only by adhoc lab |
| §14.3.2  | ca-config.yaml schema parsing                     | P3       | `python/tests/test_ca_config.py`           | every field, including §13.9.7 default-deny |
| §14.3.3  | mssh client config schema                         | P3       | `python/tests/test_client_config_schema.py` | overlap with §6.3.1 above |
| §14.3.4  | mssh-passkey config schema                        | P4       | `python/tests/test_passkey_config.py`      | including §13.9.7 default-deny |
| §14.3.5  | mssh-admin-web config schema                      | P4       | `python/tests/test_admin_web_config.py`    | |

### 3rd-party integration contract tests

| ref      | what-needs-testing                                | priority | suggested-test-file                       | notes |
|----------|---------------------------------------------------|----------|-------------------------------------------|-------|
| §15.4    | replaceable broker contract                       | P3       | `python/tests/test_passkey_broker_contract.py` | contract test against §3.6 wire (alt-broker substitution) |
| §15.7    | operator-sshd reuse contract                      | P2       | `python/tests/lxc/test_msshd_gated.py`     | depends on §5.3.3 gated mode landing |
| §15.8    | apache2 front-end integration                     | P4       | `python/tests/lxc/test_apache_frontend.py` | mssh-passkey + mssh-admin-web through apache |
| §15.9    | systemd unit templates                            | P4       | `python/tests/test_systemd_units.py`       | `cert-renew@.{service,timer}` validation |

### Hardening members below full bar

| ref      | what-needs-testing                                | priority | suggested-test-file                       | notes |
|----------|---------------------------------------------------|----------|-------------------------------------------|-------|
| §13.9.1  | broker hardening receiver (anti-injection / DoS / bogus-callback) | P2 | `python/tests/test_ca_passkey_hardening.py` | depends on §8.3.7 |
| §13.9.2  | MCP audit tagging + CA-side allow-list enforcement | P3      | `python/tests/test_mcp_audit.py`, `python/tests/test_mcp_ca_side_enforcement.py` | partial today |
| §13.9.6  | audit log hash chain + `audit verify`             | P2       | `python/tests/test_ca_audit_integrity.py`  | new test file |
| §13.9.7  | default-deny on missing config (every security-relevant field) | P2 | parametrized across module config tests | each module must add a "config-absent → refuse-to-start" case |
| §13.9.8  | cert OID + marker enforcement (cross-site audit)  | P2       | `python/tests/test_cert_marker_enforcement.py` | matrix: each validating site × each marker OID |

### Verification-pass tooling itself

| ref      | what-needs-testing                                | priority | suggested-test-file                       | notes |
|----------|---------------------------------------------------|----------|-------------------------------------------|-------|
| §17.6    | code-↔-design xref meta-test                     | P1       | `python/tests/test_design_xref.py`         | scan code; expect every § in §1–§16 has ≥1 match |
| §17.7    | test-↔-design xref meta-test                     | P1       | `python/tests/test_design_xref.py`         | scan tests; expect every § in §1–§16 has ≥1 `Tests:` match |
| §17.6→§17.8 | discrepancy reconciliation tooling             | P1       | `python/tests/test_design_xref.py`         | implement §17.9 reconciliation rules as test failures |

## §s whose whole feature is 🚧 (not yet built)

(Mirrors FEATURES-TODO.md's "v1 ship blockers" section — tests will
be written as the features land.)

These tests are already known to be missing without needing the
verification pass to surface them. Listed here so they aren't
forgotten.

| ref      | what-needs-testing                                | priority | suggested-test-file                       | notes |
|----------|---------------------------------------------------|----------|-------------------------------------------|-------|
| §5.3.3   | gated handler — entire feature is 🚧              | P2       | `python/tests/test_msshd_gated_*.py`       | new test file; matrix: deny / allow / mTLS-fail / CA-down |
| §6.3.5   | mssh `-L` local-port forwarding                   | P3       | `python/tests/test_client_port_forward.py` | new test file |
| §8.3.7   | broker hardening v2 (anti-compromised receiver)   | P2       | `python/tests/test_ca_passkey_hardening.py` | new test file; matrix: injected ceremony / replayed callback / DoS rate / fail-state mode |
| §11.3.3  | mssh-admin-web mutating CRUD                      | P3       | `python/packages/mssh-admin/tests/test_web_crud.py` | new test file |
| §11.3.5  | admin-web via mssh-tunneled localhost              | P3       | LXC integration test                       | depends on §6.3.5 |
| §12.4.2  | mssh-mcp audit tagging                             | P3       | `python/tests/test_mcp_audit.py`           | new test file |
| §12.4.3  | mssh-mcp capability allow-list                     | P3       | `python/tests/test_mcp_capability.py`      | new test file |
| §13.9.6  | audit log tamper-resistance                        | P2       | `python/tests/test_ca_audit_integrity.py`  | new test file |
| §13.9.7  | default-deny on missing config                     | P2       | parametrized across module config tests   | every module must add a "config-absent → refuse-to-start" case |
| §13.9.8  | cert OID + marker enforcement                      | P2       | `python/tests/test_cert_marker_enforcement.py` | new test file; matrix: each validating site × each marker OID |
| §15.4    | replaceable broker — alt broker speaks §3.6        | P3       | `python/tests/test_passkey_broker_contract.py` | contract test against the wire protocol, not a specific impl |
| §15.6    | akc_shim integration with unmodified OpenSSH      | P3       | LXC integration test                       | already partially covered in `test_clients_in_containers.py`; expand |
| §15.7    | operator-sshd reuse contract (fallback/gated)     | P2       | LXC integration test                       | gated mode requires this |
| §17.6    | the verification pass itself                       | P1       | `python/tests/test_design_xref.py`         | meta-test: scan code, expect every §X.Y in design has at least one match |
| §17.7    | the test-xref check                                | P1       | `python/tests/test_design_xref.py`         | meta-test: scan tests, expect every §X.Y in design has at least one `Tests: §X.Y` |

---

When a test lands and covers a §, remove the row from this file. If
the test verifies multiple §s, it can satisfy multiple rows in a
single commit.
