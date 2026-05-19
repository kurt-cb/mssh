# Adhoc-lab spinup: transition from pytest to pyinfra-adhoc

Status: design proposal, not yet implemented
Author: Kurt Godwin (with Claude)
Date: 2026-05-19

## Context

The pytest harness at [python/tests/lxc/test_setup_only_msshd.py](../python/tests/lxc/test_setup_only_msshd.py) drives a fixed 5-container lab — 1 Ubuntu 22.04 CA + 3 Ubuntu role hosts + 1 Alpine — via direct `lxc exec` calls in [python/tests/lxc/lxc_helpers.py](../python/tests/lxc/lxc_helpers.py). mssh is therefore only continuously tested against those two distros.

Two unmet needs motivate the transition:

1. **Operator-facing reuse**: a human should be able to rebuild a single container without re-running the whole test harness. Today the spinup logic is buried inside pytest fixtures.
2. **OS-matrix coverage**: test mssh against Debian + Fedora + multiple Ubuntu/Alpine versions. The current `_is_alpine` two-way fork in [lxc_helpers.py](../python/tests/lxc/lxc_helpers.py) doesn't scale.

The newly-created [python/tests/pyinfra-adhoc/](../python/tests/pyinfra-adhoc/) is the natural home for both. Pyinfra's `server.packages` / `server.service` auto-dispatch across apt / apk / dnf and systemd / openrc — exactly the abstraction the matrix needs. Performance is *not* the reason for the offload; operator-facing reuse + cross-distro coverage are. (Folklore says ansible was considered and rejected on perf grounds, but no such investigation is documented in the repo — see "Prior art" below.)

**Out of scope for this transition**: porting msshd Phase 1 / Phase 2 work (fallback install, cert push, enforce mode) to pyinfra. Those stay in pytest until the spinup PoC validates the subprocess pattern. A follow-up design can pick that up.

## Approach

Make pyinfra-adhoc the **adhoc lab spinup** tool. Operator-only at first; pytest is unchanged. Two phases, matching the existing pattern in [pyinfra-adhoc/roles/lxc_spinup.py](../python/tests/pyinfra-adhoc/roles/lxc_spinup.py):

- **Phase A** (`pyinfra @local examples/spinup_lab.py`): launch containers from a matrix definition, install sshd + mssh runtime deps via the OS's native package manager, push pubkey, write IP into hosts.ini.
- **Phase B** (`pyinfra inventory.py deploy.py`): once hosts.ini is populated, normal SSH-driven pyinfra tasks (squid client, asyncssh upgrade, future tasks).

### Matrix definition

A new [pyinfra-adhoc/matrix.py](../python/tests/pyinfra-adhoc/matrix.py) defines the lab as a list of dicts. Operator edits this file (or sets `PYINFRA_MATRIX=/path/to/matrix.py`) to choose which containers/OSes to bring up:

```python
MATRIX = [
    {"name": "mssh-adhoc-ca",        "image": "mssh-ubuntu-22-fixed",
     "group": "ca_server",   "os_family": "debian"},
    {"name": "mssh-adhoc-acct-u22",  "image": "mssh-ubuntu-22-fixed",
     "group": "accounting",  "os_family": "debian"},
    {"name": "mssh-adhoc-sales-u24", "image": "mssh-ubuntu-24-fixed",
     "group": "sales",       "os_family": "debian"},
    {"name": "mssh-adhoc-hr-d12",    "image": "mssh-debian-12-fixed",
     "group": "hr",          "os_family": "debian"},
    {"name": "mssh-adhoc-eng-f40",   "image": "mssh-fedora-40-fixed",
     "group": "engineering", "os_family": "redhat"},
    {"name": "mssh-adhoc-eng-alpine","image": "mssh-alpine-fixed",
     "group": "engineering", "os_family": "alpine"},
]
```

The `os_family` field is the dispatch key for package-install (debian | redhat | alpine). Modeled on [test_setup_only_msshd.py:104-108](../python/tests/lxc/test_setup_only_msshd.py#L104-L108) `SERVERS: list[_Server]`.

### Extend `roles/lxc_spinup.py`

Current state: hardcoded `apt-get install` with an `apk add` fallback ([roles/lxc_spinup.py:60-70](../python/tests/pyinfra-adhoc/roles/lxc_spinup.py#L60-L70)). Extend to:

- Add `os_family: str` parameter to `lxc_spinup()`.
- Dispatch package install by `os_family`:
  - `debian` → `apt-get update && apt-get install -y openssh-server python3 python3-pip`
  - `redhat` → `dnf install -y openssh-server python3 python3-pip`
  - `alpine` → `apk add --no-cache openssh-server openssh-keygen python3 py3-pip && ssh-keygen -A`
- Install mssh runtime deps via pip (move from [examples/spinup_mssh_configure.py](../python/tests/pyinfra-adhoc/examples/spinup_mssh_configure.py) into the role so spinup_lab.py is self-sufficient). PEP 668 detection via `Find /usr/lib EXTERNALLY-MANAGED` matches the existing pattern.
- Service start dispatched by family: `systemctl start ssh` (debian/redhat) vs `/usr/sbin/sshd` (alpine).

### Phase A driver: `examples/spinup_lab.py`

New file. Reads `MATRIX` from `matrix.py` (or `$PYINFRA_MATRIX`); for each entry calls `lxc_spinup(...)` with the right `image`, `os_family`, `name`, plus `inventory_file=hosts.ini`. Each row is independent; pyinfra processes them sequentially against `@local` since they all shell out to `lxc`.

### Image prerequisites

Today only `mssh-ubuntu-fixed` (22.04) and `mssh-alpine-fixed` (3.21) get prebaked by `ensure_fixed_images()` ([lxc_helpers.py:515](../python/tests/lxc/lxc_helpers.py#L515)). For new OSes the operator can either:

- Use upstream image aliases directly (`debian/12`, `images:fedora/40`) — works for short-lived testing; apt-daily race on cloud images is the known gotcha.
- Prebake their own `mssh-<os>-<ver>-fixed` images (out of scope for this transition; document in README).

A small `examples/build_images.py` is **not** part of this design — defer until the matrix scope clarifies which prebake quirks each OS needs.

### Pytest left untouched

[test_setup_only_msshd.py](../python/tests/lxc/test_setup_only_msshd.py) is not modified. Its fixed Ubuntu+Alpine path continues to work via [lxc_helpers.py](../python/tests/lxc/lxc_helpers.py). The matrix-driven spinup is an **operator-facing parallel surface**, not a replacement. A follow-up design can subprocess `pyinfra @local examples/spinup_lab.py` from pytest once the spinup PoC is validated.

## Files

**New**:

- [python/tests/pyinfra-adhoc/matrix.py](../python/tests/pyinfra-adhoc/matrix.py) — `MATRIX` list with default 5-container lab definition.
- [python/tests/pyinfra-adhoc/examples/spinup_lab.py](../python/tests/pyinfra-adhoc/examples/spinup_lab.py) — Phase A driver; iterates matrix and calls `lxc_spinup()`.

**Modified**:

- [python/tests/pyinfra-adhoc/roles/lxc_spinup.py](../python/tests/pyinfra-adhoc/roles/lxc_spinup.py) — add `os_family` param + per-family dispatch + mssh-deps install (merged in from `spinup_mssh_configure.py`).
- [python/tests/pyinfra-adhoc/README.md](../python/tests/pyinfra-adhoc/README.md) — new "Adhoc lab spinup" section documenting matrix.py + two-phase flow + image expectations.
- [python/tests/pyinfra-adhoc/examples/spinup_mssh.py](../python/tests/pyinfra-adhoc/examples/spinup_mssh.py) — keep as the single-container example; cross-reference spinup_lab.py for the matrix flow.

**Reused existing code** (no changes):

- [roles/lxc_spinup.py](../python/tests/pyinfra-adhoc/roles/lxc_spinup.py) `@deploy` decorator pattern + IP-write-back logic.
- [inventory.py](../python/tests/pyinfra-adhoc/inventory.py) Ansible-INI parser (Phase B reads what Phase A wrote).
- [lxc_helpers.py:36-51](../python/tests/lxc/lxc_helpers.py#L36-L51) image-alias constants — read for naming consistency between pytest and pyinfra surfaces (`mssh-<os>-fixed` convention).

## Verification

1. **Single Debian container, end-to-end**:

   ```sh
   cd python/tests/pyinfra-adhoc
   # Edit matrix.py down to one entry, image: debian/12 (upstream), os_family: debian
   pyinfra @local examples/spinup_lab.py
   grep "debian-12" hosts.ini                 # IP should be written
   ssh -i ansible_id_ed25519 -o StrictHostKeyChecking=no \
       root@$(grep debian-12 hosts.ini | awk '{print $2}' | cut -d= -f2) 'cat /etc/os-release'
   ```

   Expect: container reachable; `cat /etc/os-release` shows Debian 12.

2. **Phase B follows from updated inventory**:

   ```sh
   pyinfra inventory.py task_squid.py
   ```

   Expect: squid client config applied; no re-spinup attempted.

3. **OS-family dispatch**: run with one entry per family (`debian`, `redhat`, `alpine`). For each, confirm pyinfra's output shows the right package manager invoked (`apt-get`, `dnf`, `apk`).

4. **Idempotency**: re-run `spinup_lab.py` against an already-launched container. Expect: pyinfra reports `lxc launch` as no-op (the role's `|| true` swallows "already exists"), package install is no-op (`server.packages` is idempotent), authorized_keys push is no-op or updates in place.

5. **Cleanup**:

   ```sh
   for c in $(awk '/ansible_host=/ {print $1}' hosts.ini); do lxc delete --force $c; done
   ```

6. **Pytest unaffected**:

   ```sh
   pytest python/tests/lxc/test_setup_only_msshd.py -k "phase_0"
   ```

   Expect: passes; no new failures from the spinup_lab.py additions.

## Open risks

1. **Fixed-image prebake** for non-Ubuntu/non-Alpine distros doesn't exist yet. Using upstream images directly is fine for ad-hoc testing but exposes the apt-daily-on-first-boot race on Debian/Fedora cloud images. Document in README; defer prebake recipes to a follow-up.

2. **Cryptography on Fedora/RHEL** may need `python3-devel` + a C compiler for the pip install. If `pip install cryptography` fails, switch to `dnf install python3-cryptography` as a fallback. Discover during PoC.

3. **lxc image remote `images:`** must be configured on the operator workstation. Already the case in this lab (used by `ensure_fixed_images` at [lxc_helpers.py:355,492](../python/tests/lxc/lxc_helpers.py#L355)), but worth noting for an operator with a fresh LXD install.

4. **Group membership in `inventory.py`** keys off section names (`[hr]`, `[engineering]`, …) — matrix entries with new groups need either the section in `hosts.ini` or a small extension to `inventory.py` to auto-create groups from `host.data.group`. Trivial extension; flag during implementation.

## Prior art / decisions

- **No documented ansible perf investigation**: Explore search of `bugs.md`, commit history, `design/`, `archive/design/`, and READMEs turned up no concrete measurements or design notes rejecting ansible on performance grounds. The "ansible is too slow" rationale is folklore. The operator-facing-reuse and OS-matrix arguments are sufficient on their own to justify the pyinfra transition — don't rest the case on speed claims that aren't backed up.
- **Pyinfra's known gap (inventory mutation)** is already accommodated by the existing two-phase pattern in pyinfra-adhoc: Phase A writes IPs into `hosts_live.py` (a native pyinfra import), Phase B reads them via `inventory.py`. The matrix-driven spinup follows the same pattern. Note: the original transition draft kept an Ansible-INI intermediate (`hosts.ini` + a parser); that has since been removed in favor of native pyinfra inventory. See [README.md § Inventory](README.md#inventory).
- **CA-bypass cert mechanism and authz cache** (CLAUDE.md Amendments 2026-05-18 a/b/c) are downstream of this work — operator-facing rebuild of a single container is partly motivated by the bypass-cert workflow (operator pre-mints, injects later). Wiring those into pyinfra tasks is a future design.

## Follow-ups (not in this transition)

- Port pytest's msshd Phase 1 install ([test_setup_only_msshd.py:1664-1700](../python/tests/lxc/test_setup_only_msshd.py#L1664-L1700)) to a `phase1_msshd_fallback.py` task. Already cleanly factored — sshd is up, only wrapper.yaml + systemd unit + restart needed.
- Port Phase 2 cert push ([msshd_helpers.py:214](../python/tests/lxc/msshd_helpers.py#L214) `push_msshd_cert_material`) to `phase2_certs.py`. Cert *minting* stays host-side Python (cryptography library); pyinfra is push-only.
- Prebake recipes for `mssh-debian-12-fixed`, `mssh-fedora-40-fixed`, `mssh-ubuntu-24-fixed` — each needs apt-daily / dnf-automatic / unattended-upgrades masked.
- Subprocess pyinfra from pytest once the operator-facing surface is stable, replacing the hardcoded `for s in SERVERS` loops with a single pyinfra invocation parameterized by `matrix.py`.
