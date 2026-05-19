# adhoc-lab pyinfra-adhoc

A pyinfra project that drives the mssh adhoc lab. Functionally
overlaps with [ansible-project/](../ansible-project/) — same lab,
same tasks — but uses pyinfra-native inventory (no Ansible INI
intermediate). Pick whichever tool you prefer.

This tree is a **mutable example**: feel free to edit
`inventory.py`, `roles/`, and the task files to fit your workflow.

## Inventory

`inventory.py` is a native pyinfra inventory — module-level group
lists (`ubuntu_servers`, `accounting`, `proxy_clients`, …) derived
from a single `HOSTS` dict at the top of the file. The committed
shape ships with placeholder IPs for offline `--check` runs.

When the lab is brought up, `examples/spinup_mssh.py` writes a
sibling `hosts_live.py` with the real IPs:

```python
# hosts_live.py — written by spinup; gitignored.
HOSTS = {
    "claude-abc-adhoc-ca":   {"ssh_hostname": "10.26.244.1",  "role": "ca_server",  "os": "ubuntu"},
    "claude-abc-adhoc-acct": {"ssh_hostname": "10.26.244.10", "role": "accounting", "os": "ubuntu"},
    ...
}
```

`inventory.py` imports `hosts_live` if present and uses its `HOSTS`
in place of the placeholder. No INI parsing, no cross-tree copying.

### Group structure

- **By OS:** `ubuntu_servers`, `alpine_servers`, `debian`, `fedora_servers`
- **By role:** `ca_server`, `accounting`, `sales`, `hr`, `engineering`
- **Rollups:** `proxy_clients` (every lab container), `proxy_servers`
  (the external squid host — edit `PROXY_HOST_IP` in inventory.py)

## Layout

| File                                 | Purpose                                              |
|--------------------------------------|------------------------------------------------------|
| `inventory.py`                       | Native pyinfra inventory + group composition         |
| `hosts_live.py` (gitignored)         | Live host map, written by spinup                     |
| `group_data/all.py`                  | Variables for every host (proxy IP/port, …)          |
| `deploy.py`                          | Top-level deploy — globs every `task_*.py`           |
| `task_squid.py`                      | Point each host at the squid proxy                   |
| `task_upgrade_asyncssh.py`           | Fix Ubuntu 22.04 asyncssh ≤2.5 PTY bug               |
| `roles/lxc_spinup.py`                | Reusable `@deploy` to launch LXC containers          |
| `examples/spinup_mssh.py`            | Phase A: create lab containers, write hosts_live.py  |
| `examples/spinup_mssh_configure.py`  | Phase B: install deps + squid on the new hosts       |
| `examples/spinup_nginx.py`           | Phase A: nginx container                             |
| `examples/spinup_nginx_configure.py` | Phase B: install + start nginx                       |
| `ansible_id_ed25519`                 | Private key — auto-generated at lab setup (gitignored) |

## Two-phase pattern

Pyinfra can't mutate its running inventory, so spinup is two passes:

```sh
# Phase A: launch containers and write hosts_live.py
pyinfra @local examples/spinup_mssh.py

# Phase B: configure the new hosts (proxy clients + python deps + squid)
pyinfra inventory.py deploy.py
# or just the squid task:
pyinfra inventory.py task_squid.py
```

## Invocation cheatsheet

```sh
# Smoke-test connectivity (all hosts):
pyinfra inventory.py exec -- whoami

# Run every task on every host (proxy_clients):
pyinfra inventory.py deploy.py

# Run a single task (closest pyinfra analogue to ansible --tags):
pyinfra inventory.py task_squid.py
pyinfra inventory.py task_upgrade_asyncssh.py

# Limit by group:
pyinfra inventory.py:ubuntu_servers deploy.py
pyinfra inventory.py:ubuntu_servers task_upgrade_asyncssh.py
```

`deploy.py` globs every `task_*.py` in lexical order — drop a new
`task_<name>.py` here and the next `pyinfra deploy.py` run picks it
up automatically.

## Adding tasks

Drop a new `task_<name>.py` in this directory. Skeleton:

```python
from pyinfra import host
from pyinfra.facts.server import LinuxName
from pyinfra.operations import server

if host.get_fact(LinuxName) in ("Ubuntu", "Debian"):
    server.shell(
        name="myfeature: do the thing",
        commands=["/usr/local/bin/thing"],
    )
```

Then:

```sh
pyinfra inventory.py task_myfeature.py    # tag-equivalent
pyinfra inventory.py deploy.py            # everything
```

## Differences from the ansible version

- **No `add_host`.** pyinfra can't mutate the running inventory.
  Phase A writes `hosts_live.py`; Phase B reads it via `inventory.py`.
- **No native `ini_file`.** `task_squid.py` uses `files.line` for the
  DNF proxy line — works for typical dnf.conf shape, may need
  `crudini` or `server.shell` if your file is more complex.
- **No native `ufw`.** `spinup_nginx_configure.py` shells out instead.
- **`failed_when: false`** becomes `command 2>/dev/null || true` in
  `server.shell` since pyinfra has no per-op ignore_errors.

## Operator-side prerequisites

```sh
pip install pyinfra            # >=2.x
# plus the lab key:
ssh-keygen -t ed25519 -N '' -f ansible_id_ed25519 -C ansible@mssh-lab
chmod 600 ansible_id_ed25519
```

If you also use the ansible-project tree, you can reuse the same
`ansible_id_ed25519` keypair — symlink or copy it across. The lab
test harness generates it into ansible-project/ automatically.

## See also

[adhoc-pyinfra-transition.md](adhoc-pyinfra-transition.md) — design
doc for extending this surface into a matrix-driven cross-distro
spinup (precondition for [future-ideas §20](../../../design/future-ideas.md)
and [§24](../../../design/future-ideas.md)).
