# Spinup Examples

These show how to use the `lxc_spinup` reusable `@deploy` to create
containers and then configure services on them. They're the pyinfra
analogue of [ansible-project/examples](../../ansible-project/examples/).

## Two-phase pattern

ansible's spinup playbooks could create a container AND configure it
in a single file because `add_host` injects new hosts into the running
inventory mid-play. pyinfra has no equivalent — the inventory is
fixed for the run.

So every spinup is split into two files:

  - `spinup_<service>.py`           — **Phase A**, run against `@local`.
                                       Creates the container; the driver
                                       writes its name/IP/role/os into
                                       `hosts_live.py`.
  - `spinup_<service>_configure.py` — **Phase B**, run against
                                       `inventory.py` (which imports
                                       `hosts_live`). Installs and
                                       configures the service.

Invocation:

```sh
pyinfra @local examples/spinup_mssh.py                       # create
pyinfra inventory.py examples/spinup_mssh_configure.py       # configure

pyinfra @local examples/spinup_nginx.py
pyinfra inventory.py:web-server examples/spinup_nginx_configure.py
```

## What `lxc_spinup` does

Same as the ansible role — creates the LXC container, installs
openssh-server, pushes the lab pubkey to `/root/.ssh/authorized_keys`,
restarts sshd, waits for an IP. The driver (`spinup_mssh.py`) is
responsible for collecting IPs and emitting `hosts_live.py` after
every container in the matrix has booted — pyinfra can't mutate its
own running inventory, so that step lives outside the role.
See `roles/lxc_spinup.py` for the role implementation.

## Variables

| Variable          | Default                  | Description                            |
|-------------------|--------------------------|----------------------------------------|
| `container_name`  | (required)               | LXC container name                     |
| `image_name`      | `mssh-alpine-fixed`      | Image to launch from                   |
| `container_user`  | `root`                   | Kept for parity with the ansible role  |
| `ssh_key_path`    | `./ansible_id_ed25519`   | Host-side path to the SSH private key  |
| `wait_timeout`    | `30`                     | Seconds to wait for container IP / SSH |

## Customizing the container list

`spinup_mssh.py` reads `$PYINFRA_CONTAINERS` if set:

```sh
PYINFRA_CONTAINERS="acct-test01:mssh-ubuntu-fixed:accounting:ubuntu,sales-test01:mssh-alpine-fixed:sales:alpine" \
  pyinfra @local examples/spinup_mssh.py
```

Format: `name:image:role:os,…`. Omitted role / os default to
`accounting` / `ubuntu`; omitted image defaults to `mssh-ubuntu-fixed`.

## Writing your own spinup

```python
# examples/spinup_myservice.py — Phase A
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from roles.lxc_spinup import lxc_spinup

lxc_spinup(
    container_name="my-service",
    image_name="mssh-alpine-fixed",
    ssh_key_path=str(_ROOT / "ansible_id_ed25519"),
)
# (Driver code that writes hosts_live.py lives in spinup_mssh.py —
#  copy that pattern if your service needs to be in inventory.)
```

```python
# examples/spinup_myservice_configure.py — Phase B
from pyinfra.operations import server

server.packages(name="Install my-service", packages=["my-service"])
server.service(name="Start my-service", service="my-service",
               running=True, enabled=True)
```

## Notes

- `lxc_spinup` runs against `@local` (the operator workstation, since
  it shells out to `lxc`). The Phase B file uses the regular
  inventory.
- The container must have network access for its IP to be picked up.
- Make sure `ansible_id_ed25519` and its `.pub` half exist before
  running.
