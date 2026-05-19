"""Adhoc mssh test environment: spin up containers and install deps.

Two phases:

  Phase A — run against @local to create containers and write IPs
            into hosts_live.py:

      pyinfra @local examples/spinup_mssh.py

  Phase B — re-run pyinfra against the now-updated inventory to
            install runtime deps + configure squid:

      pyinfra inventory.py examples/spinup_mssh_configure.py
      # or just: pyinfra inventory.py deploy.py

Pyinfra can't mutate its running inventory, so spinup runs in two
passes — the first populates ``hosts_live.py``, the second consumes
it via the sibling ``inventory.py``.

Container set: edit ``CONTAINERS`` below, or set the env var
``PYINFRA_CONTAINERS`` to a comma-separated list of
``<name>:<image>:<role>:<os_family>`` tokens. Role + os_family default
to ``accounting`` / ``ubuntu`` if omitted.
"""

import os
import sys
from pathlib import Path

# Make the project root importable so we can pull in roles/lxc_spinup.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from roles.lxc_spinup import lxc_spinup  # noqa: E402

_HOSTS_LIVE_FILE = _ROOT / "hosts_live.py"
_SSH_KEY = _ROOT / "ansible_id_ed25519"

# Path to adhoc-env.sh — same layout the ansible playbook used. Best-
# effort; skipped if not present.
_ADHOC_ENV_FILE = _ROOT.parent.parent / "adhoc-env.sh"


def _parse_containers() -> list[dict]:
    raw = os.environ.get("PYINFRA_CONTAINERS", "").strip()
    if not raw:
        return [{
            "name": "mssh-adhoc-acct", "image": "mssh-ubuntu-fixed",
            "role": "accounting", "os": "ubuntu",
        }]
    out = []
    for chunk in raw.split(","):
        parts = chunk.split(":")
        name = parts[0].strip()
        image = (parts[1].strip() if len(parts) > 1 else "") or "mssh-ubuntu-fixed"
        role = (parts[2].strip() if len(parts) > 2 else "") or "accounting"
        os_family = (parts[3].strip() if len(parts) > 3 else "") or "ubuntu"
        out.append({"name": name, "image": image,
                    "role": role, "os": os_family})
    return out


CONTAINERS = _parse_containers()

# --- Phase A.1: bring every container up. ----------------------------------

for c in CONTAINERS:
    lxc_spinup(
        container_name=c["name"],
        image_name=c["image"],
        ssh_key_path=str(_SSH_KEY),
    )


# --- Phase A.2: write hosts_live.py with the resolved IPs. -----------------
#
# A single shell op emits the whole file: resolve every container's
# eth0 v4 from `lxc list`, then heredoc the dict literal. This way
# inventory.py sees a consistent snapshot — no per-row sed surgery.

from pyinfra.operations import server  # noqa: E402

_rows = []
for c in CONTAINERS:
    name = c["name"]
    _rows.append(
        f'    "{name}": {{'
        f'"ssh_hostname": "$(lxc list {name} --format=json | '
        f'jq -r \'.[0].state.network.eth0.addresses[] '
        f'| select(.family=="inet") | .address\')", '
        f'"role": "{c["role"]}", '
        f'"os": "{c["os"]}"'
        f'}},'
    )
_body = "\n".join(_rows)

server.shell(
    name=f"hosts_live.py: write {len(CONTAINERS)} host(s)",
    commands=[
        f'cat > {_HOSTS_LIVE_FILE} <<EOF\n'
        f'"""Live host map — written by examples/spinup_mssh.py.\n'
        f'Imported by ../inventory.py if present. Gitignored."""\n'
        f'HOSTS = {{\n{_body}\n}}\n'
        f'EOF'
    ],
)


# --- Phase A.3: also export IPs into adhoc-env.sh (legacy helper). --------

if _ADHOC_ENV_FILE.exists():
    for c in CONTAINERS:
        short = c["name"].replace("-", "_")
        server.shell(
            name=f"adhoc-env.sh: export {short}_IP",
            commands=[
                f"ip=$(lxc list {c['name']} --format=json | "
                f"jq -r '.[0].state.network.eth0.addresses[]"
                f"| select(.family==\"inet\") | .address'); "
                f"line=\"export {short}_IP=$ip\"; "
                f"if grep -qE '^export {short}_IP=' {_ADHOC_ENV_FILE}; then "
                f"  sed -i.bak -E "
                f"  's|^export {short}_IP=.*|'\"$line\"'|' "
                f"  {_ADHOC_ENV_FILE}; "
                f"else "
                f"  printf '%s\\n' \"$line\" >> {_ADHOC_ENV_FILE}; "
                f"fi",
            ],
        )
