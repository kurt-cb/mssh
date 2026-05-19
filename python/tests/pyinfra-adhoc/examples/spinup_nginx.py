"""Spinup and configure Nginx web server — pyinfra equivalent of
examples/spinup_nginx.yml.

Two-phase, like spinup_mssh.py:

  Phase A — create the web-server container (@local):

      pyinfra @local examples/spinup_nginx.py

  Phase B — configure Nginx on the new host:

      pyinfra inventory.py examples/spinup_nginx_configure.py

This minimal driver does Phase A only; it does not write
hosts_live.py (a single-host deploy doesn't need the inventory
machinery). To target the new host from Phase B, either edit
hosts_live.py by hand or use the `--limit` flag. See spinup_mssh.py
for the multi-host pattern that writes hosts_live.py.
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from roles.lxc_spinup import lxc_spinup  # noqa: E402

lxc_spinup(
    container_name="web-server",
    image_name="mssh-alpine-fixed",
    ssh_key_path=str(_ROOT / "ansible_id_ed25519"),
)
