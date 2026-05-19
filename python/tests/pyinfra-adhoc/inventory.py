"""pyinfra inventory — native Python (no Ansible INI translation).

Groups are module-level lists of ``(name, data)`` tuples — pyinfra's
native format. The host dict at the top is the single source of
truth; group exports derive from it.

The committed file ships with a placeholder shape. When the lab is
brought up, ``roles/lxc_spinup.py`` writes the live host map into
``hosts_live.py`` (gitignored); the import below picks it up if
present. This keeps the committed inventory stable for offline
``--check`` runs while the lab-driven flow stays self-contained.

Usage:

    pyinfra inventory.py deploy.py                 # every task on every host
    pyinfra inventory.py task_squid.py             # one task, every host
    pyinfra inventory.py:ubuntu_servers deploy.py  # subset by group

Group structure (matches operator mental model):
  - by OS:    ubuntu_servers / alpine_servers / debian / fedora_servers
  - by role:  ca_server / accounting / sales / hr / engineering
  - rollups:  proxy_clients (every lab container), proxy_servers (squid)
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent


# ---------------------------------------------------------------------------
# Connection defaults — applied to every host. The lab generates
# ansible_id_ed25519 alongside this file.
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, str] = {
    "ssh_user": "root",
    "ssh_key": str(_HERE / "ansible_id_ed25519"),
    "ssh_python_interpreter": "/usr/bin/python3",
    # Match the ansible inventory's ssh_common_args default.
    "ssh_strict_host_key_checking": "off",
}


# ---------------------------------------------------------------------------
# Host map. Placeholder shape; the lab overwrites this via hosts_live.py.
# Each entry: name -> {ssh_hostname, role, os, [other connection vars]}
# ---------------------------------------------------------------------------
HOSTS: dict[str, dict[str, str]] = {
    "mssh-adhoc-ca":    {"ssh_hostname": "10.0.0.1",  "role": "ca_server",   "os": "ubuntu"},
    "mssh-adhoc-acct":  {"ssh_hostname": "10.0.0.10", "role": "accounting",  "os": "ubuntu"},
    "mssh-adhoc-sales": {"ssh_hostname": "10.0.0.11", "role": "sales",       "os": "ubuntu"},
    "mssh-adhoc-hr":    {"ssh_hostname": "10.0.0.12", "role": "hr",          "os": "ubuntu"},
    "mssh-adhoc-eng":   {"ssh_hostname": "10.0.0.13", "role": "engineering", "os": "alpine"},
}

# Override HOSTS from hosts_live.py if the lab has written it.
try:
    from hosts_live import HOSTS as _live  # type: ignore[no-redef]
    HOSTS = _live
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Externally-managed hosts (NOT spun up by the lab). The operator runs
# `pyinfra inventory.py task_squid.py` to apply proxy-client config to
# every lab container; the squid proxy itself is a fixed external host
# pre-configured on the test network. Edit to taste.
# ---------------------------------------------------------------------------
PROXY_HOST_NAME = "squid-proxy"
PROXY_HOST_IP   = "10.26.244.2"


def _entry(name: str, h: dict[str, str]) -> tuple[str, dict[str, str]]:
    data = {**DEFAULTS}
    for k, v in h.items():
        if k in ("role", "os"):
            continue
        data[k] = v
    return (name, data)


def _by(attr: str, value: str) -> list[tuple[str, dict[str, str]]]:
    return [_entry(n, h) for n, h in HOSTS.items() if h.get(attr) == value]


# ---- Group exports — pyinfra picks these up by name ----------------------

# By OS family.
ubuntu_servers  = _by("os", "ubuntu")
alpine_servers  = _by("os", "alpine")
debian          = _by("os", "debian")
fedora_servers  = _by("os", "fedora")

# By role.
ca_server       = _by("role", "ca_server")
accounting      = _by("role", "accounting")
sales           = _by("role", "sales")
hr              = _by("role", "hr")
engineering     = _by("role", "engineering")

# Proxy infrastructure.
proxy_servers   = [(PROXY_HOST_NAME, {**DEFAULTS, "ssh_hostname": PROXY_HOST_IP})]

# Every lab container is a proxy *client* by default.
proxy_clients = ubuntu_servers + alpine_servers + debian + fedora_servers
