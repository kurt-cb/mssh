"""Phase B of the mssh spinup — runs on the freshly-created containers
to install Python + mssh runtime deps and apply the squid proxy
client config.

Pairs with spinup_mssh.py (which creates the containers and writes
their IPs into hosts_live.py). After Phase A, run:

    pyinfra inventory.py examples/spinup_mssh_configure.py

Limit to specific groups if you only spun up a subset:

    pyinfra inventory.py:ubuntu_servers examples/spinup_mssh_configure.py

This is split from spinup_mssh.py because pyinfra can't mutate the
running inventory; configuration has to happen in a second pass once
inventory.py reflects the new hosts.
"""

import sys
from pathlib import Path

from pyinfra import host
from pyinfra.facts.files import Find
from pyinfra.facts.server import LinuxName
from pyinfra.operations import apk, apt, pip

# Allow `pyinfra inventory.py examples/...` to find task_squid.py and
# group_data — we need to include the squid task at the end.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

linux_name = host.get_fact(LinuxName)
DEBIAN_FAMILY = ("Ubuntu", "Debian")
ALPINE_FAMILY = ("Alpine",)

# ---- Install Python3 + pip --------------------------------------------

if linux_name in DEBIAN_FAMILY:
    apt.packages(
        name="Install Python3 and pip (Debian/Ubuntu)",
        packages=["python3", "python3-pip", "python3-venv"],
        update=True,
    )

if linux_name in ALPINE_FAMILY:
    apk.packages(
        name="Install Python3 and pip (Alpine)",
        packages=["python3", "py3-pip"],
        update=True,
    )

# ---- Detect PEP 668 marker + install mssh runtime deps via pip --------

# PEP 668 (EXTERNALLY-MANAGED) blocks system-wide pip installs on
# modern distros. Old Ubuntu 22.04 lacks the marker AND lacks the
# --break-system-packages flag, so only pass the flag when needed.
pep668 = host.get_fact(
    Find,
    path="/usr/lib",
    pattern="EXTERNALLY-MANAGED",
)
extra_args = "--break-system-packages" if pep668 else None

pip.packages(
    name="Install mssh runtime deps via pip",
    packages=[
        "asyncssh>=2.14",
        "cryptography>=41.0",
        "flask>=3.0",
        "pyyaml>=6.0",
        "click>=8.0",
        "requests>=2.31",
    ],
    extra_install_args=extra_args,
)

# ---- Apply squid proxy client config ----------------------------------

# Reuse task_squid.py — same effect as ansible's
# include_tasks: "{{ playbook_dir }}/../task_squid.yml". Skip with
# PYINFRA_SKIP_SQUID=1.
import os
if not os.environ.get("PYINFRA_SKIP_SQUID"):
    from pyinfra.operations import local
    local.include(str(_ROOT / "task_squid.py"))
