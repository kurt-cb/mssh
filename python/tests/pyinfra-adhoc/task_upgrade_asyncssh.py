"""Fix Ubuntu 22.04 asyncssh<=2.5 PTY bug — pyinfra equivalent of
task_upgrade_asyncssh.yml.

Ubuntu's apt python3-asyncssh is pinned at 2.5.0 (from 2020); msshd
needs 2.14+ for stable interactive PTY data flow. Pip-override the
apt version, then restart msshd. No-op on any other distro.

Directly runnable:

    pyinfra inventory.py task_upgrade_asyncssh.py

Or chained through deploy.py.

Delete this file if you don't need the workaround on your lab.
"""

from pyinfra import host
from pyinfra.operations import pip, server

# Match the ansible "'ubuntu_servers' in group_names" guard. pyinfra
# exposes host group membership via host.groups (a set/list of names).
if "ubuntu_servers" in host.groups:
    pip.packages(
        name="Upgrade asyncssh to >=2.14 (fixes interactive-mssh PTY bug)",
        packages=["asyncssh>=2.14"],
        extra_install_args="--break-system-packages --upgrade",
    )
    # msshd may not be configured yet at this phase — ignore failure
    # like the ansible task's `failed_when: false`.
    server.shell(
        name="Restart msshd (if running)",
        commands=["systemctl restart msshd 2>/dev/null || true"],
    )
