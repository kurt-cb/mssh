"""Phase B of the nginx spinup — installs and starts Nginx on the
container that spinup_nginx.py just created.

Run with:

    pyinfra inventory.py:web_server examples/spinup_nginx_configure.py

(or target the host directly via its name once it's in hosts_live.py.)
"""

from pyinfra import host
from pyinfra.facts.server import LinuxName
from pyinfra.operations import server


DEBIAN_FAMILY = ("Ubuntu", "Debian")

linux_name = host.get_fact(LinuxName)

# Install — Alpine uses apk, Debian/Ubuntu use apt, fedora uses dnf.
# pyinfra's `server.packages` picks the right tool automatically.
server.packages(
    name="Install Nginx",
    packages=["nginx"],
    present=True,
)

server.service(
    name="Start and enable Nginx",
    service="nginx",
    running=True,
    enabled=True,
)

if linux_name in DEBIAN_FAMILY:
    # ufw equivalent — pyinfra has no ufw op, shell out.
    server.shell(
        name="Allow HTTP/HTTPS in firewall (Debian)",
        commands=[
            "command -v ufw >/dev/null && ufw allow 80/tcp || true",
            "command -v ufw >/dev/null && ufw allow 443/tcp || true",
        ],
    )

server.shell(
    name="Check Nginx status",
    commands=["systemctl is-active --quiet nginx || rc-service nginx status"],
)
