"""Point each host at the squid proxy — pyinfra equivalent of task_squid.yml.

Directly runnable (acts like an ansible tag-limited play):

    pyinfra inventory.py task_squid.py

Or chained through deploy.py:

    pyinfra inventory.py deploy.py
"""

from pyinfra import host
from pyinfra.facts.server import LinuxName
from pyinfra.operations import files

proxy_ip = host.data.proxy_ip
proxy_hostname = host.data.proxy_hostname
proxy_port = host.data.proxy_port

linux_name = host.get_fact(LinuxName)
DEBIAN_FAMILY = ("Ubuntu", "Debian")
REDHAT_FAMILY = ("CentOS", "RedHat", "Fedora", "Rocky", "AlmaLinux", "Oracle")
ALPINE_FAMILY = ("Alpine",)


files.line(
    name="squid: /etc/hosts entry",
    path="/etc/hosts",
    line=rf"^{proxy_ip}\s+",
    replace=f"{proxy_ip} {proxy_hostname}",
    present=True,
)

if linux_name in DEBIAN_FAMILY or linux_name in REDHAT_FAMILY:
    files.block(
        name="squid: system environment (Debian/RedHat)",
        path="/etc/environment",
        content=(
            f'http_proxy="http://{proxy_hostname}:{proxy_port}/"\n'
            f'https_proxy="http://{proxy_hostname}:{proxy_port}/"'
        ),
    )

if linux_name in DEBIAN_FAMILY:
    files.block(
        name="squid: APT proxy (Ubuntu/Debian)",
        path="/etc/apt/apt.conf.d/99proxy",
        content=f'Acquire::http::Proxy "http://{proxy_hostname}:{proxy_port}/";',
        create_remote_file=True,
    )

if linux_name in REDHAT_FAMILY:
    # DNF cares about the [main] section. files.line is regex-based; it
    # replaces an existing proxy= line or appends one at EOF. dnf is
    # tolerant of an out-of-section proxy= when the file has only [main].
    files.line(
        name="squid: DNF proxy (RedHat)",
        path="/etc/dnf/dnf.conf",
        line=r"^proxy\s*=",
        replace=f"proxy=http://{proxy_hostname}:{proxy_port}",
    )

if linux_name in ALPINE_FAMILY:
    files.block(
        name="squid: profile proxy (Alpine)",
        path="/etc/profile.d/proxy.sh",
        content=(
            f'export http_proxy="http://{proxy_hostname}:{proxy_port}/"\n'
            f'export https_proxy="http://{proxy_hostname}:{proxy_port}/"'
        ),
        create_remote_file=True,
        mode="0755",
    )
