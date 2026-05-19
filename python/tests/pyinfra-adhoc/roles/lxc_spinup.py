"""LXC container spinup — reusable pyinfra @deploy.

Decorated with ``@deploy`` so example deploys can import + reuse it.
Targets ``@local`` (the operator workstation, which has the lxc CLI).

Responsibility: bring the container up, install sshd, drop the lab
key into ``root@``'s authorized_keys, wait until eth0 has an IP. The
caller is responsible for collecting IPs and writing them into
``hosts_live.py`` — pyinfra can't mutate its running inventory, so
that job is a separate post-step the driver runs after every host
in the matrix has booted.

Parameters:

    container_name   (required) — LXC container name
    image_name       (default mssh-alpine-fixed)
    container_user   (default root) — kept for parity; unused here
    ssh_key_path     (default ./ansible_id_ed25519) — host-side path
    wait_timeout     (default 30) — seconds to wait for SSH/IP
"""

from pyinfra.api import deploy
from pyinfra.operations import server


@deploy("lxc_spinup")
def lxc_spinup(
    container_name: str,
    image_name: str = "mssh-alpine-fixed",
    container_user: str = "root",
    ssh_key_path: str = "./ansible_id_ed25519",
    wait_timeout: int = 30,
):
    server.shell(
        name=f"lxc_spinup[{container_name}]: launch",
        commands=[
            # `|| true` swallows "already exists" without checking stderr
            # — equivalent to the ansible role's failed_when filter.
            f"lxc launch {image_name} {container_name} 2>&1 | "
            f"tee /tmp/lxc-launch-{container_name}.log; "
            f"grep -q 'already exists' /tmp/lxc-launch-{container_name}.log "
            f"|| lxc info {container_name} >/dev/null 2>&1",
        ],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: wait for boot",
        commands=["sleep 3"],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: install openssh-server",
        commands=[
            # Try apt first (Debian/Ubuntu); fall back to apk (Alpine).
            f"lxc exec {container_name} -- sh -c '"
            f"command -v apt-get >/dev/null && "
            f"  (apt-get update && apt-get install -y openssh-server) || "
            f"  (apk add --no-cache openssh-server openssh-keygen && "
            f"   ssh-keygen -A)'",
        ],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: start sshd",
        commands=[
            f"lxc exec {container_name} -- sh -c '"
            f"command -v systemctl >/dev/null && "
            f"  systemctl start ssh || /usr/sbin/sshd'",
        ],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: install authorized_keys",
        commands=[
            f"lxc exec {container_name} -- mkdir -p /root/.ssh",
            f"lxc exec {container_name} -- chmod 700 /root/.ssh",
            f"lxc file push {ssh_key_path}.pub "
            f"{container_name}/root/.ssh/authorized_keys --mode=0600",
            f"lxc exec {container_name} -- "
            f"chown root:root /root/.ssh/authorized_keys",
            f"lxc exec {container_name} -- chmod 600 /root/.ssh/authorized_keys",
        ],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: restart sshd",
        commands=[
            f"lxc exec {container_name} -- sh -c '"
            f"command -v systemctl >/dev/null && "
            f"  systemctl restart ssh || "
            f"  (pkill -HUP sshd; /usr/sbin/sshd)'",
        ],
    )

    server.shell(
        name=f"lxc_spinup[{container_name}]: wait for IP",
        commands=[
            # Poll until eth0 has a v4 address or timeout. Echo the IP
            # to stdout so pyinfra shows it.
            f"for i in $(seq 1 {wait_timeout}); do "
            f"  ip=$(lxc list {container_name} --format=json | "
            f"  jq -r '.[0].state.network.eth0.addresses[]"
            f"  | select(.family==\"inet\") | .address' 2>/dev/null); "
            f"  if [ -n \"$ip\" ]; then echo \"$ip\"; exit 0; fi; "
            f"  sleep 1; "
            f"done; echo 'timed out waiting for IP' >&2; exit 1",
        ],
    )
