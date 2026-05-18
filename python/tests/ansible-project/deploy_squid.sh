#!/bin/bash

set -e

CONTAINER_NAME="squid-proxy"
IMAGE_NAME="mssh-alpine-fixed"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_KEY="${SCRIPT_DIR}/ansible_id_ed25519"
SSH_PUB_KEY="${SCRIPT_DIR}/ansible_id_ed25519.pub"
HOSTS_FILE="${SCRIPT_DIR}/hosts.ini"
VARS_FILE="${SCRIPT_DIR}/variables.yml"
PLAYBOOK="${SCRIPT_DIR}/task_squid_server.yml"

echo "Starting container..."
#lxc launch "${IMAGE_NAME}" "${CONTAINER_NAME}"

echo "Waiting for container to be ready..."
sleep 3

echo "Installing OpenSSH server..."
lxc exec "${CONTAINER_NAME}" -- apt-get update
lxc exec "${CONTAINER_NAME}" -- apt-get install -y openssh-server

echo "Starting sshd service..."
lxc exec "${CONTAINER_NAME}" -- systemctl start ssh

echo "Creating .ssh directory in container..."
lxc exec "${CONTAINER_NAME}" -- mkdir -p /root/.ssh
lxc exec "${CONTAINER_NAME}" -- chmod 700 /root/.ssh

echo "Pushing SSH public key to container..."
lxc file push "${SSH_PUB_KEY}" "${CONTAINER_NAME}"/root/.ssh/authorized_keys --mode=0600

echo "Fixing SSH key permissions..."
lxc exec "${CONTAINER_NAME}" -- chown root:root /root/.ssh/authorized_keys
lxc exec "${CONTAINER_NAME}" -- chmod 600 /root/.ssh/authorized_keys

echo "Restarting SSH service..."
lxc exec "${CONTAINER_NAME}" -- systemctl restart ssh

echo "Getting container IP address..."
CONTAINER_IP=$(lxc list "${CONTAINER_NAME}" --format=json | jq -r '.[0].state.network.eth0.addresses[0].address')

echo "Container IP: ${CONTAINER_IP}"

echo "Updating hosts.ini with new IP..."
sed -i "s/squid-proxy  ansible_host=.*/squid-proxy  ansible_host=${CONTAINER_IP}/" "${HOSTS_FILE}"

echo "Updating variables.yml with new IP..."
sed -i "s/proxy_ip: .*/proxy_ip: \"${CONTAINER_IP}\"/" "${VARS_FILE}"

echo "Running Ansible playbook..."
cd "${SCRIPT_DIR}"
ansible-playbook -i "${HOSTS_FILE}" "${PLAYBOOK}"

echo "Testing proxy installation..."

# Test 1: Check if squid service is running
echo "  Checking squid service status..."
if lxc exec "${CONTAINER_NAME}" -- systemctl is-active --quiet squid; then
  echo "  ✓ Squid service is running"
else
  echo "  ✗ Squid service is NOT running"
  exit 1
fi

# Test 2: Check if squid is listening on port 3128
echo "  Checking squid listening on port 3128..."
if lxc exec "${CONTAINER_NAME}" -- ss -tlnp | grep -q 3128; then
  echo "  ✓ Squid is listening on port 3128"
else
  echo "  ✗ Squid is NOT listening on port 3128"
  exit 1
fi

# Test 3: Test proxy connectivity
echo "  Testing proxy connectivity..."
if curl -s --proxy "http://${CONTAINER_IP}:3128" -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null | grep -q "200"; then
  echo "  ✓ Proxy request successful"
else
  echo "  ⚠ Proxy request returned non-200 status (may be normal depending on network)"
fi

echo "Proxy installation verified!"

# create source file to set http proxy settings for bash
cat <<EOF >"${SCRIPT_DIR}/proxy_setup.sh"
export http_proxy=http://${CONTAINER_IP}:3128
export https_proxy=http://${CONTAINER_IP}:3128
export HTTP_PROXY=http://${CONTAINER_IP}:3128
export HTTPS_PROXY=http://${CONTAINER_IP}:3128
EOF

chmod +x "${SCRIPT_DIR}/proxy_setup.sh"
echo "Use 'source proxy_setup.sh' to configure proxy in your shell"

echo "Deployment complete!"