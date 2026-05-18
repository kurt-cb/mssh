#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VARS_FILE="${SCRIPT_DIR}/variables.yml"

# Read proxy_ip from variables.yml
PROXY_IP=$(grep "proxy_ip:" "${VARS_FILE}" | sed 's/proxy_ip:[ "*]//g' | tr -d '"')

echo "Using proxy IP from variables.yml: ${PROXY_IP}"
echo "Configuring LXC network to exclude static IP range..."
lxc network set lxdbr0 ipv4.dhcp.ranges 10.26.244.100-10.26.244.254

echo "Deploying Squid Proxy..."
cd "${SCRIPT_DIR}"
ansible-playbook examples/spinup_squid.yml -e "proxy_static_ip=${PROXY_IP}"

echo ""
echo "✓ Squid proxy deployed successfully!"
echo ""
echo "Proxy is running at: http://${PROXY_IP}:3128"
echo ""
echo "To use the proxy in your shell:"
cat <<EOF
  export http_proxy=http://${PROXY_IP}:3128
  export https_proxy=http://${PROXY_IP}:3128
EOF
echo ""