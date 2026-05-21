#!/usr/bin/env bash
# setup-adhoc-passkey.sh — bring up an mssh-passkey container
# alongside a running adhoc lab.
#
# Usage:
#   scripts/setup-adhoc-passkey.sh <lab-prefix>
#   e.g. scripts/setup-adhoc-passkey.sh claude-abc123
#
# What this provisions:
#   - LXC container <lab-prefix>-passkey
#   - mssh-passkey installed (pip from the local wheels)
#   - Self-signed mTLS material so mssh-ca and the broker can
#     mutually authenticate. Lab-only; production uses real PKI.
#   - Broker service running in 'dev' mode (in-process TLS)
#   - Generates a ca-config snippet the operator can append to
#     mssh-ca's config to enable the passkey block.
#
# Doesn't touch the main lab setup. Run AFTER setup_adhoc.sh has
# completed (or run standalone if you just want a broker to poke at).

set -euo pipefail

PREFIX="${1:-}"
if [ -z "$PREFIX" ]; then
    echo "usage: $0 <lab-prefix>" >&2
    exit 2
fi

PASSKEY_CN="${PREFIX}-passkey"
WORK="${PWD}/adhoc-passkey-creds"

echo "==> Building wheels (if needed)..."
make -C "$(dirname "$0")/.." pkg >/dev/null

echo "==> Launching container ${PASSKEY_CN}..."
if lxc list --format=csv -c n | grep -q "^${PASSKEY_CN}$"; then
    echo "    container already exists; reusing"
else
    lxc launch mssh-ubuntu-fixed "$PASSKEY_CN"
    # Wait for the container to be reachable.
    for i in $(seq 1 30); do
        if lxc exec "$PASSKEY_CN" -- true 2>/dev/null; then break; fi
        sleep 1
    done
fi

PASSKEY_IP=$(lxc list "$PASSKEY_CN" --format=json \
    | python3 -c "import json,sys; d=json.load(sys.stdin)[0]; \
        addrs=d['state']['network']['eth0']['addresses']; \
        print(next(a['address'] for a in addrs if a['family']=='inet'))")
echo "    ${PASSKEY_CN} = ${PASSKEY_IP}"

echo "==> Minting mTLS material for broker↔CA..."
mkdir -p "$WORK"
cd "$WORK"

# Self-signed CA for the broker side (lab-only).
if [ ! -f passkey-ca.key ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout passkey-ca.key -out passkey-ca.crt \
        -days 30 -subj "/CN=mssh-passkey-lab-CA" 2>/dev/null
fi

# Server cert for the broker's mTLS listener.
if [ ! -f broker-server.crt ]; then
    openssl req -nodes -newkey rsa:2048 \
        -keyout broker-server.key -out broker-server.csr \
        -subj "/CN=${PASSKEY_IP}" 2>/dev/null
    cat > broker-server.ext <<EOF
subjectAltName = IP:${PASSKEY_IP}
EOF
    openssl x509 -req -in broker-server.csr \
        -CA passkey-ca.crt -CAkey passkey-ca.key -CAcreateserial \
        -days 30 -extfile broker-server.ext \
        -out broker-server.crt 2>/dev/null
    rm broker-server.csr broker-server.ext
fi

# Server cert for the broker's public HTTPS listener (port 8000).
if [ ! -f broker-public.crt ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout broker-public.key -out broker-public.crt \
        -days 30 -subj "/CN=passkey.lab.local" \
        -addext "subjectAltName = DNS:passkey.lab.local,IP:${PASSKEY_IP}" 2>/dev/null
fi

# Client cert for mssh-ca (presented when calling the broker).
if [ ! -f ca-client.crt ]; then
    openssl req -nodes -newkey rsa:2048 \
        -keyout ca-client.key -out ca-client.csr \
        -subj "/CN=mssh-ca" 2>/dev/null
    openssl x509 -req -in ca-client.csr \
        -CA passkey-ca.crt -CAkey passkey-ca.key -CAcreateserial \
        -days 30 -out ca-client.crt 2>/dev/null
    rm ca-client.csr
fi

# Self-signed callback-client cert mssh-passkey presents when
# calling back to mssh-ca's /v1/admin/passkey/callback. Reuses the
# same CA for simplicity (lab).
if [ ! -f callback-client.crt ]; then
    openssl req -nodes -newkey rsa:2048 \
        -keyout callback-client.key -out callback-client.csr \
        -subj "/CN=mssh-passkey-broker" 2>/dev/null
    openssl x509 -req -in callback-client.csr \
        -CA passkey-ca.crt -CAkey passkey-ca.key -CAcreateserial \
        -days 30 -out callback-client.crt 2>/dev/null
    rm callback-client.csr
fi

cd - >/dev/null
echo "==> Pushing wheels + certs into ${PASSKEY_CN}..."
lxc exec "$PASSKEY_CN" -- mkdir -p /etc/mssh-passkey/tls /var/lib/mssh-passkey
for f in passkey-ca.crt broker-server.crt broker-server.key \
         broker-public.crt broker-public.key callback-client.crt \
         callback-client.key; do
    lxc file push --quiet "$WORK/$f" "$PASSKEY_CN/etc/mssh-passkey/tls/$f"
done
lxc exec "$PASSKEY_CN" -- chmod 600 \
    /etc/mssh-passkey/tls/broker-server.key \
    /etc/mssh-passkey/tls/broker-public.key \
    /etc/mssh-passkey/tls/callback-client.key

# Push every mssh-* wheel; mssh-passkey doesn't need them strictly,
# but the container's python env is the same we use elsewhere.
for w in dist/mssh_common-*.whl dist/mssh_passkey-*.whl; do
    lxc file push --quiet "$w" "$PASSKEY_CN/tmp/$(basename "$w")"
done

echo "==> Installing in container (apt python + pip wheels)..."
lxc exec "$PASSKEY_CN" -- bash -c '
set -e
apt-get update -q >/dev/null
apt-get install -yq python3 python3-pip >/dev/null
pip install --quiet --break-system-packages \
    /tmp/mssh_common-*.whl /tmp/mssh_passkey-*.whl
'

echo "==> Writing /etc/mssh-passkey/config.yaml..."
lxc exec "$PASSKEY_CN" -- tee /etc/mssh-passkey/config.yaml >/dev/null <<EOF
front_end: dev
public_base_url: https://${PASSKEY_IP}:8000

listen:
  public_https:
    host: 0.0.0.0
    port: 8000
    cert: /etc/mssh-passkey/tls/broker-public.crt
    key:  /etc/mssh-passkey/tls/broker-public.key

  broker_mtls:
    host: 0.0.0.0
    port: 8443
    cert: /etc/mssh-passkey/tls/broker-server.crt
    key:  /etc/mssh-passkey/tls/broker-server.key
    client_ca_cert: /etc/mssh-passkey/tls/passkey-ca.crt

allowed_client_cns:
  - "mssh-ca"

callback:
  client_cert: /etc/mssh-passkey/tls/callback-client.crt
  client_key:  /etc/mssh-passkey/tls/callback-client.key
  ca_cert:     /etc/mssh-passkey/tls/passkey-ca.crt

rp:
  rp_id:   ${PASSKEY_IP}
  rp_name: "mssh-passkey adhoc lab"
  expected_origins:
    - https://${PASSKEY_IP}:8000

database:
  path: /var/lib/mssh-passkey/state.db
EOF

echo "==> Installing systemd unit + starting service..."
lxc exec "$PASSKEY_CN" -- tee /etc/systemd/system/mssh-passkey.service >/dev/null <<'EOF'
[Unit]
Description=mssh-passkey broker (lab)
After=network-online.target

[Service]
ExecStart=mssh-passkey --config /etc/mssh-passkey/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
lxc exec "$PASSKEY_CN" -- systemctl daemon-reload
lxc exec "$PASSKEY_CN" -- systemctl enable --now mssh-passkey
sleep 2

echo "==> Verifying broker is up..."
for i in $(seq 1 10); do
    if lxc exec "$PASSKEY_CN" -- ss -tlnp 2>/dev/null | grep -q ':8443'; then
        echo "    broker mTLS listening on ${PASSKEY_IP}:8443"
        break
    fi
    sleep 1
done

echo
echo "==> Done. To enable passkey on the CA, append to ca-config.yaml:"
cat <<EOF

passkey:
  broker_url:   https://${PASSKEY_IP}:8443
  client_cert:  ${WORK}/ca-client.crt
  client_key:   ${WORK}/ca-client.key
  ca_cert:      ${WORK}/passkey-ca.crt
  callback_url: https://<ca-ip>:8443/v1/admin/passkey/callback
  rp_id:        ${PASSKEY_IP}
  rp_name:      "mssh-ca lab"
  expected_origin: https://${PASSKEY_IP}:8000

EOF
echo "Then restart mssh-ca and try:"
echo "  mssh-admin user passkey enroll --user <admin>"
