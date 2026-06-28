#!/usr/bin/env bash
set -euo pipefail

DATABASE_URL="sqlite::memory:"
STATE_DIR="/tmp/nextest/keystone"
CONFIG_FILE="${STATE_DIR}/etc/keystone.conf"
AXUM_PID=""
SPIRE_SOCKET="/tmp/spire-ci-test-harness/agent.sock"
SPIFFE_ENDPOINT_SOCKET="unix:///${SPIRE_SOCKET}"
TMP_DIR=$(mktemp -d -t spire-test-XXXXXX)

mkdir -p "$STATE_DIR"
mkdir -p "$STATE_DIR/etc/fernet-keys"

# Generate self-signed CA + leaf TLS certificates for distributed storage
SSL_DIR="$STATE_DIR"
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "${SSL_DIR}/ca.key" \
    -out "${SSL_DIR}/ca.crt" \
    -subj "/CN=Keystone-CA" \
    -days 365 2>/dev/null
openssl req -newkey rsa:4096 -nodes \
    -keyout "${SSL_DIR}/ks.key" \
    -out "${SSL_DIR}/ks.csr" \
    -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "${SSL_DIR}/ks.csr" \
    -CA "${SSL_DIR}/ca.crt" -CAkey "${SSL_DIR}/ca.key" \
    -CAcreateserial -out "${SSL_DIR}/ks.pem" \
    -days 365 -copy_extensions copyall 2>/dev/null
rm -f "${SSL_DIR}/ks.csr"

cleanup() {
  echo "Tearing down SPIRE daemons..." >&2
  PID_DIR="/tmp/spire-ci-test-harness"
  if [ -f "$PID_DIR/agent.pid" ]; then kill "$(cat "$PID_DIR/agent.pid")" 2>/dev/null || true; fi
  if [ -f "$PID_DIR/server.pid" ]; then kill "$(cat "$PID_DIR/server.pid")" 2>/dev/null || true; fi
  if [ -f "$STATE_DIR/keystone.pid" ]; then kill "$(cat "$STATE_DIR/keystone.pid")" 2>/dev/null || true; fi
  if [ -n "$AXUM_PID" ]; then kill "$AXUM_PID" 2>/dev/null || true; fi
}

trap cleanup ERR INT TERM

# 0. Aggressive cleanup of previous iterations
tools/teardown-api.sh || true

cat << EOF > "$CONFIG_FILE"

[api_policy]
opa_base_url = unix:///tmp/nextest/keystone/opa.sock
enable = true
opa_policies_path = policy

[auth]
methods = password,token,openid,application_credential,x509

[DEFAULT]
use_stderr = false
debug = true
log_dir = ${STATE_DIR}

[database]
connection = sqlite::memory:

[fernet_receipts]
key_repository = ${STATE_DIR}/etc/fernet-keys
[fernet_tokens]
key_repository = ${STATE_DIR}/etc/fernet-keys

[interface_public]
tcp_address = 0.0.0.0:8080
type = "http"

[interface_admin]
socket_path = ${STATE_DIR}/keystone.sock
trust_domains=example.org
admin_svid=spiffe://example.org/keystone

[distributed_storage]
path = ${STATE_DIR}/raft/db
node_cluster_addr = https://127.0.0.1:50051
node_listener_addr = 0.0.0.0:50051
node_id = 0
tls_client_ca_file = ${STATE_DIR}/ca.crt
tls_cert_file = ${STATE_DIR}/ks.pem
tls_key_file = ${STATE_DIR}/ks.key
dev_mode = true

[webauthn]
driver = raft
enabled = true
relying_party_id = localhost
relying_party_origin = http://localhost:8080

EOF

echo "2Rlc-npWYOGqqG1zM-bmfBj2apLacLXhIbBsdyqQ0zg=" > "${STATE_DIR}"/etc/fernet-keys/0

tools/start-spire.sh

cargo build --bins

KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 KEYSTONE_ALLOW_ENV_KEK=1 SPIFFE_ENDPOINT_SOCKET=$SPIFFE_ENDPOINT_SOCKET ./target/debug/keystone --config "$CONFIG_FILE" &
AXUM_PID=$!

echo "$AXUM_PID" > "$STATE_DIR/keystone.pid"

# 6. Wait for the local port to become active
URL="http://127.0.0.1:8080"
for i in {1..30}; do
    if curl -s "$URL/health" > /dev/null; then
        # Wait for the admin socket to appear
        until [ -S "${STATE_DIR}/keystone.sock" ]; do
          sleep 0.5
        done
        KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 KEYSTONE_ALLOW_ENV_KEK=1 SPIFFE_ENDPOINT_SOCKET=${SPIFFE_ENDPOINT_SOCKET} ./target/debug/keystone-manage --config "${CONFIG_FILE}" bootstrap --bootstrap-password password

        # Export env vars for nextest to inject into test processes
        echo "KEYSTONE_URL=http://localhost:8080" >> "$NEXTEST_ENV"
        echo "OS_AUTH_URL=http://localhost:8080" >> "$NEXTEST_ENV"
        echo "OS_USERNAME=admin" >> "$NEXTEST_ENV"
        echo "OS_PASSWORD=password" >> "$NEXTEST_ENV"
        echo "OS_USER_DOMAIN_ID=default" >> "$NEXTEST_ENV"
        echo "OS_PROJECT_NAME=admin" >> "$NEXTEST_ENV"
        echo "OS_PROJECT_DOMAIN_ID=default" >> "$NEXTEST_ENV"
        echo "KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242" >> "$NEXTEST_ENV"
        echo "KEYSTONE_ALLOW_ENV_KEK=1" >> "$NEXTEST_ENV"
        echo "Server started and bootstrapped successfully."
        exit 0
    fi
    sleep 0.2
done

echo "Server failed to start." >&2
kill $AXUM_PID 2>/dev/null || true
exit 1
