#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/tmp/loadtest/keystone"
CONFIG_FILE="${STATE_DIR}/etc/keystone.conf"
REAL_HOME="$HOME"
DATABASE_URL="postgres://postgres:password@127.0.0.1:15432/postgres"
SPIRE_SOCKET="/tmp/spire-ci-test-harness/agent.sock"
SPIFFE_ENDPOINT_SOCKET="unix:///${SPIRE_SOCKET}"
KEYSTONE_PID=""

cleanup() {
  echo "Tearing down loadtest environment..." >&2
  if [ -n "$KEYSTONE_PID" ]; then kill "$KEYSTONE_PID" 2>/dev/null || true; fi
  pkill -f "opa run -s .* --addr unix://${STATE_DIR}/opa.sock" 2>/dev/null || true
}
trap cleanup ERR INT TERM

tools/teardown-loadtest.sh || true
rm -rf "$STATE_DIR"
mkdir -p "${STATE_DIR}/etc/fernet-keys"

# openstack_sdk caches auth tokens per cloud-config hash under
# $HOME/.osc, surviving across server restarts. Since we bootstrap a
# brand new admin user/token every run, a stale cache entry would make the
# SDK replay a token for a user id that no longer exists in the fresh DB
# (500s downstream). Point load_test at an isolated HOME (reset alongside
# the rest of STATE_DIR above) instead of touching the real ~/.osc.
LOADTEST_HOME="${STATE_DIR}/home"
mkdir -p "$LOADTEST_HOME"

tools/start-spire.sh

docker run -d --name loadtest_postgres \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
    -p 15432:5432 docker.io/postgres:17

for i in {1..30}; do
    if docker exec loadtest_postgres pg_isready -U postgres > /dev/null 2>&1; then
        echo "✅ Postgres is ready!"
        break
    fi
    sleep 1
done

cat <<EOF > "$CONFIG_FILE"
[api_policy]
opa_base_url = unix://${STATE_DIR}/opa.sock
enable = true
opa_policies_path = policy

[auth]
methods = password,token,openid,application_credential,x509

[DEFAULT]
debug = true
use_stderr = false
log_dir = ${STATE_DIR}

[database]
connection = ${DATABASE_URL}

[fernet_receipts]
key_repository = ${STATE_DIR}/etc/fernet-keys
[fernet_tokens]
key_repository = ${STATE_DIR}/etc/fernet-keys

[interface_admin]
socket_path = ${STATE_DIR}/keystone.sock
trust_domains = example.org
admin_svid = spiffe://example.org/keystone

[audit]
spool_dir = ${STATE_DIR}/audit
EOF

echo "2Rlc-npWYOGqqG1zM-bmfBj2apLacLXhIbBsdyqQ0zg=" > "${STATE_DIR}/etc/fernet-keys/0"

cargo build --release --bins

./target/release/keystone-manage -c "$CONFIG_FILE" db sync
./target/release/keystone-manage -c "$CONFIG_FILE" db up

KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 \
KEYSTONE_ALLOW_ENV_KEK=1 \
SPIFFE_ENDPOINT_SOCKET=$SPIFFE_ENDPOINT_SOCKET \
./target/release/keystone -c "$CONFIG_FILE" -vv > "${STATE_DIR}/rust.log" 2>&1 &
KEYSTONE_PID=$!
echo "$KEYSTONE_PID" > "${STATE_DIR}/keystone.pid"

URL_METRICS="http://127.0.0.1:8099"
for i in {1..30}; do
    if curl -s "${URL_METRICS}/health" > /dev/null; then
        echo "✅ Keystone health url started responding!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Server failed to start." >&2
        cat "${STATE_DIR}/rust.log" >&2
        exit 1
    fi
    sleep 0.5
done

until [ -S "${STATE_DIR}/keystone.sock" ]; do
    sleep 0.5
done
echo "✅ Keystone admin socket appeared!"

KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 \
KEYSTONE_ALLOW_ENV_KEK=1 \
SPIFFE_ENDPOINT_SOCKET=$SPIFFE_ENDPOINT_SOCKET \
./target/release/keystone-manage -c "$CONFIG_FILE" bootstrap --bootstrap-password password

echo "✅ Keystone bootstrap completed!"

(cd tests/loadtest && cargo build --release)

mkdir -p tests/loadtest/reports
(cd tests/loadtest && \
    HOME="$LOADTEST_HOME" \
    OS_AUTH_URL="http://localhost:8080/v3" \
    OS_USERNAME=admin \
    OS_PASSWORD=password \
    OS_USER_DOMAIN_NAME=default \
    OS_PROJECT_NAME=admin \
    OS_PROJECT_DOMAIN_NAME=default \
    ./target/release/load_test \
    --host http://localhost:8080 \
    "$@")
