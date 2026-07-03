#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURATION ---
TRUST_DOMAIN="example.org"
# Fixed, predictable directory so other projects/scripts know exactly where it is
DIR="/tmp/spire-ci-test-harness"
SERVER_SOCKET="$DIR/server.sock"
AGENT_SOCKET="$DIR/agent.sock"

# Force a clean slate before starting to prevent pollution from old runs
echo "🧹 Wiping old SPIRE state and setting up workspace..."
rm -rf "$DIR"
mkdir -p "$DIR"

# --- 1. GENERATE CONFIGURATIONS ---
echo "📝 Generating SPIRE configurations in $DIR..."

cat << EOF > "$DIR/server.conf"
server {
    bind_address = "127.0.0.1"
    bind_port = "13081"
    trust_domain = "$TRUST_DOMAIN"
    data_dir = "$DIR"
    log_level = "WARN"
    socket_path = "$SERVER_SOCKET"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$DIR/datastore.sqlite3"
        }
    }
    KeyManager "disk" {
        plugin_data {
            keys_path = "$DIR/keys.json"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
}
EOF

cat << EOF > "$DIR/agent.conf"
agent {
    data_dir = "$DIR"
    log_level = "WARN"
    server_address = "127.0.0.1"
    server_port = "13081"
    socket_path = "$AGENT_SOCKET"
    trust_domain = "$TRUST_DOMAIN"
    insecure_bootstrap = true
}
plugins {
    KeyManager "memory" {
        plugin_data {}
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF

# --- 2. START SPIRE SERVER ---
echo "🚀 Starting SPIRE Server..."
spire-server run -config "$DIR/server.conf" > "$DIR/server.log" 2>&1 &
echo "$!" > "$DIR/server.pid"

# Wait for server to become healthy
until spire-server healthcheck -socketPath "$SERVER_SOCKET" >/dev/null 2>&1; do
    echo "⏱️ Waiting for SPIRE server..."
    sleep 0.5
done
# --- 3. AUTOMATIC AGENT ATTESTATION ---

echo "🔑 Generating join token..."
# Generate token and isolate just the string token value
TOKEN=$(spire-server token generate \
    -spiffeID "spiffe://$TRUST_DOMAIN/agent" \
    -socketPath "$SERVER_SOCKET" | awk '{print $2}')

# --- 3. INSECURE AGENT START ---
echo "🚀 Starting SPIRE Agent via Insecure Bootstrap..."
spire-agent run -config "$DIR/agent.conf" -joinToken ${TOKEN} > "$DIR/agent.log" 2>&1 &
echo "$!" > "$DIR/agent.pid"

# Wait for agent to become healthy
until spire-agent healthcheck -socketPath "$AGENT_SOCKET" >/dev/null 2>&1; do
    echo "⏱️ Waiting for SPIRE agent..."
    sleep 0.5
done

# --- 4. AUTOMATIC WORKLOAD REGISTRATION ---
echo "📌 Registering CI workload entry..."
CURRENT_UID=$(id -u)

spire-server entry create \
    -socketPath "$SERVER_SOCKET" \
    -parentID "spiffe://$TRUST_DOMAIN/agent" \
    -spiffeID "spiffe://$TRUST_DOMAIN/keystone" \
    -selector "unix:uid:$CURRENT_UID"

echo "✅ SPIRE is fully initialized and running in the background!"
echo "📍 Agent Socket available at: $AGENT_SOCKET"
