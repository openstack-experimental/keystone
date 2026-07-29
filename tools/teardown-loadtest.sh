#!/usr/bin/env bash

STATE_DIR="/tmp/loadtest/keystone"
PID_FILE="${STATE_DIR}/keystone.pid"
SPIRE_PID_DIR="/tmp/spire-ci-test-harness"

echo "Cleaning up loadtest server process..."
if [ -f "$PID_FILE" ]; then
  echo "Killing Keystone process $(cat "${PID_FILE}")"
  kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
fi

if [ -f "$SPIRE_PID_DIR/agent.pid" ]; then kill -9 "$(cat "$SPIRE_PID_DIR/agent.pid")" 2>/dev/null || true; fi
if [ -f "$SPIRE_PID_DIR/server.pid" ]; then kill -9 "$(cat "$SPIRE_PID_DIR/server.pid")" 2>/dev/null || true; fi

# `keystone`'s embedded OPA subprocess is never signaled to stop on shutdown,
# see tools/teardown-api.sh -- kill it directly by its socket path.
pkill -9 -f "opa run -s .* --addr unix://${STATE_DIR}/opa.sock" 2>/dev/null || true

docker rm -f loadtest_postgres 2>/dev/null || true

echo "Cleanup complete. Logs preserved in $STATE_DIR."
