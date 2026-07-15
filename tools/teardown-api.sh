#!/usr/bin/env bash
set -e

STATE_DIR="/tmp/nextest/keystone"
PID_FILE="${STATE_DIR}/keystone.pid"
SPIRE_PID_DIR="/tmp/spire-ci-test-harness"

echo "Cleaning up server processes..."
if [ -f "$PID_FILE" ]; then
  echo "Killing Keystone process $(cat ${PID_FILE})"
  kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
fi
if [ -f "$SPIRE_PID_DIR/agent.pid" ]; then kill -9 "$(cat "$SPIRE_PID_DIR/agent.pid")" 2>/dev/null || true; fi
if [ -f "$SPIRE_PID_DIR/server.pid" ]; then kill -9 "$(cat "$SPIRE_PID_DIR/server.pid")" 2>/dev/null || true; fi

# `keystone`'s embedded OPA subprocess (crates/keystone/src/bin/keystone.rs
# `spawn_opa_subprocess`) is never signaled to stop on shutdown -- its
# owning task only awaits the child's own exit and never observes the
# server's shutdown cancellation token, so `kill -9` above orphans it every
# time. Kill it directly by its socket path for this STATE_DIR instead of
# relying on the parent's death to take it down.
pkill -9 -f "opa run -s .* --addr unix://${STATE_DIR}/opa.sock" 2>/dev/null || true

rm -rf /tmp/nextest/keystone/raft

echo "Cleanup complete. Logs preserved in $STATE_DIR and $SPIRE_PID_DIR."
