#!/usr/bin/env bash
set -e

STATE_DIR="/tmp/nextest/keystone"
PID_FILE="${STATE_DIR}/keystone.pid"
SPIRE_PID_DIR="/tmp/spire-ci-test-harness"

echo "Cleaning up server processes..."
if [ -f "$PID_FILE" ]; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
if [ -f "$SPIRE_PID_DIR/agent.pid" ]; then kill "$(cat "$SPIRE_PID_DIR/agent.pid")" 2>/dev/null || true; fi
if [ -f "$SPIRE_PID_DIR/server.pid" ]; then kill "$(cat "$SPIRE_PID_DIR/server.pid")" 2>/dev/null || true; fi

echo "Cleanup complete. Logs preserved in $STATE_DIR and $SPIRE_PID_DIR."
