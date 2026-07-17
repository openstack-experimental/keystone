#!/usr/bin/env bash
set -e

STATE_DIR="/var/tmp/nextest/keystone-ldap"
PID_FILE="${STATE_DIR}/run/slapd.pid"

if [ -f "$PID_FILE" ]; then
  echo "Killing test slapd process $(cat "$PID_FILE")"
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
