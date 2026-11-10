#!/usr/bin/env bash
set -e

STATE_DIR="/var/tmp/nextest/keystone-ldap"
PID_FILE="${STATE_DIR}/run/slapd.pid"

if [ -f "$PID_FILE" ]; then
  echo "Killing test slapd process $(cat "$PID_FILE")"
  PID="$(cat "$PID_FILE")"
  kill "$PID" 2>/dev/null || true
  # Wait for the process to actually exit: slapd removes its pidfile on
  # shutdown, and a replacement instance started too early would lose its
  # own pidfile to the dying one.
  for _ in $(seq 1 50); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$PID" 2>/dev/null || true
fi
