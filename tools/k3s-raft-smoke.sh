#!/usr/bin/env bash
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Smoke test for the single-voter Raft KEK overlays on k3s
# (tools/k8s/keystone/overlays/k3s-test, skaffold-k3s-test.yaml).
#
# Expects the overlay to be deployed already. It authenticates as the
# bootstrapped admin user, restarts the pod so the KEK provider has to
# unwrap the persisted DEK again, and checks that the token issued before
# the restart is still valid and that a new one can be issued.
#
# Environment:
#   NAMESPACE  namespace of the overlay (default: keystone-raft-test)
#   LOCAL_PORT local port for the port-forward (default: 18080)
set -euo pipefail

NAMESPACE="${NAMESPACE:-keystone-raft-test}"
LOCAL_PORT="${LOCAL_PORT:-18080}"
BASE_URL="http://127.0.0.1:${LOCAL_PORT}"
PF_PID=""

cleanup() {
  if [[ -n "${PF_PID}" ]]; then
    kill "${PF_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

start_port_forward() {
  cleanup
  kubectl -n "${NAMESPACE}" port-forward svc/keystone-rs \
    "${LOCAL_PORT}:8080" >/dev/null 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 30); do
    if curl -sf -o /dev/null "${BASE_URL}/v3"; then
      return 0
    fi
    sleep 1
  done
  echo "keystone did not answer on ${BASE_URL}/v3" >&2
  return 1
}

# Prints the issued token (X-Subject-Token) on stdout.
issue_token() {
  local headers
  headers="$(curl -sf -D - -o /dev/null \
    -H 'Content-Type: application/json' \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{
          "name":"admin","domain":{"id":"default"},"password":"password"}}},
        "scope":{"project":{"name":"admin","domain":{"id":"default"}}}}}' \
    "${BASE_URL}/v3/auth/tokens")"
  awk 'tolower($1)=="x-subject-token:" {gsub(/\r/,"",$2); print $2}' \
    <<<"${headers}"
}

# Fails unless keystone accepts the token as its own subject.
validate_token() {
  curl -sf -o /dev/null \
    -H "X-Auth-Token: $1" -H "X-Subject-Token: $1" \
    "${BASE_URL}/v3/auth/tokens"
}

echo "== authenticating before restart"
start_port_forward
TOKEN="$(issue_token)"
[[ -n "${TOKEN}" ]] || { echo "no token issued" >&2; exit 1; }
validate_token "${TOKEN}"

echo "== restarting keystone-rs"
cleanup
PF_PID=""
kubectl -n "${NAMESPACE}" rollout restart statefulset/keystone-rs
kubectl -n "${NAMESPACE}" rollout status statefulset/keystone-rs --timeout=300s

echo "== authenticating after restart"
start_port_forward
validate_token "${TOKEN}"
NEW_TOKEN="$(issue_token)"
[[ -n "${NEW_TOKEN}" ]] || { echo "no token issued after restart" >&2; exit 1; }
validate_token "${NEW_TOKEN}"

echo "smoke test passed"
