#!/usr/bin/env bash
set -euo pipefail
#
# Runs tempest identity tests against a locally started Keystone server,
# without skaffold/k8s. This is the local-agent counterpart to the
# `tempest` skaffold module (skaffold.yaml, tools/Dockerfile.tempest,
# tools/tempest/run-tempest.sh) which only runs in-cluster.
#
# Reuses tools/start-api.sh to bring up SPIRE + OPA + Keystone exactly like
# `cargo nextest run --profile api -p test_api` does, then drives tempest
# directly from a local venv (no docker image needed) using the same
# tools/tempest/tempest.conf.template the CI container renders.
#
# Server is left running on exit (same behavior as start-api.sh) so repeat
# runs against the same server are cheap; use tools/teardown-api.sh to stop
# it, or just re-run this script which tears down and restarts fresh.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TEMPEST_REGEX="${TEMPEST_REGEX:-tempest\.api\.identity\.(v3|admin\.v3)\.}"
WORKSPACE="${TEMPEST_WORKSPACE:-/tmp/nextest/tempest-workspace}"
VENV_DIR="${TEMPEST_VENV:-/tmp/nextest/tempest-venv}"

# start-api.sh appends connection details (OS_*, KEYSTONE_URL, ...) as
# KEY=VALUE lines to $NEXTEST_ENV; give it a real file so we can source
# those vars even when not running under nextest.
export NEXTEST_ENV
NEXTEST_ENV="$(mktemp)"

echo "=== Starting Keystone (SPIRE + OPA + server) via tools/start-api.sh ==="
tools/start-api.sh

set -a
source "$NEXTEST_ENV"
set +a
# start-api.sh's bootstrap (crates/cli-manage/src/bootstrap.rs) registers
# the identity service under type "identity" with only a "public"
# interface endpoint - unlike the skaffold-deployed keystone-rs, which the
# shared template's catalog_type/v3_endpoint_type defaults (identity-rs /
# internal) target instead. Match what's actually in the catalog here.
export OS_IDENTITY_SERVICE_TYPE=identity

if [ ! -x "$VENV_DIR/bin/tempest" ]; then
  echo "=== Installing tempest into ${VENV_DIR} ==="
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/bin/pip" install --quiet tempest
fi

TEMPEST_WORKSPACE_NAME="$(basename "$WORKSPACE")"
if [ ! -f "$WORKSPACE/.stestr.conf" ]; then
  # `tempest init` also registers $TEMPEST_WORKSPACE_NAME -> $WORKSPACE in
  # ~/.tempest/workspace.yaml and refuses to re-init a name it already
  # knows, so drop any stale registration (e.g. from a run whose directory
  # was since removed) before creating a fresh one.
  sed -i "\#^${TEMPEST_WORKSPACE_NAME}:#d" ~/.tempest/workspace.yaml 2>/dev/null || true
  rm -rf "$WORKSPACE"
  mkdir -p "$WORKSPACE"
  "$VENV_DIR/bin/tempest" init "$WORKSPACE"
fi
envsubst <tools/tempest/tempest.conf.template >"$WORKSPACE/etc/tempest.conf"
# The template's log_file is hardcoded to /tempest/workspace, the fixed
# mount path inside the CI verify container (tools/Dockerfile.tempest);
# outside that container it must point at our real $WORKSPACE instead.
sed -i "s#/tempest/workspace#${WORKSPACE}#" "$WORKSPACE/etc/tempest.conf"
# Same reasoning as OS_IDENTITY_SERVICE_TYPE above: the template's
# v3_endpoint_type is hardcoded to "internal" for the skaffold deployment;
# start-api.sh's bootstrap only registers a "public" endpoint.
sed -i "s#^v3_endpoint_type = internal#v3_endpoint_type = public#" "$WORKSPACE/etc/tempest.conf"
# The template's admin_domain_name is hardcoded to "Default" to match
# keystone-py's bootstrap (used by skaffold/devstack targets); the rust
# bootstrap here (crates/cli-manage/src/bootstrap.rs) names it "default"
# (lowercase), and domain lookup is case-sensitive.
sed -i "s#^admin_domain_name = Default#admin_domain_name = default#" "$WORKSPACE/etc/tempest.conf"

cd "$WORKSPACE"

echo "=== Running tempest identity tests against ${OS_AUTH_URL} (regex=${TEMPEST_REGEX}) ==="
set +e
"$VENV_DIR/bin/tempest" run --config-file "$WORKSPACE/etc/tempest.conf" --regex "$TEMPEST_REGEX"
RESULT=$?
set -e

echo ""
echo "===== FAILED TESTS ====="
"$VENV_DIR/bin/stestr" failing --list >/tmp/tempest-failed-tests.txt 2>/dev/null || true
if [ -s /tmp/tempest-failed-tests.txt ]; then
  cat /tmp/tempest-failed-tests.txt
else
  echo "(none)"
fi
echo "===== END FAILED TESTS ====="

exit "$RESULT"
