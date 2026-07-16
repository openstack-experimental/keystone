#!/usr/bin/env bash
#
# Entrypoint for the tempest-identity skaffold verify container.
#
# Runs tempest's identity v3 tests against the Keystone deployment pointed
# to by the OS_* env vars, and prints the list of failing test IDs so
# compatibility gaps are visible in the pod's log stream. The real tempest
# exit code is preserved - this script itself never swallows failures; the
# CI job decides separately (via a non-blocking step) not to gate on it, so
# behavior here is identical whether run locally or in CI.
set -u

: "${OS_AUTH_URL:?OS_AUTH_URL is required}"
: "${OS_USERNAME:?OS_USERNAME is required}"
: "${OS_PASSWORD:?OS_PASSWORD is required}"
: "${OS_USER_DOMAIN_ID:?OS_USER_DOMAIN_ID is required}"
: "${OS_PROJECT_NAME:?OS_PROJECT_NAME is required}"
: "${OS_PROJECT_DOMAIN_ID:?OS_PROJECT_DOMAIN_ID is required}"

TEMPEST_TARGET="${TEMPEST_TARGET:-unknown}"
TEMPEST_REGEX="${TEMPEST_REGEX:-tempest\.api\.identity\.(v3|admin\.v3)\.}"
WORKSPACE=/tempest/workspace

export OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_USER_DOMAIN_ID OS_PROJECT_NAME OS_PROJECT_DOMAIN_ID

mkdir -p "${WORKSPACE}"
tempest init "${WORKSPACE}"
envsubst </etc/tempest/tempest.conf.template >"${WORKSPACE}/etc/tempest.conf"

cd "${WORKSPACE}"

echo "=== Running tempest identity tests against target=${TEMPEST_TARGET} (${OS_AUTH_URL}) ==="
tempest run --config-file "${WORKSPACE}/etc/tempest.conf" --regex "${TEMPEST_REGEX}"
RESULT=$?

echo ""
echo "===== FAILED TESTS (target=${TEMPEST_TARGET}) ====="
stestr failing --list >/tmp/failed-tests.txt 2>/dev/null
if [ -s /tmp/failed-tests.txt ]; then
  cat /tmp/failed-tests.txt
else
  echo "(none)"
fi
echo "===== END FAILED TESTS (target=${TEMPEST_TARGET}) ====="

exit "${RESULT}"
