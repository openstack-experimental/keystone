#!/usr/bin/env bash
set -euo pipefail

# Starts a throwaway local `slapd` (OpenLDAP) instance for the LDAP identity
# driver's functional tests (crates/identity-driver-ldap), seeded from
# tests/fixtures/base.ldif. Runs as a plain local process, not a container --
# no Docker daemon is required or used, matching tools/start-api.sh's
# pattern of spawning real daemons directly for nextest setup scripts.
#
# Requires the `slapd`/`ldap-utils` Debian/Ubuntu packages (or equivalent):
#   apt-get install -y slapd ldap-utils

STATE_DIR="/var/tmp/nextest/keystone-ldap"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/identity-driver-ldap/tests/fixtures"
LDAP_HOST="127.0.0.1"
LDAP_PORT="3890"
LDAP_URL="ldap://${LDAP_HOST}:${LDAP_PORT}"
BASE_DN="dc=example,dc=com"
ADMIN_DN="cn=admin,${BASE_DN}"
ADMIN_PW="adminpw"

tools/teardown-ldap-test.sh || true
rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR/data" "$STATE_DIR/run" "$STATE_DIR/fixtures"

# slapd runs under an AppArmor profile (usr.sbin.slapd) on Debian/Ubuntu that
# only grants read/write access to /etc/ldap, /var/lib/ldap and /var/tmp --
# it cannot read files from an arbitrary repo checkout path. Copy the
# fixtures it needs to open directly (schema, ldif) into STATE_DIR, which
# lives under /var/tmp and is therefore covered by the profile.
cp "${FIXTURES_DIR}/keystone-test.schema" "${FIXTURES_DIR}/base.ldif" "$STATE_DIR/fixtures/"

cat > "$STATE_DIR/slapd.conf" <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
include ${STATE_DIR}/fixtures/keystone-test.schema

modulepath /usr/lib/ldap
moduleload back_mdb.so

pidfile ${STATE_DIR}/run/slapd.pid
argsfile ${STATE_DIR}/run/slapd.args

database mdb
maxsize 1073741824
suffix "${BASE_DN}"
rootdn "${ADMIN_DN}"
rootpw "${ADMIN_PW}"
directory ${STATE_DIR}/data
EOF

> "$STATE_DIR/slapd.log" 2>&1 /usr/sbin/slapd -f "$STATE_DIR/slapd.conf" -h "${LDAP_URL}/" -d config,acl,trace &
SLAPD_BG_PID=$!
disown

# slapd forks into the background and (re)writes its own pidfile; wait for
# that rather than trusting $! or a fixed sleep.
for _ in $(seq 1 50); do
  [ -s "$STATE_DIR/run/slapd.pid" ] && break
  sleep 0.1
done
if [ ! -s "$STATE_DIR/run/slapd.pid" ]; then
  echo "slapd did not start (no pidfile written)" >&2
  echo "--- $STATE_DIR/slapd.log ---" >&2
  cat "$STATE_DIR/slapd.log" >&2 || true
  echo "--- dmesg | grep -i apparmor (last 20) ---" >&2
  (sudo -n dmesg 2>/dev/null || dmesg 2>/dev/null) | grep -i apparmor | tail -20 >&2 || true
  echo "--- aa-status (slapd) ---" >&2
  (command -v aa-status >/dev/null 2>&1 && (sudo -n aa-status 2>&1 || aa-status 2>&1) | grep -A1 slapd) >&2 || true
  kill "$SLAPD_BG_PID" 2>/dev/null || true
  exit 1
fi

for _ in $(seq 1 50); do
  if ldapsearch -x -H "$LDAP_URL" -b "" -s base "(objectclass=*)" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

ldapadd -x -H "$LDAP_URL" -D "$ADMIN_DN" -w "$ADMIN_PW" -f "${STATE_DIR}/fixtures/base.ldif"

if [ -n "${NEXTEST_ENV:-}" ]; then
  {
    echo "KEYSTONE_LDAP_TEST_URL=${LDAP_URL}"
    echo "KEYSTONE_LDAP_TEST_BASE_DN=${BASE_DN}"
    echo "KEYSTONE_LDAP_TEST_ADMIN_DN=${ADMIN_DN}"
    echo "KEYSTONE_LDAP_TEST_ADMIN_PW=${ADMIN_PW}"
  } >> "$NEXTEST_ENV"
fi

echo "Test slapd instance ready at ${LDAP_URL} (base ${BASE_DN})"
