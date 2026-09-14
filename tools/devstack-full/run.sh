#!/usr/bin/env bash
# Local-runnable replica of the devstack-full CI job
# (.github/workflows/devstack.yml, devstack-full: steps 337-488).
#
# Meant to run *inside* a throwaway VM/host with nested KVM (see
# tools/devstack-full/README.md for the recommended virt-install setup) -
# it is destructive to /opt/stack and installs system packages/services.
# Never run it against a machine you care about.
#
# Unlike the CI job, this does NOT go through devstack's file:// git clone
# of the key-rs plugin (which only sees committed refs). Instead it rsyncs
# the *current working tree* - staged, unstaged, untracked included - into
# $DEST/key-rs before stack.sh runs. devstack's git_clone() is a no-op
# whenever the destination directory already exists (functions-common,
# RECLONE defaults to False), so pre-populating it this way makes devstack
# skip cloning entirely and just use what's there. No commit, no push, no
# branch ref required - re-running this script re-syncs and re-stacks.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="/opt/stack"
BIN_DIR=""
SKIP_BUILD=false
SKIP_SMOKE=false
SKIP_VERIFY=false
RESTACK=false

usage() {
    cat <<EOF
Usage: $0 [options]

  --workspace DIR   keystone-rs worktree to install (default: repo this
                     script lives in, $WORKSPACE)
  --bin-dir DIR     pre-built keystone/keystone-manage binaries; skips the
                     cargo build step (default: build target/release here)
  --skip-build      reuse WORKSPACE/target/release without rebuilding
  --skip-smoke      skip the cirros boot/delete smoke test (lite mode)
  --skip-verify     skip all post-stack verification/smoke steps
  --restack         wipe \$DEST and devstack's own state before re-stacking
                     (devstack's own unstack/clean, not just our rsync)
  -h, --help        show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace) WORKSPACE="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --skip-smoke) SKIP_SMOKE=true; shift ;;
        --skip-verify) SKIP_VERIFY=true; shift ;;
        --restack) RESTACK=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$BIN_DIR" ]] && [[ "$SKIP_BUILD" == false ]]; then
    echo "==> Building keystone-rs release binaries"
    (cd "$WORKSPACE" && cargo build --release -p openstack-keystone -p openstack-keystone-cli-manage)
    BIN_DIR="$WORKSPACE/target/release"
elif [[ -z "$BIN_DIR" ]]; then
    BIN_DIR="$WORKSPACE/target/release"
fi
for bin in keystone keystone-manage; do
    test -x "$BIN_DIR/$bin" || { echo "missing $BIN_DIR/$bin (build first or pass --bin-dir)" >&2; exit 1; }
done

if [[ "$RESTACK" == true ]] && [[ -x "$DEST/devstack/unstack.sh" ]]; then
    echo "==> Tearing down previous stack"
    (cd "$DEST/devstack" && ./unstack.sh || true)
    sudo "$DEST/devstack/clean.sh" || true
fi

# On a fresh disposable VM, $DEST pre-exists root-owned (or doesn't exist
# yet); devstack's own git_clone calls (e.g. for openstack/requirements)
# run unprivileged as $USER and fail with "Permission denied" creating
# their destination dir under $DEST unless $DEST itself is writable first.
sudo mkdir -p "$DEST"
sudo chown "$USER" "$DEST"

if [[ ! -d "$DEST/devstack/.git" ]]; then
    echo "==> Cloning devstack"
    sudo git clone https://opendev.org/openstack/devstack "$DEST/devstack"
    sudo chown -R "$USER" "$DEST/devstack"
fi

echo "==> Syncing local keystone-rs worktree into $DEST/key-rs"
sudo mkdir -p "$DEST/key-rs"
sudo rsync -a --delete \
    --exclude .git \
    --exclude target \
    --exclude tests/loadtest/target \
    "$WORKSPACE"/ "$DEST/key-rs"/
sudo chown -R "$USER" "$DEST/key-rs"

echo "==> Syncing SPIRE devstack plugin into $DEST/spire"
sudo mkdir -p "$DEST/spire/devstack"
sudo cp -rT "$WORKSPACE/tools/devstack-plugin-spire" "$DEST/spire/devstack"
sudo chown -R "$USER" "$DEST/spire"

echo "==> Writing local.conf"
cat <<EOF | sudo tee "$DEST/devstack/local.conf" >/dev/null
[[local|localrc]]
ADMIN_PASSWORD=password
DATABASE_PASSWORD=password
RABBIT_PASSWORD=password
SERVICE_PASSWORD=password
SERVICE_TOKEN=service-token
GIT_BASE=https://github.com

disable_all_services
enable_service mysql
enable_service rabbit
enable_service key
enable_service key-rs
enable_service tempest
enable_service spire

# Nova (+ placement, a hard Nova dependency in modern devstack)
enable_service n-api n-cpu n-sch n-cond n-novnc n-crt n-api-meta
enable_service placement-api placement-client
# Cinder (c-vol defaults to an LVM-over-loopback backend when no
# CINDER_DRIVER is set - no real block device needed)
enable_service c-api c-sch c-vol
# Glance
enable_service g-api
# Neutron with OVN (devstack's default ML2 mechanism driver since 2023).
# The legacy agents (q-agt/q-dhcp/q-l3/q-meta) are mutually exclusive with
# OVN - devstack's ovn_sanity_check aborts the run if any of them is
# enabled. OVN's own services must be listed explicitly because
# disable_all_services drops stackrc's defaults.
enable_service q-svc q-ovn-agent
enable_service ovn-controller ovn-northd ovs-vswitchd ovsdb-server

# Both plugin dirs already exist (rsynced above), so devstack's git_clone
# skips cloning and uses the local working tree as-is - the "local" ref
# below is unused in that case, just a placeholder enable_plugin requires.
enable_plugin spire file://$DEST/spire local
enable_plugin key-rs file://$DEST/key-rs local

SPIRE_TRUST_DOMAIN=cloud.trust.domain

KEYSTONE_RS_BIN_DIR=$BIN_DIR

LOGFILE=\$HOME/devstack.log
LOG_COLOR=False
EOF
cat "$DEST/devstack/local.conf"

echo "==> Running stack.sh"
(cd "$DEST/devstack" && FORCE=yes ./stack.sh)

if [[ "$SKIP_VERIFY" == true ]]; then
    echo "==> Stack up, skipping verification (--skip-verify)"
    exit 0
fi

echo "==> Verifying rust Keystone is serving directly"
curl -sf http://127.0.0.1:8080/v3 >/dev/null

echo "==> Issuing a token via the openstack CLI"
source "$DEST/devstack/openrc" admin admin
openstack token issue

echo "==> Verifying OpenStack service health"
openstack compute service list
openstack volume service list
openstack image list
openstack network agent list
# devstack no longer binds per-service ports (8774/8776/9292/9696): all
# APIs are proxied by a single Apache on port 80 via URL path prefixes.
# -f is omitted on purpose: unauthenticated requests get 3xx/401 back,
# which still proves the API is up and answering.
curl -s -o /dev/null http://127.0.0.1/compute/
curl -s -o /dev/null http://127.0.0.1/volume/v3/
curl -s -o /dev/null http://127.0.0.1/image/
curl -s -o /dev/null http://127.0.0.1/networking/

if [[ "$SKIP_SMOKE" == false ]]; then
    echo "==> Smoke test - boot and delete a cirros instance"
    image_id=$(openstack image list -f value -c ID | head -n1)
    network_id=$(openstack network list -f value -c ID --long -c "Name" | awk '$0 !~ /public/ {print $1; exit}')
    openstack server create --image "$image_id" \
        --flavor cirros256 --network "$network_id" smoke-test --wait
    openstack server delete smoke-test --wait
fi

echo "==> Verifying SPIRE server and agent are healthy"
/usr/local/bin/spire-server healthcheck -socketPath "$DEST/data/spire/server.sock"
/usr/local/bin/spire-agent healthcheck -socketPath "$DEST/data/spire/agent.sock"

echo "==> Verifying pre-registered SPIRE entries exist"
/usr/local/bin/spire-server entry show -socketPath "$DEST/data/spire/server.sock" | tee /tmp/spire-entries.txt
grep -q "service/keystone" /tmp/spire-entries.txt
grep -q "service/nova-api" /tmp/spire-entries.txt
grep -q "service/neutron" /tmp/spire-entries.txt
grep -q "service/cinder" /tmp/spire-entries.txt
grep -q "service/glance" /tmp/spire-entries.txt
grep -q "service/nova-compute/host/" /tmp/spire-entries.txt

echo "==> Verifying SPIRE CA bundle was exported"
test -s /etc/keystone/spiffe/ca.crt

echo "==> Verifying spiffe-helper processes are running"
for svc in nova cinder glance neutron; do
    sudo systemctl is-active "devstack@spiffe-helper-$svc"
done

echo "==> Verifying spiffe-helper certs were issued and are valid"
# SPIRE does not put the SPIFFE ID in the cert's Subject (it is C=US,
# O=SPIRE) - the identity lives in the URI SAN. So assert the exact
# per-service identity each helper is pinned to, and verify the SVID
# chains to the trust bundle the helper stored alongside it.
for pair in nova:nova-api cinder:cinder glance:glance neutron:neutron; do
    svc=${pair%%:*}
    dir="$DEST/data/spire/certs/$svc"
    openssl x509 -in "$dir/tls.crt" -noout -checkend 0
    openssl verify -CAfile "$dir/ca.crt" "$dir/tls.crt"
    openssl x509 -in "$dir/tls.crt" -noout -text | grep -q "URI:spiffe://cloud.trust.domain/service/${pair#*:}"
done

echo "==> devstack-full OK"
