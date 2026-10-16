#!/usr/bin/env bash
# check_tls_provider.sh — guards for the TLS/crypto provider selection
#
# 1. The default (ring) dependency tree of the service binaries must not
#    contain aws-lc-rs / aws-lc-sys (issue #1534). aws-lc is opt-in through
#    the `rustls-aws-lc` / `fips` features.
# 2. No code outside crates/tls-provider may name a rustls crypto provider:
#    `openstack_keystone_tls_provider::{provider, install_default}` is the
#    single selection point.
#
# Exit 0 = clean; exit 1 = violations found.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

status=0

for pkg in aws-lc-rs aws-lc-sys; do
    # `cargo tree -i` exits non-zero both when the package is absent (the
    # wanted outcome) and on real errors, so tell them apart by the message.
    if out=$(cargo tree -p openstack-keystone -p openstack-keystone-cli-manage \
        -e normal,build -i "$pkg" 2>&1); then
        echo "ERROR: $pkg is in the default dependency tree:" >&2
        echo "$out" | head -20 >&2
        status=1
    elif ! grep -q 'did not match any packages' <<<"$out"; then
        echo "ERROR: cargo tree failed for $pkg:" >&2
        echo "$out" >&2
        status=1
    fi
done

if hits=$(git grep -nE 'rustls::crypto::(aws_lc_rs|ring)' -- crates tests \
    ':!crates/tls-provider'); then
    echo "ERROR: hardcoded rustls crypto provider; use" >&2
    echo "openstack_keystone_tls_provider::provider() instead:" >&2
    echo "$hits" >&2
    status=1
fi

exit "$status"
