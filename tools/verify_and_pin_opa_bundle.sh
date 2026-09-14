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
#
# Gate H, load side (security review V4, issue #984 follow-up): the publish
# job in `.github/workflows/policy-container.yml` signs the pushed OPA
# bundle by digest with cosign keyless signing and verifies its own
# signature before reporting success. That proves the bundle *left CI*
# correctly signed; it says nothing about what a running deployment
# actually *loads*, because OPA's own bundle downloader has no native
# cosign/Sigstore verification hook and `tools/opa_config.yaml` tracks the
# mutable `:latest` tag. This script is the missing other half:
#
#   1. Resolve the digest the given tag currently points at.
#   2. `cosign verify` that digest against this repository's GitHub Actions
#      OIDC identity -- the same check the publish job already performs on
#      itself, run again here as an independent, deployment-side check.
#   3. On success, rewrite `resource:` in the target OPA bundle config to
#      pin that verified digest instead of the mutable tag.
#
# Intended use: run this as an explicit, reviewed release step (a human or
# a controlled release pipeline invoking it, not a step that runs
# automatically on every push -- the digest changes on every policy merge,
# so "pin to latest verified digest" is a deliberate promotion action, not
# continuous rollout). A deployment that instead wants continuous rollout
# from `:latest` must run the equivalent `cosign verify` itself in an init
# container or admission hook before OPA starts serving traffic; this
# script is that same check, packaged so it can also be used to produce a
# pinned config for deployments that prefer promotion over continuous
# polling.
#
# Requires: oras, cosign, sed. Fails closed: any missing tool, resolve
# failure, or verification failure aborts before the config is touched.
set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $0 --repo <owner/repo> --tag <tag> [--config <path>]

  --repo    GitHub repository the bundle was published from, e.g.
            openstack-experimental/keystone. Used both to build the image
            reference and to constrain the cosign certificate-identity
            check to that repository's GitHub Actions OIDC issuer.
  --tag     Tag to resolve and verify, e.g. main or latest.
  --config  OPA bundle config file to pin (default: tools/opa_config.yaml).
            Pass /dev/null to only resolve+verify without rewriting a file.
EOF
    exit 1
}

repo=""
tag=""
config="$(dirname "$0")/opa_config.yaml"

while [ $# -gt 0 ]; do
    case "$1" in
        --repo) repo="$2"; shift 2 ;;
        --tag) tag="$2"; shift 2 ;;
        --config) config="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$repo" ] || usage
[ -n "$tag" ] || usage

for tool in oras cosign; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool '$tool' not found on PATH" >&2
        exit 1
    }
done

image="ghcr.io/${repo}/opa-bundle"
ref="${image}:${tag}"

echo "Resolving digest for ${ref} ..." >&2
digest="$(oras resolve "$ref")"
if [ -z "$digest" ]; then
    echo "error: failed to resolve a digest for ${ref}" >&2
    exit 1
fi
echo "Resolved: ${digest}" >&2

digest_ref="${image}@${digest}"
echo "Verifying cosign signature on ${digest_ref} ..." >&2
cosign verify \
    --certificate-identity-regexp "^https://github.com/${repo}/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$digest_ref" >&2

echo "Signature verified." >&2

if [ "$config" = "/dev/null" ]; then
    echo "$digest_ref"
    exit 0
fi

if [ ! -f "$config" ]; then
    echo "error: config file not found: $config" >&2
    exit 1
fi

# Replace the bundle `resource:` line's image reference (any tag or
# existing digest) with the freshly verified digest pin. Matches the
# `resource: ghcr.io/<repo>/opa-bundle:<tag-or-digest>` shape documented in
# tools/opa_config.yaml.
escaped_image=$(printf '%s\n' "$image" | sed 's/[.[\*^$/]/\\&/g')
sed -i.bak -E "s#(resource:[[:space:]]+)${escaped_image}(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]+)#\\1${digest_ref}#" "$config"
rm -f "${config}.bak"

echo "Pinned ${config} to ${digest_ref}" >&2
grep -n "resource:" "$config" >&2
