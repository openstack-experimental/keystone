#!/usr/bin/env bash
# check_no_dev_mode.sh — deployment safety check for ADR 0016-v2 §11
#
# Runs in CI (`linters.yml`, job `no-dev-mode`) and should also be run from the
# deployment pipeline.
#
# Scans Dockerfiles, Kubernetes manifests, and systemd unit files for flags
# that must never appear in production deployments:
#   --dev-mode
#   dev_mode (config key)
#   KEYSTONE_ALLOW_ENV_KEK
#   KEYSTONE_DEV_KEK
#
# Source trees (`crates/`, where the flags appear in code comments and tests)
# and explicitly allow-listed development artefacts (see ALLOWED_PATHS) are not
# scanned.
#
# Exit 0 = clean; exit 1 = violations found.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATTERNS=(
    '--dev-mode'
    'dev_mode'
    'KEYSTONE_ALLOW_ENV_KEK'
    'KEYSTONE_DEV_KEK'
)

FILE_GLOBS=(
    'Dockerfile*'
    '*.yaml'
    '*.yml'
    '*.service'
    '*.conf'
    '*.toml'
)

# Repo-relative path prefixes that are excluded from the scan.
ALLOWED_PATHS=(
    'crates/'
    'doc/'
    'tools/k8s/keystone/overlays/skaffold/'
    'tools/k8s/tests/'
)

is_allowed() {
    local rel="${1#"${REPO_ROOT}/"}"
    local prefix
    for prefix in "${ALLOWED_PATHS[@]}"; do
        [[ "${rel}" == "${prefix}"* ]] && return 0
    done
    return 1
}

violations=0

for glob in "${FILE_GLOBS[@]}"; do
    while IFS= read -r -d '' file; do
        if is_allowed "${file}"; then
            continue
        fi
        for pattern in "${PATTERNS[@]}"; do
            if grep -q "${pattern}" "${file}" 2>/dev/null; then
                echo "VIOLATION: '${pattern}' found in ${file}" >&2
                violations=$((violations + 1))
            fi
        done
    done < <(find "${REPO_ROOT}" -name "${glob}" -not -path "*/target/*" -not -path "*/.github/*" -print0 2>/dev/null)
done

if [ "${violations}" -gt 0 ]; then
    echo "ERROR: ${violations} dev-mode violation(s) detected. Remove --dev-mode, dev_mode," >&2
    echo "       KEYSTONE_ALLOW_ENV_KEK and KEYSTONE_DEV_KEK from all deployment artifacts before shipping." >&2
    exit 1
fi

echo "OK: no dev-mode flags found in deployment files."
