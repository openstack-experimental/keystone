#!/usr/bin/env bash
# check_no_dev_mode.sh — CI safety gate for ADR 0016-v2 §11
#
# Scans Dockerfiles, Kubernetes manifests, and systemd unit files for flags
# that must never appear in production deployments:
#   --dev-mode
#   KEYSTONE_ALLOW_ENV_KEK
#
# Exit 0 = clean; exit 1 = violations found.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATTERNS=(
    '--dev-mode'
    'KEYSTONE_ALLOW_ENV_KEK'
)

FILE_GLOBS=(
    'Dockerfile*'
    '*.yaml'
    '*.yml'
    '*.service'
    '*.conf'
)

violations=0

for glob in "${FILE_GLOBS[@]}"; do
    while IFS= read -r -d '' file; do
        for pattern in "${PATTERNS[@]}"; do
            if grep -q "${pattern}" "${file}" 2>/dev/null; then
                echo "VIOLATION: '${pattern}' found in ${file}" >&2
                violations=$((violations + 1))
            fi
        done
    done < <(find "${REPO_ROOT}" -name "${glob}" -not -path "*/target/*" -print0 2>/dev/null)
done

if [ "${violations}" -gt 0 ]; then
    echo "ERROR: ${violations} dev-mode violation(s) detected. Remove --dev-mode and" >&2
    echo "       KEYSTONE_ALLOW_ENV_KEK from all deployment artifacts before shipping." >&2
    exit 1
fi

echo "OK: no dev-mode flags found in deployment files."
