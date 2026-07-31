#!/usr/bin/env bash
# Samples `kubectl top` (keystone-rs/keystone-py pods + node) and host
# free/loadavg on a fixed interval, for correlating memory/CPU behavior with
# a concurrent tools/run-loadtest-local.sh or manual `load_test` run against
# the skaffold k3s deployment (see AGENTS.md "Running loadtests locally").
#
# Requires a working `kubectl` context pointed at the cluster under test and
# metrics-server installed (`kubectl top nodes` must already work standalone).
#
# Usage: run in the background around your loadtest invocation, then kill it
# once the loadtest finishes:
#
#   ./sample_metrics.sh /tmp/metrics.log 3 &
#   SAMPLER=$!
#   OS_CLOUD=ciab-rs ./target/release/load_test --host http://keystone-rs.local \
#     --users 50 --hatch-rate 10 --run-time 90s --report-file reports/run.md
#   kill "$SAMPLER"
#
# Args: $1 output file (required), $2 sample interval in seconds (default 3).
#
# Output is plain text blocks separated by "=== <unix-ts> ===", one block per
# sample; parse per-pod min/max/avg memory with e.g.:
#
#   awk -v p="keystone-rs-0" '$1==p {gsub("Mi","",$3); print $3}' metrics.log \
#     | awk '{s+=$1; if(min==""||$1<min)min=$1; if($1>max)max=$1; n++}
#            END{printf "min=%dMi max=%dMi avg=%.0fMi\n", min, max, s/n}'
set -u
OUT="${1:?output file}"
INTERVAL="${2:-3}"
: > "$OUT"
while true; do
  ts=$(date +%s)
  {
    echo "=== $ts ==="
    kubectl top pods -l app.kubernetes.io/name=keystone-rs --no-headers 2>/dev/null
    kubectl top pods -l app.kubernetes.io/name=keystone-py --no-headers 2>/dev/null
    kubectl top nodes --no-headers 2>/dev/null
    free -m | awk 'NR==2{print "host_mem_used_mb="$3, "host_mem_total_mb="$2}'
    awk '{print "loadavg="$1,$2,$3}' /proc/loadavg
  } >> "$OUT"
  sleep "$INTERVAL"
done
