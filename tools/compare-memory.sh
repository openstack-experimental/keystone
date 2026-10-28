#!/usr/bin/env bash
# Compare the memory profile of keystone-rs and keystone-py under the same
# workload (skaffold k3s deployment, see doc/src/contributor/development.md).
#
# keystone-py has no /v4 API, so the loadtest is restricted to the /v3
# scenarios both implementations serve (goose `--scenarios`, substring match
# on the lower-cased scenario name). Both targets share the Postgres of the
# deployment, so the same admin credentials work against either.
#
# Per sample (every INTERVAL seconds) and per pod the CSV gets:
#   ts,target,pod,working_set_mib,rss_mib,rss_anon_mib,rss_file_mib
# - working_set_mib: `kubectl top` of the keystone container (what the kubelet OOM-kills on)
# - rss_*: summed over every process of the container from /proc/<pid>/status
#   (uwsgi master + workers for keystone-py, a single process for keystone-rs).
#   RssAnon is heap/allocator memory, RssFile is mapped binaries/libs; a leak
#   or allocator fragmentation shows in RssAnon.
#
# Usage:
#   OS_PASSWORD=... tools/compare-memory.sh [options]
#     --run-time 30m     load duration per target (default 15m)
#     --users 50         goose users (default 50)
#     --mode seq|par     run targets one after the other (default, cleaner CPU
#                        comparison) or at the same time
#     --targets rs,py    (default both)
#     --interval 15      sample interval, seconds
#     --think-ms 250     read-scenario think time (LOADTEST_THINK_MS, default 250;
#                        0 = flat out)
#     --out DIR          default: reports/memory-<timestamp>
#
# Env: OS_PASSWORD (required), OS_USERNAME (admin), OS_PROJECT_NAME (admin),
#      RS_URL (http://keystone-rs.local), PY_URL (http://keystone-py.local),
#      LOAD_TEST (path to the load_test binary, default
#      tests/loadtest/target/release/load_test), NAMESPACE (kubectl default).
#
# Run it in the background and read the output files (never pipe through
# `tail`, the goose process would keep the pipe open).
set -euo pipefail

RUN_TIME=15m; USERS=50; MODE=seq; TARGETS=rs,py; INTERVAL=15; THINK_MS=250
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --run-time) RUN_TIME="$2"; shift 2;;
    --users) USERS="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --targets) TARGETS="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    --think-ms) THINK_MS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
: "${OS_PASSWORD:?set OS_PASSWORD (admin password)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOAD_TEST="${LOAD_TEST:-$ROOT/tests/loadtest/target/release/load_test}"
OUT="${OUT:-$ROOT/tests/loadtest/reports/memory-$(date +%Y%m%d-%H%M%S)}"
NS=(); [ -n "${NAMESPACE:-}" ] && NS=(-n "$NAMESPACE")
mkdir -p "$OUT"
[ -x "$LOAD_TEST" ] || { echo "build it: (cd tests/loadtest && cargo build --release)" >&2; exit 1; }

# Scenarios that exist on both implementations (/v3 only).
SCENARIOS="readheavy,tokenlifecycle,validatetoken,usercrud,projectcrud,rolecrud,groupchurn,catalogchurn,credentialchurn,trustchurn,identitychurn,rolelist,roleassignmentlist,userread,projectread,passwordauth,rescope,systemscopeauth"

selector() { case "$1" in rs) echo app.kubernetes.io/name=keystone-rs;; py) echo app.kubernetes.io/name=keystone-py;; esac; }
url() { case "$1" in rs) echo "${RS_URL:-http://keystone-rs.local}";; py) echo "${PY_URL:-http://keystone-py.local}";; esac; }
container() { case "$1" in rs) echo keystone;; py) echo keystone-py;; esac; }

# Sum VmRSS/RssAnon/RssFile (kB) over all processes of the container.
proc_rss() { # pod container
  kubectl "${NS[@]}" exec "$1" -c "$2" -- sh -c '
    for f in /proc/[0-9]*/status; do cat "$f" 2>/dev/null; done' 2>/dev/null |
    awk '/^VmRSS:/{r+=$2} /^RssAnon:/{a+=$2} /^RssFile:/{f+=$2}
         END{printf "%.0f,%.0f,%.0f", r/1024, a/1024, f/1024}'
}

sampler() { # target outfile
  local t="$1" f="$2" sel; sel="$(selector "$t")"
  while true; do
    ts=$(date +%s)
    # --containers: the rs pod also runs opa and spiffe-helper sidecars.
    kubectl "${NS[@]}" top pods --containers -l "$sel" --no-headers 2>/dev/null |
    while read -r pod ctr _ mem; do
      [ "$ctr" = "$(container "$t")" ] || continue
      echo "$ts,$t,$pod,${mem%Mi},$(proc_rss "$pod" "$(container "$t")")" >> "$f"
    done
    sleep "$INTERVAL"
  done
}

run_load() { # target
  local t="$1"
  OS_AUTH_URL="$(url "$t")/v3" OS_USERNAME="${OS_USERNAME:-admin}" OS_PASSWORD="$OS_PASSWORD" \
  OS_PROJECT_NAME="${OS_PROJECT_NAME:-admin}" OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default \
  LOADTEST_THINK_MS="$THINK_MS" LOADTEST_SUMMARY_FILE="$OUT/load-$t.json" \
    "$LOAD_TEST" --host "$(url "$t")" --users "$USERS" --hatch-rate "$((USERS / 5 + 1))" \
      --run-time "$RUN_TIME" --scenarios "$SCENARIOS" --no-reset-metrics --quiet \
      --report-file "$OUT/load-$t.md" > "$OUT/load-$t.log" 2>&1
}

CSV="$OUT/memory.csv"
echo "ts,target,pod,working_set_mib,rss_mib,rss_anon_mib,rss_file_mib" > "$CSV"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

IFS=, read -ra TS <<< "$TARGETS"
for t in "${TS[@]}"; do sampler "$t" "$CSV" & PIDS+=($!); done

if [ "$MODE" = par ]; then
  for t in "${TS[@]}"; do run_load "$t" & done; wait "${PIDS[@]:${#TS[@]}}" 2>/dev/null || true
  wait $(jobs -p | grep -v -w "${PIDS[*]}" || true) 2>/dev/null || true
else
  for t in "${TS[@]}"; do echo "== $t: $RUN_TIME @ $USERS users"; run_load "$t"; done
fi
# One more sample after the load stopped (idle retention / release).
sleep "$((INTERVAL * 2))"

"$ROOT/tools/summarize-memory.py" "$CSV" | tee "$OUT/summary.md"
echo "results in $OUT"
