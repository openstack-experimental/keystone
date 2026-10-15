# Raft soak test

A long-running test for a keystone Raft cluster in Kubernetes (k3s). It is
meant to be left running for hours or days and to judge cluster health and
storage growth by itself.

The `soak` controller

1. runs the goose `load_test` in repeating phases (steady, burst, idle) so the
   profile includes idle time for compaction and purging,
2. every `SOAK_INTERVAL` scrapes `/metrics` and `/ready` of every Raft pod
   (found through the headless `keystone-rs-internal` service),
3. evaluates the invariants below and publishes the outcome as Prometheus
   metrics (`:9100/metrics`, `soak_*`), JSON (`:9100/verdict`, HTTP 503
   once unhealthy) and an on-demand report (`:9100/report`),
4. exits `0` when `SOAK_DURATION` elapsed without a violation and non-zero on
   the first one (`SOAK_FAIL_FAST=false` records violations and keeps going).

## Run

The soak test targets a production-sized cluster of at least 3 voters. With
skaffold (module `soak` in `skaffold.yaml`), deploy keystone with the `soak`
profile (overlay `skaffold-soak`: 3 `keystone-rs` replicas) first:

```sh
skaffold build -m keystone -p local,soak --default-repo localhost:5000 --file-output keystone-build.json
skaffold deploy -m keystone -p local,soak -a keystone-build.json
skaffold build -m soak -p local --default-repo localhost:5000 --file-output soak-build.json
skaffold deploy -m soak -p local -a soak-build.json
skaffold delete -m soak
```

Manually:

```sh
docker build -f tests/soak/Dockerfile -t keystone-soak .   # import into k3s
kubectl apply -k tools/k8s/keystone/overlays/soak
kubectl logs -f deploy/keystone-soak
kubectl port-forward svc/keystone-soak 9100 && curl localhost:9100/verdict
```

For graphs deploy the observability stack (`skaffold deploy -m observability`);
its Prometheus scrapes both the Raft pods and the `keystone-soak` service.

## Report on demand

For a headless system there is nothing to open in a browser or to port-forward:

```sh
kubectl exec deploy/keystone-soak -- soak report          # Markdown
kubectl exec deploy/keystone-soak -- soak report --json   # complete state
```

The command exits `0` when healthy, `1` when an invariant was violated and `2`
when the controller cannot be reached, so it can be used from CI or cron. The
same content is served at `GET :9100/report[?format=json]` and is written to
the pod log when the run ends (`kubectl logs deploy/keystone-soak`).

The report contains the verdict and violations, the current cluster state,
the storage series (disk, Raft log, snapshots) with first/min/max/last, the
load totals, a table of the latest load phases (requests, failures, 429s,
latency percentiles) and the endpoints that failed most. Phase records are
capped at 1000 (the totals cover the whole run).

Length and thresholds are environment variables (see the ConfigMap in
`tools/k8s/keystone/overlays/soak/soak.yaml` and `soak --help`), e.g.
`SOAK_DURATION=30m` for a smoke run or `7d` for a long one. Changes need a
pod restart: `kubectl rollout restart deploy/keystone-soak`.

## Invariants

A condition must hold for `SOAK_GRACE` before it counts, so elections and
restarts are tolerated.

- every pod is scrapeable and `/ready`
- exactly one leader; `SOAK_EXPECTED_VOTERS` voters; no learners for longer
  than `SOAK_LEARNER_GRACE`
- `last_applied_index` spread, apply lag and replication lag below limits
- no quarantined partitions; `gcm_failures_total` does not grow
- disk usage does not differ by more than `SOAK_MAX_DISK_SPREAD` between nodes
  (judged once every node holds `SOAK_MIN_DISK_FOR_SPREAD`, 1 GiB; journal
  preallocation makes small stores differ by tens of MiB)
- the Raft log plateaus: after `SOAK_WARMUP` its total size may not grow more
  than `SOAK_MAX_LOG_GROWTH` between the first and last quarter of
  `SOAK_GROWTH_WINDOW`
- the load generator keeps running, and at most `SOAK_MAX_LOAD_ERROR_RATE`
  (1 %) of the requests of a load phase fail. Phases with fewer than
  `SOAK_MIN_LOAD_REQUESTS` requests are not judged. Expected negative
  responses (wrong password, ...) and throttling (`429`, reported separately)
  are not failures

`soak_disk_bytes_total`, `soak_log_disk_bytes_total` and
`soak_snapshot_bytes_total` are exported for judging long-term growth in
Prometheus.

## Chaos

With `SOAK_CHAOS_INTERVAL` set (`20m` in the soak overlay, `0` disables) the
controller deletes one Raft pod at that interval while the load keeps
running. Pods are hit in name order, so every node, the leader included, is
killed repeatedly. A pod is only deleted while all pods are ready, and the
next one only after the previous victim came back as a new, ready pod.

- A victim that is not ready again within `SOAK_CHAOS_RECOVERY` (`5m`)
  violates `chaos_recovery`.
- Requests that fail because of the kills count against
  `SOAK_MAX_LOAD_ERROR_RATE`; the other invariants (leader count, applied
  spread, lags) apply during recovery after their `SOAK_GRACE`.
- The controller needs RBAC to `get`/`list`/`delete` pods, which the soak
  overlay grants through the `keystone-soak` service account (namespace
  scoped Role). Selector: `SOAK_CHAOS_SELECTOR`.
- Exported: `soak_chaos_kills_total`, `soak_chaos_recovered_total`,
  `soak_chaos_timed_out_total`, `soak_chaos_last_recovery_seconds`,
  `soak_chaos_max_recovery_seconds`; the report has a "Chaos" section.

## Not implemented yet

Read-after-write and integrity canaries and bytes-per-record tracking are
planned follow-ups.

## Load generator contract

The controller runs `load_test` once per steady/burst phase with
`LOADTEST_SUMMARY_FILE=<path>`; on exit `load_test` writes the totals of the
run there as JSON (`tests/loadtest/src/summary.rs`). Sync traffic honors
`Retry-After` on `429` instead of retrying immediately, and a concurrent-update
`409` on the shared SCIM realm counts as expected contention.
