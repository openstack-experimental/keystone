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
   metrics (`:9100/metrics`, `soak_*`) and JSON (`:9100/verdict`, HTTP 503
   once unhealthy),
4. exits `0` when `SOAK_DURATION` elapsed without a violation and non-zero on
   the first one (`SOAK_FAIL_FAST=false` records violations and keeps going).

## Run

```sh
docker build -f tests/soak/Dockerfile -t keystone-soak .   # import into k3s
kubectl apply -k tools/k8s/keystone/overlays/soak
kubectl logs -f deploy/keystone-soak
kubectl port-forward svc/keystone-soak 9100 && curl localhost:9100/verdict
```

For graphs deploy the observability stack (`skaffold run -m observability`);
its Prometheus scrapes both the Raft pods and the `keystone-soak` service.

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
- the Raft log plateaus: after `SOAK_WARMUP` its total size may not grow more
  than `SOAK_MAX_LOG_GROWTH` between the first and last quarter of
  `SOAK_GROWTH_WINDOW`
- the load generator keeps running

`soak_disk_bytes_total`, `soak_log_disk_bytes_total` and
`soak_snapshot_bytes_total` are exported for judging long-term growth in
Prometheus.

## Not implemented yet

Chaos (pod deletion), read-after-write and integrity canaries, a load error
rate threshold and bytes-per-record tracking are planned follow-ups.
