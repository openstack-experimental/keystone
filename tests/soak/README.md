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
- the p99 latency of a load phase stays within `SOAK_MAX_READ_P99` (`1s`,
  GET), `SOAK_MAX_WRITE_P99` (`2s`) and `SOAK_MAX_AUTH_P99` (`2s`, token
  issuing, dominated by password hashing); `0` disables a limit. A class
  needs `SOAK_MIN_LOAD_REQUESTS` requests to be judged. Phases that overlap a
  pod kill, a partition, a rolling restart, a SPIRE agent restart or a membership scenario (until recovery plus 30 s) are not
  judged, they are
  slow on purpose. The defaults are about 3 to 5 times the worst p99 seen on a
  single-node k3s (steady 20 users: 84/260/260 ms, burst 100 users:
  280/390/420 ms for read/write/auth); tune them to your hardware. `soak_load_read_p99_ms`, `soak_load_write_p99_ms`
  and `soak_load_auth_p99_ms` show the last phase, the report table has the
  p99 per class for every phase

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

## Membership churn

With `SOAK_MEMBERSHIP_INTERVAL` set (off in the soak overlay: it needs the
storage operator role) the controller runs one of two scenarios, alternating,
while the load and the canaries keep running.

- **wipe**: delete the volume and the pod of a follower voter. It comes back
  with empty storage and must rejoin as a learner, never as a voter: a voter
  with an empty log could help elect a leader that lacks acknowledged
  entries. When it caught up, the operator promotes it and the cluster must
  converge with all voters again.
- **scale**: scale the StatefulSet from 3 to `SOAK_MEMBERSHIP_SCALE_TO` (5).
  The new nodes must join as learners, catch up and be removable with
  `remove-peer`. Then the StatefulSet is scaled back and the volumes of the
  extra pods are deleted (a node that keeps its state never joins again), and
  exactly the original voters must be left. The scale-back also runs after a
  failed scale-up.

Checks: `membership_wiped_voter` (came back as a voter), `membership_rejoin`
(not a member), `membership_promote`, `membership_scale_voters` (new nodes
joined as voters), `membership_remove`, `membership_leftover` (members left
after scaling back), `membership_timeout` (a step took longer than
`SOAK_MEMBERSHIP_TIMEOUT`, 10 m), `membership_operator` (the operator command
or the Kubernetes call failed) and `membership_write_gap` (no acknowledged
write for longer than `SOAK_MEMBERSHIP_MAX_WRITE_GAP`, 30 s). Data that a
rebuilt or new node lacks shows up as a canary `integrity` or
`read_after_write` failure.

The operator commands run as Jobs created from the pod template of the
`keystone-storage-operator` Deployment (`SOAK_OPERATOR_DEPLOYMENT`): the pod
label grants the operator SPIFFE identity, which the keystone pods and the
controller do not have. That is the power of the operator role (promote,
demote, remove members, rotate the DEK, restore), so grant it to the
controller in test clusters only. RBAC: `keystone-soak-membership` in
`overlays/soak/soak.yaml` (create Jobs, read the Deployment and pod logs,
delete volumes). Volumes are `<SOAK_CLAIM_PREFIX>-<pod>`, default
`raft-storage`.

`remove-peer` only removes voters: for a learner it prints "not a voter;
nothing to do" and exits 0, so a node that joined as a learner and was then
scaled away stays in the membership as a dead learner. The scale scenario
reports that as `membership_remove` and `membership_leftover`; it needs a way
to remove learners in `keystone-manage storage` before it can pass.

A scenario deliberately makes a node unready, lagging and, after a wipe, a
learner. While one runs, the `scrape`, `ready`, `voters`, `learners`,
`applied_spread`, `apply_lag` and `replication_lag` invariants are not
reported; the scenario's own checks judge the outcome.

Other fault tasks wait while a scenario runs, and load phases overlapping it
are not judged for latency. Exported: `soak_membership_runs_total`,
`soak_membership_failed_total`, `soak_membership_max_seconds`; the report has
a "Membership churn" section.

## SPIRE agent restarts

Keystone gets its SVID from the SPIRE agent's Workload API socket, and the
agent is a node-level DaemonSet that restarts independently of keystone (node
reboot, upgrade, crash). A power cycle once left keystone crash-looping
because the socket came up after it. With `SOAK_SPIRE_INTERVAL` set (off in
the soak overlay: the agent is shared by everything on the node) the
controller deletes the agent pod (`SOAK_SPIRE_NAMESPACE`, default `spire`,
selected by `SOAK_SPIRE_SELECTOR`) while the load and canaries keep running.

- `spire_recovery`: the new agent pod was not ready, or the cluster did not
  converge afterwards, within `SOAK_SPIRE_RECOVERY` (5 m).
- `spire_keystone_restart`: a keystone container restarted. Restarts are
  watched for `SOAK_SPIRE_WATCH` (60 s) after the agent is back, to catch a
  crash loop that starts late.
- `spire_write_gap`: writes through the service were unacknowledged for
  longer than `SOAK_SPIRE_MAX_WRITE_GAP` (30 s).
- Other fault tasks wait while an agent restart is judged, and load phases
  overlapping it are not judged for latency.
- Needs RBAC to `get`/`list`/`delete` pods in the SPIRE namespace
  (`keystone-soak-spire` in `overlays/soak/soak.yaml`, bound to the service
  account of the `default` namespace; change the subject namespace for other
  deployments).
- Exported: `soak_spire_restarts_total`, `soak_spire_failed_total`,
  `soak_spire_max_agent_ready_seconds`, `soak_spire_keystone_restarts_total`;
  the report has a "SPIRE agent restarts" section.

Not covered: clock skew. Skewing one pod's clock needs a time namespace,
`CAP_SYS_TIME` or libfaketime in the image, none of which the soak
deployment has. Token and SVID expiry under skew is better tested with unit
tests against a mock clock.

## Rolling restarts

With `SOAK_ROLLOUT_INTERVAL` set (`2h` in the soak overlay, `0` disables)
the controller restarts the whole `keystone-rs` StatefulSet
(`SOAK_ROLLOUT_STATEFULSET`) the way `kubectl rollout restart` does, so every
pod is replaced in turn while the load and the canaries keep running. That
is what an image upgrade does to the cluster, and what the other faults do
not cover: a node that comes back with old state while its peers have moved
on, repeated leader changes and a voter that has to catch up each time.

- `rollout_timeout`: not every pod ran the new revision and was ready, and
  the cluster not converged (one leader that every node agrees on, no apply
  lag, all voters present), within `SOAK_ROLLOUT_TIMEOUT` (15 m).
- `rollout_write_gap`: while the rollout runs a write is sent through the
  cluster service every few seconds; the longest stretch without an
  acknowledged one may not exceed `SOAK_ROLLOUT_MAX_WRITE_GAP` (60 s).
- Writes that were acknowledged and then lost, or data changed by the
  restarts, show up as a canary `integrity` failure.
- Pod kills and partitions wait while a rollout runs, and the rollout waits
  until the cluster is idle, ready and converged. Load phases that overlap a
  rollout are not judged for latency.
- Needs RBAC to `get`/`patch` the StatefulSet (`overlays/soak/soak.yaml`).
- Exported: `soak_rollout_total`, `soak_rollout_failed_total`,
  `soak_rollout_last_converged_seconds`,
  `soak_rollout_max_write_gap_seconds`; the report has a "Rolling restarts"
  section.

## Partitions

With `SOAK_PARTITION_INTERVAL` set (`30m` in the soak overlay, `0` disables)
the controller isolates one node for `SOAK_PARTITION_DURATION` (60 s) while
the load and the canaries keep running. A `NetworkPolicy` on the pod blocks
TCP port 8300 (Raft and write forwarding) in both directions and leaves
every other port open, so the pod stays alive and reachable for probes. The
victim alternates between the current leader and a follower, and the policy
is removed afterwards (leftovers of a crashed run are removed at start).
Needs RBAC for network policies (`overlays/soak/soak.yaml`) and a CNI that
enforces them; k3s does. A pod kill is never started during a partition.

- `partition_availability`: the other two nodes did not accept a write
  within `SOAK_PARTITION_ELECTION` (60 s). Writes are sent straight to each
  of them.
- `partition_split_brain`: the isolated node acknowledged a write. Only
  judged once the nodes' own view confirms the cut (a leader victim: another
  node leads; a follower victim: it lost sight of the leader). A cut the
  nodes did not notice, for example because the CNI keeps established
  connections alive, is shown as "cut took effect: no" in the report and
  counted in `soak_partition_ineffective_total`, not judged.
- `partition_recovery`: within `SOAK_PARTITION_RECOVERY` (3 m) of lifting the
  cut the cluster must have exactly one leader that every node agrees on, no
  apply lag, and all pods ready.
- Data lost or diverged by a partition shows up as a canary `integrity`
  failure.
- Exported: `soak_partition_total`, `soak_partition_ineffective_total`,
  `soak_partition_failed_total`, `soak_partition_last_heal_seconds`,
  `soak_partition_max_heal_seconds`; the report has a "Partitions" section.

## Canaries

With `SOAK_CANARY_INTERVAL` set (`30s` in the soak overlay, `0` disables) the
controller logs in with the `OS_*` credentials and writes one API key (a
Raft-backed record) per interval through the cluster service. Once the write
is acknowledged it reads the key from **every** pod directly
(`SOAK_API_PORT`, default 8080).

- `read_after_write`: a pod answers 404 for an acknowledged write (stale
  read).
- `integrity`: a pod returns a key that differs from what was written, or
  no longer returns one written earlier. The last 20 keys are re-checked from
  every pod each cycle, older ones are revoked.
- Transport errors, 429 and 5xx answers (a pod being killed by chaos) are
  counted as `soak_canary_read_errors_total` but not judged.

Each cycle also writes one SCIM user through `/SCIM/v2/default/Users`. The
controller creates the `soak-scim-idp` identity provider and the
`soak-scim-realm` SCIM realm if they are missing, mints an API key bound to
the realm (renewed every 30 minutes) and uses it as bearer. The user is read
from every pod with the same bearer and judged like the API key. Here a 401
counts as a stale read too: the key was just written through the leader, so a
pod that rejects it has not applied it yet. SCIM users are removed after 20
cycles. The totals count both record types together.

## Storage per entry

`soak_applied_index_max` (log entries so far) and `soak_disk_bytes_per_entry`
(average per-node disk usage divided by it) are exported and shown in the
report, to see a bytes-per-record regression that the plateau check hides.

## Not implemented yet

Nothing is planned beyond this.

## Load generator contract

The controller runs `load_test` once per steady/burst phase with
`LOADTEST_SUMMARY_FILE=<path>`; on exit `load_test` writes the totals of the
run there as JSON (`tests/loadtest/src/summary.rs`). Sync traffic honors
`Retry-After` on `429` instead of retrying immediately, and a concurrent-update
`409` on the shared SCIM realm counts as expected contention.
