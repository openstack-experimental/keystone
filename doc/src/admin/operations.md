# Operations

## Health and Readiness

The dedicated `[interface_metrics]` listener defaults to `0.0.0.0:8099`.

```console
curl http://keystone:8099/health
curl http://keystone:8099/ready
```

Both endpoints report database, policy-engine, and distributed-storage status.
`/ready` returns `503 Service Unavailable` for degraded components; `/health`
allows warning states to remain `200 OK`.

With distributed storage enabled, a node is only ready when all of the following
hold; otherwise the `raft` component reports `warn` with the reasons:

- the Raft cluster is initialized and a leader is known;
- when the node is the leader, a quorum acknowledged it within the last 6
  seconds;
- the applied index trails the cluster commit index by at most 1000 entries (a
  node installing a snapshot or catching up after a partition, including one
  that has not applied a new DEK epoch yet, is not ready);
- no partition is quarantined on this node.

These states are not fatal, so they affect only readiness: use `/health` for
liveness and startup probes. A Raft core that has stopped with a fatal error
(storage failure, panic, shutdown) is the one exception — it is reported as
`error`, which fails `/health` as well, so the liveness probe restarts the pod.
In Kubernetes, run the storage StatefulSet with `podManagementPolicy: Parallel`,
otherwise a full restart of a multi-node cluster waits for the first pod to
become ready, which it cannot do without a quorum.

## Metrics and Logging

`GET /metrics` returns Prometheus text format. Current exported metrics include
audit event, drop, queue-depth, spool, sink and key-version series
(`keystone_audit_*`, listed in ADR 0023 §Observability; ready-made alert rules
are in `deploy/prometheus/alert_rules.yaml`) and dynamic-auth-plugin load
failures, and HTTP, authentication, policy, token, rate-limit and cache
series. The same data can be pushed over OTLP; see
[OpenTelemetry](features/opentelemetry.md).

With distributed storage enabled, `/metrics` also exports the per-node
`keystone_raft_*` series (alert rules in the `keystone_raft` group of the same
file):

| Metric                                                                                                       | Meaning                                                                        |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `keystone_raft_is_leader`, `_term`, `_current_leader_id`                                                     | Leadership as seen by this node (`_current_leader_id` is `-1` when none)       |
| `keystone_raft_membership_voters`, `_membership_learners`                                                    | Size of the effective membership                                               |
| `keystone_raft_last_log_index`, `_last_applied_index`, `_apply_lag`                                          | Log position; `_apply_lag` is cluster commit index minus applied index         |
| `keystone_raft_replication_lag{peer_id}`                                                                     | Per-peer lag, on the leader only                                               |
| `keystone_raft_apply_duration_seconds`                                                                       | State-machine apply latency histogram                                          |
| `keystone_raft_quarantined_partitions{partition}`, `_quarantined_partitions_count`                           | Partitions quarantined on this node                                            |
| `keystone_raft_gcm_failures_total`                                                                           | AES-GCM verification failures on state reads (quarantine trigger)              |
| `keystone_raft_dek_version`, `_dek_retired_epochs`, `_dek_revoked_epochs`                                    | Active DEK epoch and epochs still held                                         |
| `keystone_raft_dek_pending_rotation`                                                                         | Emergency rotations awaiting confirmation                                      |
| `keystone_raft_dek_reencrypt_migrated_total`, `_skipped_total`, `_last_skipped`                              | Background re-encryption progress after a rotation                             |
| `keystone_raft_log_nonce_counter`, `_log_nonce_remaining`                                                    | Log-encryption nonce counter and values left before the 2^31 limit             |
| `keystone_raft_write_rate_version_max`                                                                       | Highest per-record write version seen since start (limit 2^30)                 |
| `keystone_raft_snapshot_last_index`, `_snapshot_size_bytes`, `_snapshot_age_seconds`                         | Latest snapshot                                                                |
| `keystone_raft_disk_space_bytes`, `_log_disk_space_bytes`                                                    | Fjall database and Raft log disk usage                                         |
| `keystone_raft_audit_spool_bytes`, `_audit_dropped_total`, `_audit_channel_depth`, `_audit_channel_capacity` | Storage audit spool size, dropped records, queued records and channel capacity |

Keystone uses structured logging. Protect logs because request and identity
metadata can be sensitive, and never enable logging that records bearer tokens,
credentials, or decrypted policy input.

## Upgrades

1. Back up the database, distributed storage, and key repositories.
2. Review configuration and migration changes.
3. Apply database migrations with `keystone-manage db sync`.
4. Upgrade one instance at a time where the deployment supports rolling
   replacement.
5. Verify health, readiness, token issuance, token validation, and
   representative authorized API calls before continuing.

Coordinate Fernet and distributed-encryption key changes separately from binary
upgrades. Follow the dedicated [Fernet](tokens/fernet.md) and
[distributed-storage](storage/distributed.md) procedures.

## Recovery

Preserve the database, all Fernet and credential key repositories, distributed
storage, the configured KEK, and OPA policies. A database backup without its
matching encryption material is not sufficient for recovery.
