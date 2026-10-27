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

| Metric | Meaning |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `keystone_raft_is_leader`, `_term`, `_current_leader_id` | Leadership as seen by this node (`_current_leader_id` is `-1` when none) |
| `keystone_raft_membership_voters`, `_membership_learners` | Size of the effective membership |
| `keystone_raft_last_log_index`, `_last_applied_index`, `_apply_lag` | Log position; `_apply_lag` is cluster commit index minus applied index |
| `keystone_raft_replication_lag{peer_id}` | Per-peer lag, on the leader only |
| `keystone_raft_apply_duration_seconds` | State-machine apply latency histogram |
| `keystone_raft_quarantined_partitions{partition}`, `_quarantined_partitions_count` | Partitions quarantined on this node |
| `keystone_raft_gcm_failures_total` | AES-GCM verification failures on state reads (quarantine trigger) |
| `keystone_raft_dek_version`, `_dek_retired_epochs`, `_dek_revoked_epochs` | Active DEK epoch and epochs still held |
| `keystone_raft_dek_pending_rotation` | Emergency rotations awaiting confirmation |
| `keystone_raft_dek_reencrypt_migrated_total`, `_skipped_total`, `_last_skipped` | Background re-encryption progress after a rotation |
| `keystone_raft_log_nonce_counter`, `_log_nonce_remaining` | Log-encryption nonce counter and values left before the 2^31 limit |
| `keystone_raft_write_rate_version_max` | Highest per-record write version seen since start (limit 2^30) |
| `keystone_raft_snapshot_last_index`, `_snapshot_size_bytes`, `_snapshot_age_seconds` | Latest snapshot |
| `keystone_raft_disk_space_bytes`, `_log_disk_space_bytes` | Fjall database and Raft log disk usage |
| `keystone_raft_audit_spool_bytes`, `_audit_dropped_total`, `_audit_channel_depth`, `_audit_channel_capacity` | Storage audit spool size, dropped records, queued records and channel capacity |

Keystone uses structured logging. Protect logs because request and identity
metadata can be sensitive, and never enable logging that records bearer tokens,
credentials, or decrypted policy input.

## Upgrades

1. Back up the database, distributed storage, and key repositories.
1. Review configuration and migration changes.
1. Apply database migrations with `keystone-manage db sync`.
1. Upgrade one instance at a time where the deployment supports rolling
   replacement.
1. Verify health, readiness, token issuance, token validation, and
   representative authorized API calls before continuing.

Coordinate Fernet and distributed-encryption key changes separately from binary
upgrades. Follow the dedicated [Fernet](tokens/fernet.md) and
[distributed-storage](storage/distributed.md) procedures.

## Backup and recovery

Preserve the database, all Fernet and credential key repositories, distributed
storage, the configured KEK, and OPA policies. A database backup without its
matching encryption material is not sufficient for recovery.

### What to back up

| Item | How | Note |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| SQL database | Database-native backup | Holds identity, assignments, credentials (encrypted blobs) and token revocation events. |
| Fernet and credential key repositories | File copy | The database is unreadable without the credential keys. Keep them apart from the database backup. |
| Distributed storage | `keystone-manage storage backup` on the leader ([procedure](storage/distributed.md#backup-and-restore)) | The snapshot is encrypted. It can be restored only under the same KEK. |
| KEK (PKCS#11, TPM or environment) | Escrow according to the provider | Without the KEK, every distributed-storage backup is lost, including the archived ones. |
| Audit spool directory, including `hmac-key.bin` | File copy | Needed to verify the audit signatures after a restore. See [Audit trail](features/audit.md). |
| OPA policies and the pinned bundle digest | Version control | The policy is the authorization logic. |
| `keystone.conf` and the deployment manifests | Version control | Keep secrets out of it. |

Set the schedule and the retention from the recovery point and recovery time
that the deployment must meet. Keystone does not choose them. Copy backups off
the host, and keep the key material and the data in separate places with
separate access.

### Testing a restore

A backup that was never restored is not a backup. At least once per release
cycle, and after any change to the key hierarchy:

1. Restore the latest database backup and the matching key repositories into an
   isolated environment. For distributed storage, restore the snapshot into a
   fresh cluster that uses the same KEK. Never point the test environment at the
   production database or storage.
1. Start Keystone and check `/health` and `/ready` on the metrics listener.
1. Issue a token with a test user, validate it, and call one authorized API.
1. Verify the restored audit records as described in
   [Verifying records in a SIEM](features/audit.md#verifying-records-in-a-siem).
1. Record the elapsed time and compare it with the recovery objective.

### What a restore does not bring back

- Anything written after the backup was taken. A distributed-storage restore
  replaces all data keyspaces with the backup's contents.
- Token revocation events created after the backup. Tokens are stateless, so a
  token revoked after the backup validates again until it expires. After a
  restore, revoke the tokens of users and projects that were affected
  meanwhile, or rotate the Fernet keys.
- User deletions made after the backup. The restored state contains those users
  again. Replay the deletions, since the data removal procedure (see the
  [Security reference](security-reference.md#data-removal)) is not repeated by
  the restore.
- Audit records in an unflushed in-memory channel. Records on the spool are
  kept.

### Key custody

- Store the KEK escrow and the Fernet and credential key backups in a vault with
  dual control, separate from the systems they protect.
- Test the escrow path when you test a restore.
- A lost KEK cannot be rebuilt. There is no recovery key beyond the escrow you
  created.

## Detecting security incidents

Keystone gives an operator three signals: the signed audit trail, Prometheus
metrics and OpenTelemetry traces. Alert on the signals below, route the alerts
to the people who run incident handling, and keep the audit spool as evidence.

### Audit records to watch

Filter the CADF records of the [audit trail](features/audit.md):

| Look for | Meaning |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `authenticate` with `outcome = failure`, grouped by `initiator.host.address` and by user | Password guessing, credential stuffing, a broken client |
| `reason.reasonCode` of `UserLocked`, `UserPasswordExpired`, `UserDisabled` | A locked or disabled account that is still being used |
| `reason.reasonCode` of `MfaRulesNotSatisfied` | A password was accepted but the user's multi-factor rules were not met |
| `authenticate` successes from an address or at a time the user never used | Account takeover |
| `enable`, `disable`, `delete` and `update` on users, roles, assignments and policies | Privilege changes; compare against change tickets |
| A `pending` record without a later `success` or `failure` for the same operation | A crashed or interrupted operation; see the audit page for the procedure |
| A `*.quarantine-*` file in the spool, or records whose HMAC signature does not verify | Tampering or corruption of the evidence itself |

### Metrics

| Metric | Use |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `keystone_auth_failures_total{method,reason}` | Rate of failed logins per method and reason |
| `keystone_auth_lockouts_total` | Account lockouts; a jump means a guessing campaign |
| `keystone_rate_limit_rejections_total{scope}` | Requests refused by the limiter; sustained values mean abuse |
| `keystone_policy_decisions_total`, `keystone_policy_errors_total` | Denials by policy; errors mean OPA is unreachable or broken |
| `keystone_token_revoked_total` | Revocation volume after an incident |
| `keystone_audit_*` | Audit pipeline health; drops mean missing evidence |
| `keystone_oauth2_refresh_reuse_detected_total` | A replayed OAuth2 refresh token, a likely token theft |

`deploy/prometheus/alert_rules.yaml` ships rules for the audit pipeline, Raft
and OAuth2 refresh-token reuse. It does not alert on authentication failures,
lockouts or rate-limit rejections, because the right thresholds depend on the
traffic. Add rules for those with thresholds from your own baseline.

### Using the evidence

Audit records carry the initiator, target, action, outcome and time of each
event, each signed with an HMAC. They support the reconstruction of an incident
timeline and the notification that an entity may owe its national CSIRT. The
reporting duty itself, its deadlines and its content belong to the operator and
are not covered here. Copy the relevant spool files to write-once storage when
an incident starts, before any rotation or cleanup.
