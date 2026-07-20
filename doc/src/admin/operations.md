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

## Metrics and Logging

`GET /metrics` returns Prometheus text format. Current exported metrics include
audit event/drop counters and dynamic-auth-plugin load failures.

Keystone uses structured logging. Protect logs because request and identity
metadata can be sensitive, and never enable logging that records bearer tokens,
credentials, or decrypted policy input.

## Upgrades

1. Back up the database, distributed storage, and key repositories.
2. Review configuration and migration changes.
3. Apply database migrations with `keystone-manage db sync`.
4. Upgrade one instance at a time where the deployment supports rolling
   replacement.
5. Verify health, readiness, token issuance, token validation, and representative
   authorized API calls before continuing.

Coordinate Fernet and distributed-encryption key changes separately from binary
upgrades. Follow the dedicated [Fernet](tokens/fernet.md) and
[distributed-storage](storage/distributed.md) procedures.

## Recovery

Preserve the database, all Fernet and credential key repositories, distributed
storage, the configured KEK, and OPA policies. A database backup without its
matching encryption material is not sufficient for recovery.
