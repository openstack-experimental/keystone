# 47. Table version watermarks for process-wide caches

**Date:** 2026-11-20

## Status

Prototype (implemented for the catalog, role and project tables of the SQL
drivers; opt-in, disabled by default).

## Reference

Related: ADR 0042 (event delivery and delete cascades). The catalog, role and
resource providers already keep process-wide caches (`CatalogCache`,
`RoleCache`, the project maps of `ResourceService`).

## Context

The process-wide caches are invalidated immediately by writes made through the
same process. A write made elsewhere (another replica, `keystone-manage`, a
co-deployed Python Keystone, direct SQL) is only noticed when the TTL expires
(`[catalog] cache_time`, `[role] cache_time`), or for the project maps never
until restart. A short TTL bounds the staleness but costs a reload every few
seconds, and a long TTL does the opposite.

## Decision

Keep one version counter per watched table in a `table_version` table:

```text
table_version(table_name VARCHAR(64) PRIMARY KEY, version BIGINT NOT NULL)
```

Database triggers bump the counter of a table on every `INSERT`, `UPDATE` and
`DELETE`, in the same transaction as the change (a rolled back change leaves no
trace). A background poller (`[database] table_watermark_interval_ms`, `0` =
off) reads the whole table with one query per interval and publishes the
counters into `TableWatermarks`. A cache records the combined counter (the sum
of the counters of the tables it depends on, the counters only grow) before it
loads a value and serves the value for as long as the counter is unchanged,
without regard to the TTL.

| Cache                            | Tables                                |
| -------------------------------- | ------------------------------------- |
| `CatalogCache`                   | `service`, `endpoint`                 |
| `RoleCache`                      | `role`, `role_option`, `implied_role` |
| `ResourceService` (project maps) | `project`                             |

### Safety properties

- The watermark can only tighten the staleness. While the poller is disabled,
  has not polled yet, is failing (no poll for three intervals) or a table has no
  counter row (triggers not installed), `stamp()` is `None` and the caches fall
  back to the TTL exactly as before.
- The stamp is taken _before_ the load. A change committed during the load moves
  the stamp on and costs one extra reload, never a stale hit.
- Local writes still invalidate immediately; the watermark only adds the
  detection of foreign writes, with a staleness bound of one poll interval.
- The counter row is created together with the triggers, so a missing trigger
  installation is detected instead of reading as "never changed".

### Triggers per backend

| Backend    | Triggers per table                                                  |
| ---------- | ------------------------------------------------------------------- |
| PostgreSQL | one `FOR EACH STATEMENT` trigger (insert, update, delete, truncate) |
| MySQL      | three `FOR EACH ROW` triggers (no statement-level triggers)         |
| SQLite     | three `FOR EACH ROW` triggers (no statement-level triggers)         |

The triggers are installed by `table_watermark::install` from the driver
`SqlDriver::setup` (fresh databases, `keystone-manage db sync`) and from a
versioned migration per driver (`keystone-manage db up`). Both are idempotent,
and the migration skips tables that do not exist. `down` drops the triggers and
the counter rows.

## Consequences

- Writers of a watched table serialize on its counter row for the duration of
  their transaction. This is acceptable for the read-mostly tables above; it
  must not be extended to hot write tables (tokens, revocation events, users).
- Table granularity: any change of a watched table drops all cached entries that
  depend on it.
- `TRUNCATE` is covered on PostgreSQL only (MySQL does not fire triggers for it,
  SQLite has none).
- MySQL with binary logging needs the `TRIGGER` privilege and, without `SUPER`,
  `log_bin_trust_function_creators=1` to create triggers.
- The poll query runs every interval on every node, regardless of traffic.
- Raft-backed drivers do not use this; their log index is the natural watermark.

## Open points

- Enable by default and raise the cache TTLs once the poller has proven itself.
- Extend to further read-mostly tables (domains are rows of `project`, so they
  are already covered; `assignment` would need a per-table review).
- Expose the poller health and the cache hit ratio as metrics.
