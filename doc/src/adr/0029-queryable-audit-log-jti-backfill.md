# 29. Queryable Audit Log & Audit-Derived JTI Revocation Backfill (Amends ADR 0026 §3)

**Date:** 2026-07-15

## Status

Proposed

## Reference

Amends [ADR 0026](0026-oauth2-oidc-provider.md) §3 ("Emergency Rotation and
Signing Key Compromise"), which specifies but does not build:

> The list initially includes the `jti` of any tokens issued within the
> compromise window (derived from the audit log).

Extends [ADR 0023](0023-audit.md) (CADF-Compliant Phased Auditing
Architecture), whose CADF events are currently a best-effort, fire-and-
forget dispatch to external sinks (SIEM/Loki/JSONL spool) — not a
queryable store inside Keystone.

## Context

Today, `confirm-rotate-signing-key` takes an operator-supplied,
repeatable `--revoke-jti` flag
(`crates/cli-manage/src/oauth2/confirm_rotate_signing_key.rs` →
`crates/keystone/src/api/v4/oauth2/confirm_rotate_signing_key.rs`). The
operator must already know, by name, every `jti` minted by the
compromised key during the incident window, and paste each one in by
hand. Anything the operator doesn't happen to know about — most tokens,
in practice — is never added to the revocation list and keeps validating
until it naturally expires.

ADR 0026 §3 describes the intended behavior instead: the operator gives a
time window ("compromised starting at 14:32 UTC"), and the system derives
the full set of `jti`s minted for that domain in that window from the
audit trail, populating the revocation list automatically and
completely.

That isn't buildable as a one-off addition to the OAuth2 crate, because
the prerequisite doesn't exist: **CADF audit events (ADR 0023) are
dispatched, not stored.** Per ADR 0023, `dispatch_critical()`/best-effort
dispatch push signed `CadfEvent`s to configured sinks — SIEM, Loki,
Prometheus-observed spool files — with a local JSONL file used only as a
compensating fallback on channel congestion, not as a queryable index.
There is no code path anywhere in the workspace that answers "give me
every event of type X for domain Y between timestamps A and B." Building
audit-derived JTI backfill for real means building that queryability
first, as a general-purpose capability, and then a thin query on top of
it for this one use case — which is why it was deferred rather than
special-cased.

## Decision

This ADR is in two layers: a general-purpose queryable audit store (which
has value well beyond OAuth2), and the specific JTI-backfill query built
on top of it.

### 1. Queryable Audit Log Persistence

Add an optional, opt-in **local audit index** alongside the existing
dispatch-to-sinks path — not a replacement for it. ADR 0023's design
philosophy ("audit is advisory for SIEM compliance, not a hard
transactional guarantee") is preserved; the index is a queryability layer
on top of the same signed `CadfEvent`s already being produced, not a new
source of truth.

- **Storage:** a new `audit-sql` crate (mirroring the existing
  `identity-sql`, `catalog-sql` pattern) with a single append-only table,
  written from the same dispatch point `dispatch_critical()`/best-effort
  dispatch already calls (`crates/.../audit/dispatcher.rs`), added as one
  more configured sink rather than a special case in the dispatcher.
  Columns mirror the indexed subset of `CadfEventPayload` needed for
  lookups: `id`, `seq`, `event_time`, `domain`, `action`, `outcome`,
  `initiator_id`, `target_id`, `correlation_id`, plus the full signed
  `CadfEvent` JSON for verification/detail. The signature is stored
  verbatim (ADR 0023's HMAC chain), never re-derived — the index is a
  read path, not a re-signing authority.
- **Retention:** a configurable window (`[audit] index_retention_days`,
  default aligned with existing janitor retention conventions elsewhere
  in the codebase, e.g. ADR 0020 §4.A/§7.2's 90-day patterns), with its
  own janitor sweep. This is deliberately shorter-lived and more
  disposable than SIEM-side retention — the index exists to serve
  operational queries like JTI backfill within a recent window, not to be
  the system of record for compliance retention.
- **Delivery semantics:** same at-least-once, best-effort posture as
  every other sink in ADR 0023 (§ "Delivery Guarantee"). A dropped index
  write increments the existing `dropped_count`/`postaudit_dropped_count`
  Prometheus gauges — no new failure class, no new consistency guarantee
  claimed. This index being incomplete for a given window is a known,
  observable condition (see JTI backfill correctness below), not a silent
  gap.
- **Query surface:** a new internal-only (not exposed on the public API
  router) query function,
  `AuditApi::list_events(domain_id, action_filter, time_range) -> Vec<CadfEvent>`,
  callable only from trusted server-side code (the JTI-backfill path
  below), not exposed as a general-purpose external audit-query REST
  endpoint in this ADR — that would be a separate access-control design
  (who may read whose audit trail) out of scope here.

### 2. Audit-Derived JTI Backfill

Built on top of (1), a new operator-facing input on the existing
confirmation step:

```
keystone-manage oauth2 confirm-rotate-signing-key \
  --domain <domain_id> --rotation-id <rotation_id> \
  --compromise-window-start <RFC3339> \
  [--revoke-jti <jti> ...]
```

- `--compromise-window-start` triggers a call to
  `AuditApi::list_events(domain_id, action="oauth2.token.issue", [start, confirm_time])`,
  filtered to CADF events with a `token_use: "access"` /
  `openstack_context` present (mirroring the ADR 0026 §3 point 3
  distinction that `id_token`/`OidcAccessTokenClaims` carry no downstream
  authority and are excluded), extracting the `jti` recorded on each
  matching event.
- The derived set is **unioned** with any manually-supplied
  `--revoke-jti` values, not a replacement for them — an operator who
  already knows a specific suspect `jti` outside the declared window (or
  the index has a gap for) can still supply it directly.
- **Coverage disclosure, not silent trust.** The response to
  `confirm-rotate-signing-key` reports how many `jti`s were derived from
  the audit index versus supplied manually, and — critically — whether
  the index has any known gaps in the requested window (dropped-write
  count from (1) overlapping `[compromise_window_start, now]`). An
  operator relying on a gappy index for a real incident needs to know
  that, not discover it later. If the index reports a gap in the window,
  the CLI prints a explicit warning and the response carries
  `index_complete: false`.
- **CADF event issuance itself must not be lost** for this feature to be
  meaningful: token-issuance events already flow through
  `emit_oauth2_session_event` at issuance time (ADR 0026 §9); this ADR
  requires that path is wired into the new index sink like any other,
  with no change to when or how issuance events are emitted, only where
  one more copy of them lands.

## Consequences

### Positive

- Closes ADR 0026 §3's stated gap: an operator can name a compromise
  window instead of enumerating individual JTIs, and the revocation list
  actually catches tokens nobody happened to already know about.
- The queryable audit index is general-purpose — useful for incident
  response, compliance spot-checks, and debugging well beyond OAuth2 (ADR
  0023 already anticipated this need existing "someday," this ADR is the
  first concrete consumer).
- Preserves ADR 0023's advisory/best-effort audit philosophy rather than
  quietly upgrading audit dispatch to a hard transactional requirement,
  which would have been a much larger, riskier change.

### Negative / Risks

- **The index inherits ADR 0023's best-effort delivery guarantee**, so
  audit-derived backfill is provably complete only when the index reports
  no gaps for the requested window; during sustained channel congestion
  or an outage that also degrades the index sink, backfill coverage can
  be incomplete exactly when an incident makes completeness matter most.
  This ADR's answer is to make that condition visible (`index_complete:
  false`), not to eliminate it — eliminating it would require the harder
  transactional-audit guarantee ADR 0023 deliberately chose not to make.
- **New persistence surface** (`audit-sql` crate, retention janitor, an
  internal query API) adds operational surface (schema migrations,
  storage growth, another janitor cadence to tune) to a subsystem, that
  today, is intentionally stateless from Keystone's point of view.
- **Scope creep risk.** Because the index is general-purpose, there will
  be pressure to expose it as a public audit-query API beyond this one
  internal consumer. That is explicitly out of scope for this ADR (see
  "Query surface" above) and needs its own access-control design — who
  may query whose audit trail is a distinct authorization problem from
  "can the OAuth2 emergency-rotation code path read events it itself
  helped produce."
- **Retention/incident-response mismatch.** If `index_retention_days` is
  shorter than an organization's typical detection latency (time between
  compromise and confirmed emergency rotation), audit-derived backfill
  silently degrades to whatever manual JTIs the operator supplies for the
  portion of the window that has already rolled off the index. Operators
  should size `index_retention_days` against their own realistic
  detection-latency assumptions, not the default.

## Implementation Status

Not implemented. This ADR records the design so the gap acknowledged in
ADR 0026 §3 has a concrete shape to build against. Implementation is two
sequential pieces of work: the general-purpose queryable audit index
(new crate, schema, sink wiring, janitor) first, then the thin
JTI-backfill query and CLI/API surface on top of it.
