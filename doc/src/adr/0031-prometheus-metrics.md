# 31. Prometheus Metrics Catalog

## Status

Proposed

## Context

Keystone already exposes a `/metrics` endpoint (`crates/keystone/src/bin/keystone.rs`,
`spawn_metrics_listener` / `metrics_handler`) on the dedicated
`interface_metrics` listener (`cfg.interface_metrics.tcp_address`, default
`0.0.0.0:8099`), unauthenticated, intended to be firewalled to internal
scrapers. Today it serves exactly four metrics, each produced by hand-rolled
Prometheus text-exposition (v0.0.4) formatting functions, deliberately
avoiding a dependency on the full `prometheus` client crate
(`crates/audit/src/metrics.rs` doc comment):

- `keystone_audit_dropped_total` (counter, ADR 0023)
- `keystone_audit_postaudit_dropped_total` (counter, ADR 0023)
- `keystone_audit_events_total` (counter, ADR 0023)
- `keystone_auth_plugin_load_failure{plugin_name}` (counter, ADR 0025 §5)

That is coverage for exactly two subsystems (audit spool health, dynamic
auth-plugin load failures). Everything else — HTTP request volume/latency,
authentication outcomes, token issuance/validation/revocation, OPA policy
decisions, rate-limit rejections (ADR 0022), Raft cluster health (ADR
0016-v2), federation/mapping outcomes (ADR 0007/0020), SCIM/API-key/OAuth2/
WebAuthn activity, and per-request cache effectiveness (ADR 0030) — has no
metric today. Operators have no Prometheus-native way to alert on auth
failure spikes, token backend latency, OPA decision latency, or Raft
leader/replication health; they must fall back to log scraping.

This ADR defines the full metrics catalog Keystone should expose, the naming
and label conventions all future metrics must follow, and the exposition
mechanism for adding them without repeating the ad hoc string-formatting
pattern in every crate.

## Decision

### Naming and label conventions

All metric names use the `keystone_<subsystem>_<noun>[_<unit>]` shape,
`snake_case`, base units (seconds, bytes), and `_total` for counters,
matching upstream Prometheus naming conventions:

- Counters end in `_total` (existing exception:
  `keystone_auth_plugin_load_failure` predates this ADR and is **not**
  renamed — renaming a scraped metric name is a breaking change for every
  dashboard/alert already querying it. New counters follow the suffix.)
- Latency is always a histogram in seconds (`_duration_seconds`), never a
  gauge or summary — histograms allow aggregation across instances, which
  matters for a multi-node deployment (ADR 0016-v2).
- Point-in-time values (queue depth, connection counts, leader state) are
  gauges.

**Cardinality / PII guardrail** (extends ADR 0023's data-minimization
rule to metrics): label values MUST be drawn from a bounded,
operator-or-code-controlled set. Never a label:

- Raw resource IDs (`user_id`, `project_id`, `token_id`, `domain_id`) —
  unbounded and, per ADR 0023, treated as sensitive identifiers.
- Free-text error messages — use the same sanitized variant-name approach
  as `error_variant_name`/`sanitize_authentication_error`
  (`crates/keystone/src/api/*` audit integration) so a label value is
  always one of a fixed Rust enum's variant names.
- Raw HTTP path — use Axum's `MatchedPath` (route template, e.g.
  `/v3/users/{user_id}`), never `request.uri().path()`.

Allowed label values: HTTP method, route template, sanitized outcome/reason
enum variant, auth method name, token driver name (`fernet`/`jws`), plugin
name (already operator-configured, per `format_load_failure_metrics`),
grant/ceremony/resource-type names — all finite sets fixed at compile time
or by configuration, not by request content.

### Exposition mechanism

Continue the existing hand-rolled text-exposition approach rather than
pulling in the `prometheus` or `metrics` crate — the four existing metrics
were built this way specifically to avoid that dependency, and the catalog
below is a fixed, known-at-compile-time set of series (no dynamic
metric registration is needed). To avoid re-deriving atomic counters,
label-escaping, and bucket math in every crate as this catalog grows, factor
the shared primitives that `crates/audit/src/metrics.rs` and
`auth_plugin_startup::format_load_failure_metrics` each partially
reimplement into one internal module (`crates/keystone/src/metrics.rs` or a
new small `openstack-keystone-metrics` crate if reused outside
`keystone`/`core`):

```rust
/// Monotonic counter, optionally labeled. Label sets are bounded and
/// known at construction time (see cardinality guardrail above).
pub struct Counter(AtomicU64);
pub struct LabeledCounter<const N: usize>([(&'static str, AtomicU64); N]);

/// Fixed-bucket histogram (standard Prometheus default boundaries),
/// implemented as one AtomicU64 per bucket plus sum/count — no locks,
/// no external crate.
pub struct Histogram<const B: usize> {
    bounds: [f64; B],
    buckets: [AtomicU64; B],
    sum_micros: AtomicU64,
    count: AtomicU64,
}
pub const DEFAULT_LATENCY_BUCKETS: [f64; 11] =
    [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// Every subsystem contributes one function of this shape; `metrics_handler`
/// concatenates all of them into the scrape response, same as today.
pub trait PrometheusText {
    fn format_prometheus_text(&self) -> String;
}
```

Each subsystem keeps owning its counters/histograms (same pattern as
`AuditDispatcher` owning `dropped_count`/`events_total` today) and
implements `PrometheusText`; `metrics_handler` is extended to concatenate
each subsystem's output, same as it already concatenates audit +
auth-plugin output.

### Metrics catalog

Metrics are grouped by subsystem. Each entry: name, type, labels, purpose.
This is the target catalog — implementation lands incrementally per
subsystem in follow-up PRs (mirroring ADR 0023's phasing), not all at once.

#### HTTP / API layer

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_http_requests_total` | counter | `method`, `route`, `status` | Request volume by route/outcome |
| `keystone_http_request_duration_seconds` | histogram | `method`, `route` | Request latency |
| `keystone_http_requests_in_flight` | gauge | `interface` (public/internal/admin/metrics) | Concurrency per listener |

`route` is the Axum `MatchedPath` template, never the raw path.

#### Authentication

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_auth_attempts_total` | counter | `method`, `outcome` (success/failure) | Auth volume by method |
| `keystone_auth_duration_seconds` | histogram | `method` | Auth latency |
| `keystone_auth_failures_total` | counter | `method`, `reason` | Failure breakdown, reusing `sanitize_authentication_error`'s variant names |
| `keystone_auth_lockouts_total` | counter | — | PCI-DSS account lockouts (ADR 0010) |
| `keystone_auth_plugin_load_failure` | counter | `plugin_name` | *(existing, ADR 0025 §5)* |
| `keystone_auth_plugin_invocations_total` | counter | `plugin_name`, `outcome` | WASM plugin call volume |
| `keystone_auth_plugin_duration_seconds` | histogram | `plugin_name` | WASM plugin call latency |

`method` values: `password`, `token`, `application_credential`, `ec2`,
`federation`, `oauth2`, `passkey`, `k8s`, `api_key`.

#### Tokens

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_token_issued_total` | counter | `driver` (fernet/jws), `method` | Issuance volume |
| `keystone_token_validated_total` | counter | `driver`, `outcome` | Validation volume/outcome |
| `keystone_token_validation_duration_seconds` | histogram | `driver` | Validation latency |
| `keystone_token_revoked_total` | counter | `reason` (user_request/admin/cascade/expired_trust) | Revocation volume |
| `keystone_token_revocation_list_size` | gauge | — | In-memory/DB revocation-event backlog |

#### Policy (OPA)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_policy_decisions_total` | counter | `outcome` (allow/deny/error) | Decision volume |
| `keystone_policy_decision_duration_seconds` | histogram | `transport` (http/wasm) | OPA round-trip latency |
| `keystone_policy_errors_total` | counter | `transport` | OPA unreachable/malformed-response errors |

No `policy_name`/`action` label — the resource/action pairs come from
request content passed through `PolicyEvaluationResult`, and while the API
surface is finite, matching ADR 0023's minimization posture, decision
volume/latency is tracked in aggregate rather than per-rule.

#### Rate limiting (ADR 0022)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_rate_limit_evaluations_total` | counter | `scope`, `outcome` (allowed/rejected) | Evaluation volume |
| `keystone_rate_limit_rejections_total` | counter | `scope` | 429s issued |

`scope` values: `per_ip`, `per_user`, `global`, `auth_endpoint` — the fixed
set of limiter scopes defined by ADR 0022's config.

#### Audit (ADR 0023) — existing

`keystone_audit_dropped_total`, `keystone_audit_postaudit_dropped_total`,
`keystone_audit_events_total` — unchanged, documented here for
completeness of the catalog.

#### Domain providers (identity, resource, role, assignment, catalog,
credential, appcred, trust, federation, idmapping, k8s-auth,
token-restriction)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_provider_operations_total` | counter | `domain`, `operation`, `outcome` | CRUD volume per backend trait call |
| `keystone_provider_operation_duration_seconds` | histogram | `domain`, `operation` | Backend latency (DB or Raft) |

`operation` values follow the backend trait convention in
`crates/core/src/backend.rs` (`create`/`get`/`list`/`update`/`delete`, plus
`enable`/`disable`/`authenticate`/`revoke` per `map_event_to_action` in ADR
0023); `domain` is the crate name (`identity`, `catalog`, `role`,
`assignment`, `credential`, `appcred`, `trust`, `federation`, `idmapping`,
`k8s_auth`, `token_restriction`).

#### Raft / distributed storage (ADR 0016-v2)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_raft_is_leader` | gauge (0/1) | — | Leadership state per node |
| `keystone_raft_term` | gauge | — | Current Raft term |
| `keystone_raft_last_log_index` | gauge | — | Log tail position |
| `keystone_raft_last_applied_index` | gauge | — | State-machine apply position |
| `keystone_raft_replication_lag` | gauge | `peer_id` | `last_log_index - peer's match_index`; `peer_id` is a small, config-fixed cluster member set |
| `keystone_raft_apply_duration_seconds` | histogram | — | State-machine apply latency |

#### Federation / mapping (ADR 0007, 0013, 0020)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_federation_authentications_total` | counter | `idp_id`, `outcome` | Federated auth volume — `idp_id` is operator-configured, bounded by deployment |
| `keystone_mapping_evaluations_total` | counter | `outcome` | Mapping-engine evaluation volume |
| `keystone_mapping_evaluation_duration_seconds` | histogram | — | Mapping-engine latency |

#### SCIM / API keys (ADR 0021, 0024)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_scim_operations_total` | counter | `resource_type`, `operation`, `outcome` | SCIM provisioning volume |
| `keystone_api_key_authentications_total` | counter | `outcome` | API-key auth volume |

#### OAuth2 / OIDC (ADR 0026, ADR 0028)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_oauth2_grants_total` | counter | `grant_type`, `outcome` | Grant issuance volume |
| `keystone_oauth2_key_rotations_total` | counter | `trigger` (scheduled/emergency) | Signing-key rotations, including ADR 0028 quorum-bypass emergency rotations |
| `keystone_oauth2_jwks_requests_total` | counter | — | JWKS endpoint hits |

#### WebAuthn / Passkey (ADR 0005)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_webauthn_ceremonies_total` | counter | `ceremony` (registration/authentication), `outcome` | Passkey ceremony volume |

#### Per-request cache (ADR 0030)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `keystone_cache_hits_total` | counter | `cache` | Cache effectiveness |
| `keystone_cache_misses_total` | counter | `cache` | Cache effectiveness |

`cache` is the fixed, code-defined set of `tokio::task_local!` caches ADR
0030 introduces (e.g. `role_assignments`, `catalog_endpoints`), not
per-request data.

#### Process / runtime metrics — out of scope

Standard process metrics (`process_cpu_seconds_total`,
`process_resident_memory_bytes`, open file descriptors, Tokio runtime task
counts) are deliberately **not** part of this catalog. They are either
already provided by the container/node exporter (`node_exporter`,
cgroup metrics from the orchestrator) or, for Tokio-internal metrics,
require `tokio-console`/`tokio-metrics`' unstable runtime introspection
APIs, which is a separate decision outside this ADR's scope.

### Rollout

Implementation proceeds subsystem-by-subsystem, each its own PR, in this
order (highest operational value first): HTTP layer → authentication/token
→ policy → rate limiting → Raft → domain providers → the remaining
subsystems. Each PR adds its subsystem's counters/histograms, wires them
into `metrics_handler`, and ships matching alert rules in
`deploy/prometheus/alert_rules.yaml` alongside the existing
`keystone_audit` group, following that file's existing format.

## Consequences

- **Operability:** Operators gain Prometheus-native visibility into auth
  failure rates, token backend health, OPA latency, rate-limit pressure, and
  Raft cluster health, closing the gap where only audit-spool health and
  auth-plugin load failures were observable.
- **Consistency:** A shared `Counter`/`LabeledCounter`/`Histogram` module
  replaces three near-duplicate hand-rolled formatters (audit,
  auth-plugin, and future ones) with one, keeping the "no external metrics
  crate" property while removing per-crate reimplementation.
- **Security:** The cardinality/PII guardrail is a hard requirement for
  every future metric — it prevents both unbounded memory growth (an
  attacker-controlled label value is a cardinality-explosion DoS vector
  against the metrics registry) and the same class of identifier leakage
  ADR 0023 already forbids in audit events.
- **Compatibility:** The four existing metric names are unchanged; nothing
  currently scraping `/metrics` breaks.
- **Cost:** Incremental instrumentation work across most crates in the
  workspace; explicitly phased rather than a single large change.

## Related ADRs

- **0022:** Rate limiting — `keystone_rate_limit_*` scopes match its
  limiter configuration.
- **0023:** Audit — existing metrics, PII-minimization precedent the
  cardinality guardrail extends, and the `/metrics` endpoint this ADR
  builds on.
- **0025:** Dynamic auth plugins — existing
  `keystone_auth_plugin_load_failure` metric, `keystone_auth_plugin_*`
  additions.
- **0016-v2:** Raft storage — source of the `keystone_raft_*` metrics.
- **0030:** Per-request cache — source of the `keystone_cache_*` metrics.

## Alternatives

1. **Adopt the `metrics` + `metrics-exporter-prometheus` crates:**
   Rejected for now — the existing hand-rolled approach was a deliberate
   choice (per `crates/audit/src/metrics.rs`) to avoid the dependency, the
   full catalog here is a fixed, compile-time-known set of series (no
   dynamic registration need that would justify a registry crate), and a
   shared internal primitives module gets the same de-duplication benefit
   without the new dependency. Revisit if a future subsystem needs
   genuinely dynamic label sets a `const`-sized `LabeledCounter` can't
   express.
2. **Per-request-ID or per-project labels for finer-grained dashboards:**
   Rejected — unbounded cardinality risk and conflicts with ADR 0023's PII
   minimization; use structured logs/audit events (already correlated via
   `correlation_id`) for per-request/per-project drill-down instead of
   metrics.
3. **Expose `/metrics` only behind authentication:** Rejected, consistent
   with ADR 0023's existing posture — the metrics/health interface is
   already a separate listener (`interface_metrics`) intended to be
   firewalled to internal scrapers rather than authenticated per-request.
