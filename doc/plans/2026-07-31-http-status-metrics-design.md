# HTTP Status Metrics — Design

Date: 2026-07-31
Status: Approved
Related: `doc/src/adr/0031-prometheus-metrics.md`

## Purpose

Implement the HTTP request metric trio already catalogued in ADR 0031:

- `keystone_http_requests_total{method, route, status}` (counter)
- `keystone_http_request_duration_seconds{method, route}` (histogram)
- `keystone_http_requests_in_flight{interface}` (gauge)

so operators can watch 5xx rate and latency per route without scraping logs.

## Constraints carried from ADR 0031

- `route` must be the Axum `MatchedPath` template (e.g. `/v3/users/{user_id}`),
  never the raw path — resource IDs must never appear as a label value.
- `core` crate must stay HTTP-unaware; nothing here may be added to
  `crates/core/src/keystone.rs`'s `Service` struct.
- No `unwrap()`/`expect()`/`unsafe`; hand-rolled Prometheus text exposition
  (no `prometheus`/`metrics` crate), consistent with
  `crates/audit/src/metrics.rs`.

## Module layout

New file `crates/keystone/src/server/http_metrics.rs`, sibling to
`access_log.rs`. Contains:

- `HttpMetrics` struct (state)
- `record_http_metrics` (Axum middleware)
- `format_prometheus_text` (exposition formatter, same shape as
  `openstack_keystone_audit::metrics::format_prometheus_text`)

## State shape

```rust
pub struct HttpMetrics {
    requests_total: DashMap<(Method, String, u16), AtomicU64>,   // (method, route, status)
    duration_seconds: DashMap<(Method, String), Histogram>,      // (method, route)
    in_flight: DashMap<Interface, AtomicI64>,
}
```

`Histogram` is a small hand-rolled bucket-counter (cumulative counts per
bucket + a running sum), consistent with the project's no-external-metrics-
crate decision. Bucket bounds (keystone-tuned, tighter low end for fast
auth/token paths):

```
0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5
```

`dashmap = "6.2"` is already a workspace dependency (used elsewhere in the
tree) — no new dependency to add.

`Interface` is the existing enum from `crates/config/src/common.rs`
(`Admin`/`Internal`/`Public`). **This is a security-relevant extension, not
just a config type**: `spiffe_tls.rs`'s `attach_request_context` inserts it
into `axum::http::Extensions` at connection-accept time on the mTLS
listeners, and `crates/core/src/api/auth.rs:88,127` reads it to gate the
admin-SVID short-circuit auth path (`interface == Interface::Admin`). The
public listener never inserts it; `auth.rs:88` defaults to
`Interface::Public` when absent.

Consequently this design does **not** add any `.layer(Extension(Interface::…))`
to the listeners — doing so risks shadowing/overwriting the
already-security-critical value depending on tower layer ordering, which is
exactly the class of authentication-chain bug the security model guards
against. `record_http_metrics` only **reads** the extension the same way
`auth.rs:88` already does:

```rust
let interface = req
    .extensions()
    .get::<Interface>()
    .copied()
    .unwrap_or(Interface::Public);
```

The enum gets `Copy, Eq, Hash` derives (currently `Debug, Deserialize, Clone,
PartialEq`) so it can be used as a `DashMap` key, plus one new variant:

```rust
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interface {
    Admin,
    Internal,
    Public,
    Metrics,
}
```

`Metrics` is safe to add because it is only ever inserted on the fully
separate `metrics_app` router (`spawn_metrics_listener`), which has no `Auth`
extractor and is never merged into `build_router`'s `app` — it cannot shadow
or interact with the security-critical `Admin`/`Internal`/`Public` values set
by the mTLS listeners. `spawn_metrics_listener` adds
`.layer(Extension(Interface::Metrics))` to `metrics_app` only, and a
lightweight variant of the middleware (or the same `record_http_metrics`,
reused) is layered there purely for the `in_flight` gauge's `metrics` value —
matching ADR 0031's stated `interface ∈ {public, internal, admin, metrics}`.
The `requests_total`/`duration_seconds` breakdown is not expected to be
meaningful for the single `/metrics` route, so this listener only needs to
participate in the in-flight gauge, not the full trio.

## Config gate

New field on the existing `MetricsInterface` config struct
(`crates/config/src/interface.rs`):

```rust
pub struct MetricsInterface {
    pub tcp_address: SocketAddr,
    #[serde(default = "default_true")]
    pub http_requests_enabled: bool,
}
```

Default `true`. Only gates this HTTP trio — the pre-existing audit and
auth-plugin-load-failure metrics stay always-on and are unaffected.

When `false`: the middleware layer is **not added** to the router (zero
runtime overhead), and `metrics_handler` skips the HTTP-metrics text block
entirely. `tower::Layer` has no blanket impl for `Option<L>`, so the
conditional layer is applied as a plain `if` around an extra `Router::layer`
call *after* the shared `ServiceBuilder` middleware stack has already been
applied and collapsed into a `Router` (`Router::layer` always returns
`Router<S>` regardless of the layer's concrete type, so this doesn't change
the surrounding code's types):

```rust
let mut app = /* ...existing merge/nest/layer(middleware) as today... */;

let http_metrics = if shared_state.config_manager.config.read().await
    .interface_metrics.http_requests_enabled
{
    let hm = Arc::new(HttpMetrics::new());
    app = app
        .layer(Extension(hm.clone()))
        .layer(middleware::from_fn(record_http_metrics));
    Some(hm)
} else {
    None
};
```

## State threading

- `build_router`'s return type changes from `Result<Router, Report>` to
  `Result<(Router, Option<Arc<HttpMetrics>>), Report>` — it constructs the
  `Arc<HttpMetrics>` itself (reading the config flag it already has access
  to via `shared_state`, same as the existing `webauthn.enabled` check) and
  hands the instance back to the caller.
- `main()` destructures that tuple and passes the `Option<Arc<HttpMetrics>>`
  into `spawn_metrics_listener` as a new parameter, so both places share the
  same instance.
- `spawn_metrics_listener` adds `.layer(Extension(http_metrics.clone()))` to
  `metrics_app` (only when `Some`) so `metrics_handler` can read it via
  `Option<Extension<Arc<HttpMetrics>>>`.
- No new `Interface` insertion on the public/internal/admin path —
  `record_http_metrics` reads the `Interface` extension already stamped by
  existing connection-level code (see State shape section above for why
  insertion is deliberately avoided there). The metrics listener is the one
  exception, as already described.

`Extension` is used (not `from_fn_with_state`/second `State`) because
`main_router`/`metrics_router` are already typed `Router<ServiceState>`;
adding a second distinct state type would require threading it through
every nested router (`webauthn`, `SCIM`) and OpenAPI-generated routers.
`Extension` sidesteps that — it rides in `Request` extensions independent of
the router's `State` generic.

## Middleware

`record_http_metrics` layered immediately after `log_request` in
`build_router`'s `ServiceBuilder` chain (same position rationale: needs to
see the final response status, so it runs inside `TraceLayer`'s span but
after body compression/propagation don't matter for this metric).

Per request:

1. Read `Extension<Interface>` (defaults to `Interface::Public` if somehow
   absent — should not happen in practice since every listener tags itself).
2. Increment `in_flight[interface]` on entry.
3. Run `next.run(req)`, timing with `Instant`.
4. Read `MatchedPath` from request extensions; falls back to the literal
   string `"unmatched"` when absent (404 / probed paths) — bounds
   cardinality against path-probing traffic instead of letting arbitrary
   attacker-supplied paths become label values.
5. Decrement `in_flight[interface]`.
6. Increment `requests_total[(method, route, status)]`.
7. Record latency into `duration_seconds[(method, route)]`.

## Exposition

`metrics_handler` (in `keystone.rs`) gains a third block, appended after the
existing audit and auth-plugin-load-failure text, only when
`Extension<Arc<HttpMetrics>>` is present (i.e. feature enabled):

```rust
async fn metrics_handler(
    State(state): State<ServiceState>,
    http_metrics: Option<Extension<Arc<HttpMetrics>>>,
) -> impl IntoResponse {
    let mut body = format_prometheus_text(&state.audit_dispatcher);
    body.push_str(&format_load_failure_metrics(&*state.auth_plugin_load_failures.read().await));
    if let Some(Extension(http)) = http_metrics {
        body.push_str(&http_metrics::format_prometheus_text(&http));
    }
    ...
}
```

Same `text/plain; version=0.0.4` content type, same `/metrics` endpoint —
no new route.

## Testing

- `http_metrics.rs` `tests` submodule: formatter output shape (counter/
  histogram/gauge text lines, `_total`/`_bucket`/`_sum`/`_count` suffixes),
  unmatched-path fallback, histogram bucket placement at boundary values,
  concurrent-increment correctness.
- Extend existing `build_router_*` tests in `keystone.rs`'s test module to
  cover both `http_requests_enabled = true` (layer present, `/metrics`
  includes the new block) and `= false` (layer absent, block absent) —
  confirms the config gate actually removes the middleware rather than
  just suppressing output.
- `MetricsInterface` config parsing test (`crates/config`) for the new
  field's default and explicit-`false` override, alongside the existing
  `enable_proxy_headers_parsing`-style tests.

## Non-goals / deferred

- No changes to `deploy/prometheus/alert_rules.yaml` in this pass (can
  follow once the metric is live and real cardinality/volume is observed).
- No dashboard/Grafana work.
- Duration histogram does not distinguish streaming vs buffered responses;
  out of scope.
