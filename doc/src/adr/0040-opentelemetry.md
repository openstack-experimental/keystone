# 40. OpenTelemetry as the telemetry pipeline

**Date:** 2026-10-06

## Status

Proposed.

## Reference

Tracking issue #1411. Related: #720 (metrics example), #934 (tracing
instrumentation), #1409 (`cadf` OTel prototype), ADR 0031 (Prometheus metrics),
ADR 0039 (config engine and section registry).

## Context

Keystone exposes metrics through `openstack-keystone-metrics`: about 500 lines
of atomic counters, fixed-bucket histograms and Prometheus text rendering,
roughly 40 instruments in `core`, `storage`, `cadf` and `keystone`, each
subsystem hand-writing its own `format_prometheus_text`. Tracing uses the
`tracing` crate (about 440 `#[instrument]` sites), but
`server/startup/tracing_init.rs` installs only fmt layers: nothing leaves the
process as a trace.

The OpenStack ecosystem is converging on OpenTelemetry. `oslo.middleware` ships
`oslo_middleware.tracing.TracingMiddleware`, which creates one SERVER span per
request, propagates W3C `traceparent`/`tracestate` and exports over OTLP, and
is configured by an `[oslo_middleware_tracing]` group (`enabled`,
`otlp_endpoint`, `otlp_protocol`, `service_name`, `sampling_rate`, `insecure`).
Operators who run it on other services expect Keystone to take the same
configuration and join the same traces.

## Decision

OTLP is a first-class output for both traces and metrics. Option 4 of #1411 is
adopted: `openstack-keystone-metrics` is replaced by the OpenTelemetry SDK. The
`/metrics` Prometheus endpoint stays, as a pull view of the same SDK data.

### Crate and features

A new crate `openstack-keystone-telemetry` owns the `Resource`, the
`TracerProvider`, the `MeterProvider`, the OTLP exporters, the propagators and
the shutdown flush. `tracing_init::init` builds it and returns a guard that also
holds the file-appender `WorkerGuard`; the guard is flushed from the graceful
shutdown path in the listeners.

Cargo feature `otel` is off by default. With it on, `otlp-http` (HTTP/protobuf)
is the default transport and `otlp-grpc` (tonic) is optional. With the feature
off, instrumentation compiles to no-ops so call sites carry no `cfg`.

### Configuration

A native `[otel]` section, registered through the section registry (ADR 0039):
`enabled`, `traces_enabled`, `metrics_enabled` (both default to `enabled`),
`endpoint`, `protocol` (`http/protobuf` or `grpc`), `headers`, `timeout`,
`insecure`, `service_name` (default `keystone`), `resource_attributes`,
`sampler`, `sampling_rate`, `metrics_interval` and `include_user_ids`
(default `false`).

`[oslo_middleware_tracing]` is a registered alias section:

| `[oslo_middleware_tracing]` | `[otel]` |
| --- | --- |
| `enabled` | `enabled` (traces) |
| `otlp_endpoint` | `endpoint` |
| `otlp_protocol` | `protocol` |
| `service_name` | `service_name` |
| `sampling_rate` | `sampling_rate`, wrapped parent-based |
| `insecure` | `insecure` |

If both sections set the same option the native one wins and a warning is
logged. The alias drives traces only, as in `oslo.middleware`. osprofiler
(`X-Trace-Info`/`X-Trace-HMAC`) is not supported.

### Traces

A `tracing-opentelemetry` layer is added to the registry with its own `Targets`
filter (the `deps_targets` pinning applies to spans too). A custom `MakeSpan` on
`TraceLayer`:

- extracts `traceparent`/`tracestate` as the remote parent;
- names spans `HTTP {method} {route}` where `route` is the Axum `MatchedPath`
  template (the oslo middleware uses the raw path, which is unbounded);
- sets the stable HTTP semantic-convention attributes, and the legacy
  `http.method`/`http.url`/`http.status_code` names behind an option;
- sets `openstack.request_id` and `openstack.global_request_id`;
- sets `openstack.user_id`, `openstack.project_id` and `openstack.domain_id`
  only when `include_user_ids` is true;
- marks 5xx responses as errors.

Echoing `traceparent` in responses is optional and off by default. The
`x-request-id` layer and the `access_log` ordering are unchanged; the access log
gains the trace id.

Trace context is untrusted client input. It may select the trace id and the
parent sampling decision; it must never influence authorization (security-model
invariants). `#[instrument]` sites on authentication, token, credential, EC2 and
trust paths must `skip` secrets, because spans now leave the host.

### Metrics

Each instrument becomes an SDK instrument built from one global `Meter`.
Histograms keep the existing `DEFAULT_LATENCY_BUCKETS` as explicit bounds.

The ADR 0031 cardinality rule was enforced by types (`const N` label names,
callers pass `&str`). It stays type-level: `openstack-keystone-telemetry`
provides typed attribute helpers that accept only `&'static str` or enum-backed
label values, never an owned `String`.

`/metrics` is served from a pull reader registered on the same `MeterProvider`
as the OTLP periodic reader, rendered by a small in-tree encoder with explicit
series naming (`_total` for counters, `_bucket`/`_sum`/`_count` for histograms).
`deploy/prometheus/alert_rules.yaml` and ADR 0031 names are preserved, enforced
by a golden test captured from the current implementation before the migration.
A third-party Prometheus bridge crate is not used.

Operators scrape `/metrics` or push OTLP, not both for the same series, or a
collector that re-exposes Prometheus double counts.

Exemplars (trace-linked histogram buckets) are the main capability gained.
Their stability in the Rust SDK has not been verified; if they are not ready
they are follow-up work, not a blocker.

### Rollout

1. Golden `/metrics` test and the benchmark harness (`tests/otel-bench`).
2. This ADR.
3. `openstack-keystone-telemetry`, `[otel]` and alias sections, the `otel`
   feature, the guard and shutdown flush.
4. Traces: layer, `MakeSpan`, propagation, `#[instrument]` audit.
5. Metrics, part 1: typed wrappers, the pull reader and encoder, `/metrics` on
   the SDK with one subsystem migrated.
6. Metrics, part 2: remaining subsystems, grouped by crate.
7. Remove `openstack-keystone-metrics`; re-run the golden test and benchmark.
8. Operator documentation, including migration from
   `[oslo_middleware_tracing]` and a collector example.

## Benchmark

`tests/otel-bench` (standalone crate, `cargo bench` inside it) compares the
current primitives with SDK synchronous instruments, and measures the cost of
the OTel span layer. Run on a shared 4-vCPU cloud VM, criterion, 3 s
measurement per case, single run. Treat as indicative: the VM is noisy and the
contended cases in particular vary between runs. Versions: `opentelemetry` and
`opentelemetry_sdk` 0.33, `tracing-opentelemetry` 0.34.

Instruments (median per call; the contended rows are the slowest of 4 threads
hitting one series):

| Case | `keystone-metrics` | OTel SDK |
| --- | --- | --- |
| counter, unlabeled | 6.4 ns | 12.0 ns |
| counter, 2 labels | 81 ns | 103 ns |
| histogram, 1 label | 106 ns | 72 ns |
| counter, 2 labels, 4 threads | 1.31 us | 0.75 us |
| histogram, 1 label, 4 threads | 0.68 us | 1.37 us |

Spans (one two-field span, enter and exit):

| Case | Cost per span |
| --- | --- |
| no subscriber | 1.9 ns |
| bare registry (no consumer) | 0.2 - 1.4 us (bimodal, noisy) |
| OTel layer, sampler off | 1.25 us |
| OTel layer, ratio 0.1 | 1.30 us |
| OTel layer, always on, batch processor | 1.97 us |

Reading:

- Synchronous SDK instruments are in the same range as the current atomics:
  slower on the cheapest cases, faster on the labeled histogram and the contended
  counter. All are tens to hundreds of nanoseconds, against token validation and
  policy evaluation paths that take microseconds to milliseconds. No hot-path
  regression is visible at this level, so the SDK instruments are adopted
  directly. The observable-callback fallback (keep atomics, publish through
  callbacks) is not needed and is dropped.
- The span layer costs about 1.2 us per span even when the sampler drops the
  span, because `tracing-opentelemetry` builds span data before the sampling
  decision. With about 440 `#[instrument]` sites, a request that crosses 20
  spans pays roughly 25 - 40 us. The OTel layer therefore gets its own filter
  that admits only request-level and coarse operation spans (INFO and above for
  Keystone targets), not every driver-level DEBUG span; spans the layer filter
  rejects do not reach the layer and cost the same as today.
- The result must be re-measured end to end with `tools/run-loadtest-local.sh`
  once step 4 lands, with the layer off, on with ratio sampling, and always on.

## Consequences

- One pipeline and one resource identity for traces and metrics; OTLP push works
  without a scrape path, and Keystone joins traces started by other OpenStack
  services using `oslo.middleware` tracing.
- About 500 lines of exposition code and the per-subsystem
  `format_prometheus_text` implementations go away; a smaller encoder and a
  golden test replace them.
- New dependencies (`opentelemetry`, `opentelemetry_sdk`, an OTLP exporter,
  `tracing-opentelemetry`) behind the `otel` feature. The default build is
  unchanged until the metrics migration step, after which `/metrics` depends on
  the SDK and so on the feature; a build without `otel` keeps a minimal
  in-process path, to be settled in step 5.
- The bounded-label rule moves from a type-level check in one crate to typed
  helpers in another; reviewers still check that label sources are bounded.
- ADR 0031's "continue hand-rolled exposition" decision is superseded; its
  catalog, naming and cardinality rules still apply.
