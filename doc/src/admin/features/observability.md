# Observability

This page describes how to run Keystone so that its health and behaviour can be
watched: which signals exist, what to collect, what to alert on and how to find
the cause of a slow or failing request. The options of the exporter are in the
[OpenTelemetry](opentelemetry.md) guide, the audit trail has its own
[page](audit.md).

## Signals

| Signal  | Source                                                                 | Use it for                                                |
| ------- | ---------------------------------------------------------------------- | --------------------------------------------------------- |
| Metrics | `GET /metrics` (Prometheus text) on `[interface_metrics]`, port `8099` | Dashboards and alerts: rates, errors, latency, saturation |
| Traces  | OTLP export (`[otel]`, needs the `otel` build feature)                 | Finding where one slow or failed request spent its time   |
| Logs    | stdout of the process                                                  | Startup problems and errors                               |
| Audit   | `[audit]` sinks                                                        | Who did what, tamper-evident. Not a monitoring signal     |

Metrics tell that something is wrong, traces tell where. Start with metrics and
add tracing when the first questions of the form "which step is slow?" arrive.

## Reference architecture

```text
keystone-rs pods ──/metrics──▶ Prometheus ──▶ Grafana ◀── Jaeger / Tempo
        └────────── OTLP/HTTP traces ───────────────────────▲
```

- **Metrics are scraped**, not pushed. Prometheus pulls `/metrics` from every
  pod. Leave `metrics_enabled = false` (with `enabled = true` for traces) unless
  a collector is the only path into your metrics store: ingesting a series
  through both paths counts it twice.
- **Traces are pushed** over OTLP to a collector or directly to a backend that
  accepts OTLP (Jaeger v2, Tempo, a vendor agent).
- Run a collector close to Keystone when the backend needs authentication,
  batching or fan-out; set `headers` when the endpoint needs a token.
- The `[interface_metrics]` listener is unauthenticated. Bind it to a cluster
  internal address and never publish it through the public ingress.

### Scraping

With a fixed set of hosts:

```yaml
scrape_configs:
  - job_name: keystone
    static_configs:
      - targets: [keystone-1:8099, keystone-2:8099, keystone-3:8099]
```

On Kubernetes, scrape every pod, not the load-balanced service, so that each
instance has its own series (Raft leadership, per-node latency). A headless
service gives that without access to the Kubernetes API:

```yaml
scrape_configs:
  - job_name: keystone
    dns_sd_configs:
      - names: [keystone-internal]
        type: A
        port: 8099
```

The manifests in `tools/k8s/observability` in the repository are a complete,
non-production example of this layout. See the
[contributor page](../../contributor/observability.md) for how to run them.

## What to watch

The catalog of all series is in
[ADR 0031](../../adr/0031-prometheus-metrics.md). These are the ones to build a
first dashboard from.

| Question                | Query                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Is it up and serving?   | `sum by (status) (rate(keystone_http_requests_total[5m]))`                                                            |
| Error ratio             | `sum(rate(keystone_http_requests_total{status=~"5.."}[5m])) / sum(rate(keystone_http_requests_total[5m]))`            |
| Slowest routes (p95)    | `histogram_quantile(0.95, sum by (le, route) (rate(keystone_http_request_duration_seconds_bucket[5m])))`              |
| Login failures          | `sum by (method) (rate(keystone_auth_attempts_total{outcome="failure"}[5m]))`                                         |
| Brute-force lockouts    | `increase(keystone_auth_lockouts_total[15m])`                                                                         |
| Throttled clients       | `sum by (scope) (rate(keystone_rate_limit_rejections_total[5m]))`                                                     |
| Policy engine trouble   | `rate(keystone_policy_errors_total[5m])`                                                                              |
| Cache effectiveness     | `rate(keystone_cache_hits_total[5m]) / (rate(keystone_cache_hits_total[5m]) + rate(keystone_cache_misses_total[5m]))` |
| Raft leader exists      | `sum(keystone_raft_is_leader) == 1`                                                                                   |
| Follower falling behind | `keystone_raft_replication_lag`                                                                                       |

Route labels are the route templates (`/v3/users/{user_id}`), so the number of
series stays bounded.

### Alerts

`deploy/prometheus/alert_rules.yaml` ships the audit alerts (dropped records,
spool failures, sink errors, backlog). Load it as a rule file and add rules for
the service itself, for example:

```yaml
groups:
  - name: keystone-service
    rules:
      - alert: KeystoneHighErrorRatio
        expr: |
          sum(rate(keystone_http_requests_total{status=~"5.."}[5m]))
            / sum(rate(keystone_http_requests_total[5m])) > 0.05
        for: 10m
        labels: { severity: page }
      - alert: KeystoneSlowTokenIssue
        expr: |
          histogram_quantile(0.95, sum by (le)
            (rate(keystone_http_request_duration_seconds_bucket{route="/v3/auth/tokens"}[5m]))) > 1
        for: 10m
        labels: { severity: warning }
      - alert: KeystoneNoRaftLeader
        expr: sum(keystone_raft_is_leader) != 1
        for: 1m
        labels: { severity: page }
```

Tune the thresholds to the observed baseline. Keep the `for:` long enough to
ride out a rolling restart.

## Traces

### Structure

A trace of one request is a tree. The root is the HTTP request, named
`{method} {route}`. Below it are the layers that did the work:

| Layer                  | Span name                            | Tells you                                     |
| ---------------------- | ------------------------------------ | --------------------------------------------- |
| HTTP                   | `GET /v4/role_assignments`           | Total time, status code                       |
| API handler            | `api::<operation>`                   | Handler time without the transport            |
| Authentication, policy | `auth.*`, `policy.*`                 | Token validation, scoping, OPA round trip     |
| Provider               | `provider.<domain>.<method>`         | Business logic and caching of one domain      |
| Driver                 | `driver.<backend>.<domain>.<method>` | One storage call (`sql`, `raft`, `ldap`, ...) |

Provider and driver spans carry the identifiers or filter of the call (for
example `role_id`, `params`), never request bodies, passwords or tokens. A
driver span is the number to read when a database or the Raft store is
suspected: its duration is the storage time, and a parent much longer than the
sum of its children is time spent in Keystone itself.

### Choosing the verbosity

Only spans at or above `span_level` are exported:

| `span_level`     | Exports                                                         | Cost                                                                 |
| ---------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- |
| `info` (default) | The HTTP root span only                                         | Lowest. Enough for latency and status by route                       |
| `debug`          | Plus handler, authentication, policy, provider and driver spans | A request produces tens of spans. Use for investigations and staging |
| `trace`          | Plus per-item helper spans in loops                             | Very large traces. Short debugging sessions only                     |

With the default you see that `POST /v3/auth/tokens` is slow but not why. For
production, a good compromise is `span_level = debug` with a low `sampling_rate`
(for example `0.01`), so a small share of requests is traced in full.
`span_level` is read at startup; changing it needs a restart.

### Sampling

- `parent_based_ratio` (default) follows the decision of the caller and samples
  `sampling_rate` of the requests that arrive without one. This keeps traces
  whole across services.
- Because the caller decides, an untrusted client can force sampling by sending
  a `traceparent` header. Use `sampler = ratio` on a Keystone that is reachable
  by clients you do not control.
- To follow one request, send a `traceparent` with the sampled flag, or set
  `response_traceparent = true` so that responses carry the trace id for support
  tickets.

### Finding a slow request

1. In the metrics, find the route and the time window (`p95` by `route`).
2. In the trace backend, select the service (`service_name`), the operation
   `{method} {route}`, a _minimum duration_ near the p95 and the same window.
3. Open a trace and read the longest driver span. Many identical spans in a row
   point at a loop that should be one query; a single long driver span points at
   the storage; a gap between a parent and its children is time inside Keystone,
   or in policy evaluation when a `policy.*` span is long.
4. Compare with a fast trace of the same route.

Spans are exported in batches, so a trace shows up in the backend a few seconds
after the request.

## Privacy and data handling

Spans leave the host. By default they contain route templates, status codes and
the identifiers of the resources a call touched, but not user, project or domain
ids, user names, list filters, the raw URL path or the client address. The
exporter strips the former from every span, including the `debug` provider and
driver spans, so raising `span_level` does not change this. The options that add them
(`include_user_ids`, `include_client_address`) are off for that reason; switch
them on only when the collector and the backend are trusted with personal data
and covered by your retention rules.

Keep the stack's own access in mind: anyone who can read the trace backend sees
what operations happen on the cloud, and anyone who can write to Grafana can
change the dashboards and alerts you rely on. Authenticate and TLS-protect
Prometheus, Grafana and the trace UI. The development stack allows anonymous
admin access and must not be used as a model for that.

## Capacity

- Metrics cost is bounded: labels are route templates and small enums. A scrape
  every 15 s per pod is typical.
- Trace volume is `requests/s × sampling_rate × spans per request`. At
  `span_level = debug` that is 30 to 60 spans per request, so 1 % sampling at
  500 requests/s is about 150 to 300 spans/s. Size the backend retention and
  storage for that, and prefer a collector with a `batch` processor in front.
- Export is asynchronous and bounded. When the collector is down, spans are
  dropped rather than queued without limit, so a failing observability stack
  does not slow Keystone down; it shows as missing data.

## Troubleshooting

| Symptom                                      | Check                                                                                                                                                     |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No `keystone` service in the trace backend   | The binary was built with `--features otel`; the startup log has no telemetry warning; `endpoint` is reachable from the pod; a sampled request was served |
| Only root spans, no provider or driver spans | `span_level` is `info`; set `debug` and restart                                                                                                           |
| Traces missing for some requests             | Sampling; the caller sent a `traceparent` without the sampled flag under `parent_based_ratio`                                                             |
| Metrics series appear twice                  | Both scrape and OTLP push feed one store; set `metrics_enabled = false` or drop the scrape job                                                            |
| Prometheus target is down                    | `[interface_metrics]` binds to `127.0.0.1`; network policy blocks port `8099`                                                                             |
| Raft series missing                          | The deployment does not use the Raft storage driver                                                                                                       |
| Exporter errors in the log                   | Wrong `endpoint` or `protocol`; the `headers` token is missing or expired; for gRPC without TLS set `insecure = true`                                     |
