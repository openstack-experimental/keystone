# OpenTelemetry: traces and metrics

Keystone can export traces and metrics over OTLP, and it always serves the
same metrics as Prometheus text on `/metrics`. This page is the operator
guide; the design is in [ADR 0040](../../adr/0040-opentelemetry.md). For what
to collect, alert on and look at, see [Observability](observability.md).

## Build

OTLP export is compiled in only with a cargo feature:

| Feature | Adds |
| --- | --- |
| `otel` | OTLP over HTTP (protobuf) |
| `otlp-grpc` | OTLP over gRPC; enable it next to `otel` |

```console
cargo build --release -p openstack-keystone --features otel
```

The `[otel]` section is parsed and validated in every build. A build without
the feature that is asked to export logs that it cannot, and runs without
export. `/metrics` does not need the feature.

## Enable export

```ini
[otel]
enabled = true
endpoint = http://otel-collector:4318
service_name = keystone
sampling_rate = 0.1
```

`traces_enabled` and `metrics_enabled` both default to `enabled`; set one to
`false` to export a single signal. For HTTP the signal path (`/v1/traces`,
`/v1/metrics`) is appended to `endpoint`, and the URL scheme decides whether
TLS is used. Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Master switch |
| `traces_enabled`, `metrics_enabled` | `enabled` | Per-signal switch |
| `endpoint` | `http://localhost:4318` (`:4317` for gRPC) | Collector URL |
| `protocol` | `http/protobuf` | or `grpc` |
| `headers` | none | `name=value,name2=value2`, for example an API token. Never logged |
| `timeout` | `10` | Exporter timeout, seconds |
| `insecure` | `false` | gRPC only: connect without TLS. Ignored, with a warning, for HTTP |
| `service_name` | `keystone` | `service.name` resource attribute |
| `resource_attributes` | none | Extra `key=value,key2=value2` resource attributes |
| `sampler` | `parent_based_ratio` | `parent_based_ratio`, `ratio`, `always_on`, `always_off` |
| `sampling_rate` | `1.0` | Ratio in `0.0..=1.0` for root spans (every span with `ratio`) |
| `span_level` | `info` | Most verbose span exported: `error`, `warn`, `info`, `debug`, `trace` |
| `metrics_interval` | `60` | Metric push interval, seconds |
| `include_user_ids` | `false` | Export user, project and domain ids, user names, list filters and the raw URL path on spans |
| `include_client_address` | `false` | Add the caller's IP to request spans |
| `legacy_http_attributes` | `false` | Also emit the `http.method`, `http.user_agent` and `http.status_code` names that `oslo.middleware` uses |
| `response_traceparent` | `false` | Return `traceparent` in responses |

Spans and metrics leave the host, so the two personal-data options are off by
default. Keep them off unless the collector and its backend are trusted with
that data.

## Migrating from `[oslo_middleware_tracing]`

If other OpenStack services run `oslo.middleware`'s tracing, an existing
`[oslo_middleware_tracing]` section is accepted as it is. It only drives
traces, as in `oslo.middleware`.

| `[oslo_middleware_tracing]` | `[otel]` |
| --- | --- |
| `enabled` | `enabled` (traces) |
| `otlp_endpoint` | `endpoint` |
| `otlp_protocol` | `protocol` |
| `service_name` | `service_name` |
| `sampling_rate` | `sampling_rate` |
| `insecure` | `insecure` |

To move over, copy the values into `[otel]` and remove the old section. If
both sections set the same option the `[otel]` value wins and a warning is
logged. Keystone joins the traces of other services through the W3C
`traceparent` and `tracestate` request headers. osprofiler headers
(`X-Trace-Info`, `X-Trace-HMAC`) are not supported.

Differences to know about:

- Spans are named `{method} {route}` with the route template
  (`/v3/users/{user_id}`), not the raw path, so the name has bounded
  cardinality.
- `url.path` and user ids are exported only with `include_user_ids`.
- A client chooses the trace id and, under the default sampler, whether its
  request is sampled. Use `sampler = ratio` to ignore the caller's decision.
- Only spans are exported, never log events.

## Metrics

`GET /metrics` on the `[interface_metrics]` listener (default port `8099`)
returns Prometheus text, as before. Series names, labels and values are
unchanged, so existing dashboards and `deploy/prometheus/alert_rules.yaml`
keep working. What differs in the text:

- Labels are sorted by name and families by name.
- A series appears only after it was first recorded. A family with no sample
  yet has no `# HELP`/`# TYPE` lines (the two audit counters labelled by
  `result`).
- The Raft series are now served; they were not before.

With `metrics_enabled` the same data is pushed every `metrics_interval`
seconds. A scrape does not cause an extra push. Pick one path per series:
scrape Keystone, or collect the pushed data, but do not ingest both into one
store, or the values are counted twice.

## Collector example

An OpenTelemetry Collector that receives Keystone's OTLP and forwards traces
to Tempo and metrics to Prometheus remote-write:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch: {}

exporters:
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true
  prometheusremotewrite:
    endpoint: http://prometheus:9090/api/v1/write

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheusremotewrite]
```

Keystone side:

```ini
[otel]
enabled = true
endpoint = http://otel-collector:4318
resource_attributes = deployment.environment=prod
```

## Checking it works

1. Start with `[otel] enabled = true` and check the startup log for telemetry
   warnings, such as a build without the `otel` feature.
2. `curl http://keystone:8099/metrics` lists `keystone_http_requests_total`
   after the first request.
3. At the collector, a `POST /v1/metrics` should arrive every
   `metrics_interval` seconds, and a `POST /v1/traces` once sampled requests
   were served.
