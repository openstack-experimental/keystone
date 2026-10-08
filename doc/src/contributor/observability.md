# Observability stack

The development stack can ship Keystone's traces and metrics to local backends,
so a change to the telemetry (ADR 0040) can be looked at end to end. For the
production configuration see the
[OpenTelemetry guide](../admin/features/opentelemetry.md).

| Component                         | Role                                          | Local port                       |
| --------------------------------- | --------------------------------------------- | -------------------------------- |
| Jaeger v2 (all-in-one, in-memory) | Receives OTLP traces, UI and query API        | `16686` (UI), `4318` (OTLP/HTTP) |
| Prometheus                        | Scrapes `/metrics` of every `keystone-rs` pod | `9090`                           |
| Grafana                           | Queries both, anonymous admin                 | `3000`                           |

Traces are pushed over OTLP. Metrics are only scraped: the stack sets
`metrics_enabled = false`, so no series is ingested twice. Everything is stored
in memory and lost on restart. Never expose the stack, Grafana allows anonymous
admin access.

## Running it on k3s

The manifests are in `tools/k8s/observability` and the skaffold module is
`observability`. Deploy the backends first, then Keystone with the `otel`
profile, which selects `tools/k8s/keystone/overlays/skaffold-otel` and
configures `[otel]` through `OS_OTEL__*` environment variables:

```console
skaffold run -m observability
skaffold run -m infra,keystone -p local,otel --default-repo localhost:5000
```

The `keystone` image is built with the `otel` cargo feature in every case; it
only compiles the exporters in, and they stay off without the profile. To look
at the UIs, use the ingress hosts `jaeger.local`, `prometheus.local` and
`grafana.local` (same scheme as `keystone.local`; add them to `/etc/hosts` next
to the Keystone ones, pointing at the ingress address):

```console
192.168.2.121 jaeger.local prometheus.local grafana.local
```

## Running it without Kubernetes

Start Jaeger, then the live API test server with the export switched on:

```console
docker run --rm -p 4318:4318 -p 16686:16686 jaegertracing/jaeger:2.9.0
KEYSTONE_TEST_OTLP_ENDPOINT=http://127.0.0.1:4318 \
JAEGER_QUERY_URL=http://127.0.0.1:16686 \
  cargo nextest run --profile api -p test_api --test integration_api_v4 observability
```

`tools/start-api.sh` builds `keystone` with the `otel` feature and enables
`[otel]` whenever `KEYSTONE_TEST_OTLP_ENDPOINT` is set. The test sends a request
with a sampled `traceparent` and expects the span in Jaeger and the series on
`/metrics`. It is skipped without `JAEGER_QUERY_URL`. In CI the `Test` job runs
Jaeger as a service container and sets both variables for the REST API tests.

## Queries

Prometheus (`http://prometheus.local`, or Grafana's Explore):

```promql
# 95th percentile request latency per route
histogram_quantile(0.95,
  sum by (le, route) (rate(keystone_http_request_duration_seconds_bucket[5m])))

# Requests per second by status class
sum by (status) (rate(keystone_http_requests_total[5m]))

# Failed logins per authentication method
sum by (method) (rate(keystone_auth_attempts_total{outcome="failure"}[5m]))

# Rate limiter rejections
sum by (scope) (rate(keystone_rate_limit_rejections_total[5m]))
```

Jaeger (`http://jaeger.local`):

- _Service_ `keystone`, _Operation_ `POST /v3/auth/tokens` lists the token
  issuing requests. Operations are named `{method} {route template}`.
- _Min Duration_ `100ms` narrows the list to slow requests, and the _Tags_ field
  takes `http.response.status_code=500` for failures.
- A request with a `traceparent` header is found by its trace id, which also
  works through the API: `curl localhost:16686/api/traces/<trace-id>`.

## Troubleshooting

- No service `keystone` in Jaeger: check that the pod runs the image built with
  the `otel` feature and that the startup log has no telemetry warning. A build
  without the feature logs one and exports nothing.
- Spans are exported in batches, so they show up a few seconds late.
- Jaeger and Prometheus keep their data in memory. Redeploying the
  `observability` module restarts them and clears it, and a service only shows
  up in Jaeger once it has sent a trace, so send a request to Keystone
  afterwards.
- Grafana _Drilldown > Traces_ does not list the Jaeger data source, the app
  only supports Tempo. Use _Explore_ with the Jaeger data source or the Jaeger
  UI instead.
- Grafana _Explore_ with the Jaeger data source answers `400 Bad Request` for an
  empty search, because Jaeger requires a service. Pick the service `keystone`
  in the _Search_ tab, or paste a trace id in the _TraceID_ tab.
- Prometheus target `keystone` is empty: the targets come from the DNS name of
  the headless service `keystone-rs-internal`, which has to resolve.
- Only the root `GET /v3/...` spans and a few others show up: `span_level`
  defaults to `info`, which drops the `debug` provider and driver spans. The
  stack sets `OS_OTEL__SPAN_LEVEL=debug` in the `otel` overlay, so a deployment
  without it, or with another overlay, only exports the coarse spans.
- The default sampler follows the caller's `traceparent`. `sampling_rate` is
  `1.0` in this stack so that every root span is kept.
