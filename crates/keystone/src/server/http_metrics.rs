// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # HTTP request metrics (ADR 0031, ADR 0040)
//!
//! The HTTP request trio (`keystone_http_requests_total`,
//! `keystone_http_request_duration_seconds`,
//! `keystone_http_requests_in_flight`) on the OpenTelemetry SDK, served on
//! `/metrics` and, when configured, pushed over OTLP.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::extract::{Extension, MatchedPath, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use openstack_keystone_config::Interface;
use openstack_keystone_telemetry::metrics::{
    CounterVec, HistogramVec, LATENCY_BUCKETS, Label, Meter, UpDownCounterVec,
};

/// Every listener interface, for the zero-initialised in-flight series.
const INTERFACES: [Interface; 4] = [
    Interface::Public,
    Interface::Internal,
    Interface::Admin,
    Interface::Metrics,
];

/// Maps an [`axum::http::Method`] to a bounded label value for the
/// `method` Prometheus label: the 9 standard HTTP methods, or the literal
/// `"other"` for anything else.
///
/// `record_http_metrics` runs *before* axum's routing produces 404/405, so
/// an unauthenticated client can send arbitrary RFC-token HTTP methods
/// (hyper's `Method::Extension` accepts any token) straight into this
/// middleware. Without this bound, each distinct attacker-supplied method
/// string would mint its own permanent series: unbounded memory growth and
/// an unbounded `/metrics` payload (ADR 0031). Mirrors the `route`
/// label's `"unmatched"` fallback for unmatched paths.
fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "other",
    }
}

fn interface_label(interface: Interface) -> &'static str {
    match interface {
        Interface::Public => "public",
        Interface::Internal => "internal",
        Interface::Admin => "admin",
        Interface::Metrics => "metrics",
    }
}

/// The HTTP request instruments.
pub struct HttpMetrics {
    /// `keystone_http_requests_total{method,route,status}`.
    requests_total: CounterVec<3>,
    /// `keystone_http_request_duration_seconds{method,route}`.
    duration_seconds: HistogramVec<2>,
    /// `keystone_http_requests_in_flight{interface}`.
    in_flight: UpDownCounterVec<1>,
}

impl HttpMetrics {
    /// Create the instruments on `meter`. The in-flight series of every
    /// interface exist from the start, at zero.
    pub fn new(meter: &Meter) -> Self {
        let metrics = Self {
            requests_total: CounterVec::new(
                meter,
                "keystone_http_requests_total",
                "Total HTTP requests by method, route, and status.",
                ["method", "route", "status"],
            ),
            duration_seconds: HistogramVec::new(
                meter,
                "keystone_http_request_duration_seconds",
                "HTTP request latency by method and route.",
                ["method", "route"],
                &LATENCY_BUCKETS,
            ),
            in_flight: UpDownCounterVec::new(
                meter,
                "keystone_http_requests_in_flight",
                "In-flight HTTP requests by listener interface.",
                ["interface"],
            ),
        };
        for interface in INTERFACES {
            metrics
                .in_flight
                .add(0, [Label::fixed(interface_label(interface))]);
        }
        metrics
    }

    /// Record one completed request. `route` is the matched route template
    /// or `"unmatched"`, never the raw path (ADR 0031).
    pub fn record_request(&self, method: &Method, route: &str, status: u16, elapsed: Duration) {
        let method = Label::fixed(method_label(method));
        let route = Label::bounded(route);
        // A status code is one of a small closed set.
        let status = status.to_string();
        self.requests_total
            .inc([method, route, Label::bounded(&status)]);
        self.duration_seconds
            .record(elapsed.as_secs_f64(), [method, route]);
    }

    pub fn inc_in_flight(&self, interface: Interface) {
        self.in_flight
            .add(1, [Label::fixed(interface_label(interface))]);
    }

    pub fn dec_in_flight(&self, interface: Interface) {
        self.in_flight
            .add(-1, [Label::fixed(interface_label(interface))]);
    }
}

/// RAII guard that increments `metrics`' in-flight gauge for `interface` on
/// construction and decrements it on drop, so the decrement still runs if
/// the wrapped future panics mid-flight (e.g. a handler panic unwinding
/// through `next.run(req).await`) and not just on the ordinary return path.
struct InFlightGuard<'a> {
    metrics: &'a HttpMetrics,
    interface: Interface,
}

impl<'a> InFlightGuard<'a> {
    fn new(metrics: &'a HttpMetrics, interface: Interface) -> Self {
        metrics.inc_in_flight(interface);
        Self { metrics, interface }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.metrics.dec_in_flight(self.interface);
    }
}

/// Records one request into `metrics`: increments the in-flight gauge for
/// the request's `Interface` on entry, decrements on exit (via
/// [`InFlightGuard`], so this happens even if the handler panics), and on
/// completion records the request/status counter and latency histogram
/// keyed by `(method, route)`.
///
/// `route` is the Axum `MatchedPath` template (e.g. `/v3/users/{user_id}`),
/// falling back to the literal string `"unmatched"` when no route matched
/// (404s / probed paths) — this keeps the label's cardinality bounded
/// against arbitrary attacker-supplied paths (ADR 0031). `method` is bounded
/// the same way by [`method_label`] inside `HttpMetrics::record_request`,
/// falling back to `"other"` for any non-standard method — this middleware
/// runs *before* axum's routing produces 404/405, so an unauthenticated
/// client can otherwise mint unbounded label cardinality via arbitrary
/// RFC-token HTTP methods.
///
/// Reads (never writes) the `Interface` extension already stamped by
/// connection-level code (see
/// `docs/superpowers/specs/2026-07-31-http-status-metrics-design.md` for
/// why this must not insert its own `Interface` layer: that extension also
/// gates the admin-SVID auth short-circuit in `crates/core/src/api/auth.rs`).
pub async fn record_http_metrics(
    Extension(metrics): Extension<Arc<HttpMetrics>>,
    matched_path: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let interface = req
        .extensions()
        .get::<Interface>()
        .copied()
        .unwrap_or(Interface::Public);
    let route = matched_path
        .as_ref()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let guard = InFlightGuard::new(&metrics, interface);
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed();
    drop(guard);

    metrics.record_request(&method, &route, response.status().as_u16(), elapsed);

    response
}

#[cfg(test)]
mod tests {
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    fn fixture() -> (MetricsPipeline, Arc<HttpMetrics>) {
        let pipeline = MetricsPipeline::new();
        let metrics = Arc::new(HttpMetrics::new(&pipeline.meter()));
        (pipeline, metrics)
    }

    #[test]
    fn record_request_increments_matching_counter_only() {
        let (pipeline, m) = fixture();
        m.record_request(
            &Method::GET,
            "/v3/users/{user_id}",
            200,
            Duration::from_millis(5),
        );
        m.record_request(
            &Method::GET,
            "/v3/users/{user_id}",
            404,
            Duration::from_millis(1),
        );

        let text = pipeline.render();
        assert!(text.contains("keystone_http_requests_total{method=\"GET\",route=\"/v3/users/{user_id}\",status=\"200\"} 1\n"));
        assert!(text.contains("keystone_http_requests_total{method=\"GET\",route=\"/v3/users/{user_id}\",status=\"404\"} 1\n"));
    }

    #[test]
    fn record_request_feeds_duration_histogram_for_route() {
        let (pipeline, m) = fixture();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(15));

        let text = pipeline.render();
        assert!(text.contains(
            "keystone_http_request_duration_seconds_count{method=\"GET\",route=\"/v3/users\"} 2\n"
        ));
    }

    #[test]
    fn in_flight_gauge_increments_and_decrements() {
        let (pipeline, m) = fixture();
        m.inc_in_flight(Interface::Public);
        m.inc_in_flight(Interface::Public);
        m.dec_in_flight(Interface::Public);

        assert!(
            pipeline
                .render()
                .contains("keystone_http_requests_in_flight{interface=\"public\"} 1\n")
        );
    }

    #[test]
    fn in_flight_series_start_at_zero_for_every_interface() {
        let (pipeline, _m) = fixture();
        let text = pipeline.render();
        for interface in ["public", "internal", "admin", "metrics"] {
            assert!(
                text.contains(&format!(
                    "keystone_http_requests_in_flight{{interface=\"{interface}\"}} 0\n"
                )),
                "{text}"
            );
        }
    }

    /// Pins the rendered exposition text against `tests/golden/http.prom`
    /// (ADR 0040).
    #[test]
    fn golden_exposition() {
        let (pipeline, m) = fixture();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(40));
        m.record_request(
            &Method::POST,
            "/v3/auth/tokens",
            401,
            Duration::from_millis(300),
        );
        m.record_request(
            &Method::from_bytes(b"BREW").unwrap(),
            "/v3/probe",
            500,
            Duration::from_secs(6),
        );
        m.inc_in_flight(Interface::Public);
        m.inc_in_flight(Interface::Public);
        m.inc_in_flight(Interface::Admin);
        openstack_keystone_telemetry::assert_golden!("http", pipeline.render());
    }

    #[test]
    fn has_help_and_type_for_all_three_metrics() {
        let (pipeline, m) = fixture();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));
        m.inc_in_flight(Interface::Public);

        let text = pipeline.render();
        assert!(text.contains("# TYPE keystone_http_requests_total counter"));
        assert!(text.contains("# TYPE keystone_http_request_duration_seconds histogram"));
        assert!(text.contains("# TYPE keystone_http_requests_in_flight gauge"));
        assert!(text.contains(
            "keystone_http_requests_total{method=\"GET\",route=\"/v3/users\",status=\"200\"} 1"
        ));
        assert!(text.contains("keystone_http_requests_in_flight{interface=\"public\"} 1"));
    }

    #[test]
    fn histogram_has_le_buckets_and_inf() {
        let (pipeline, m) = fixture();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));

        let text = pipeline.render();
        assert!(text.contains(
            "keystone_http_request_duration_seconds_bucket{method=\"GET\",route=\"/v3/users\",le=\"+Inf\"} 1"
        ));
        assert!(text.contains(
            "keystone_http_request_duration_seconds_sum{method=\"GET\",route=\"/v3/users\"}"
        ));
        assert!(text.contains(
            "keystone_http_request_duration_seconds_count{method=\"GET\",route=\"/v3/users\"} 1"
        ));
    }

    #[tokio::test]
    async fn middleware_records_matched_path_as_route() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        let (pipeline, metrics) = fixture();
        let app: Router = Router::new()
            .route("/v3/widgets/{id}", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v3/widgets/abc-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let text = pipeline.render();
        assert!(
            text.contains("keystone_http_requests_total{method=\"GET\",route=\"/v3/widgets/{id}\",status=\"200\"} 1\n"),
            "must record the template, not the raw path with the id: {text}"
        );
        assert!(!text.contains("abc-123"));
    }

    #[test]
    fn in_flight_guard_decrements_on_panic_unwind() {
        // `record_http_metrics` can't be driven through `oneshot` here: a
        // panicking handler poisons/aborts the underlying hyper service in
        // this axum/tower version rather than handing `oneshot` a clean
        // `Err`, so a panic-catching wrapper around the full middleware
        // stack isn't a reliable way to observe the fix. Instead, exercise
        // `InFlightGuard` directly: construct it (which increments the
        // gauge), then panic while it's still alive and confirm — from
        // outside the `catch_unwind` — that the gauge was still
        // decremented, proving `Drop::drop` ran during unwind and not just
        // on the ordinary return path.
        let (pipeline, metrics) = fixture();
        let public = "keystone_http_requests_in_flight{interface=\"public\"} ";

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = InFlightGuard::new(&metrics, Interface::Public);
            assert!(
                pipeline.render().contains(&format!("{public}1\n")),
                "constructing the guard must increment the gauge"
            );
            panic!("simulated handler panic while request is in flight");
        }));

        assert!(result.is_err(), "the inner closure must have panicked");
        assert!(
            pipeline.render().contains(&format!("{public}0\n")),
            "guard's Drop impl must decrement the gauge even when unwinding"
        );
    }

    #[tokio::test]
    async fn middleware_labels_unmatched_requests() {
        use axum::Router;
        use axum::body::Body;
        use tower::ServiceExt;

        let (pipeline, metrics) = fixture();
        let app: Router = Router::new()
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics));

        let _ = app
            .oneshot(
                Request::builder()
                    .uri("/does/not/exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let text = pipeline.render();
        assert!(text.contains("route=\"unmatched\""));
        assert!(!text.contains("/does/not/exist"));
    }

    #[test]
    fn method_label_passes_through_standard_methods() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::HEAD), "HEAD");
        assert_eq!(method_label(&Method::POST), "POST");
        assert_eq!(method_label(&Method::PUT), "PUT");
        assert_eq!(method_label(&Method::PATCH), "PATCH");
        assert_eq!(method_label(&Method::DELETE), "DELETE");
        assert_eq!(method_label(&Method::OPTIONS), "OPTIONS");
        assert_eq!(method_label(&Method::TRACE), "TRACE");
        assert_eq!(method_label(&Method::CONNECT), "CONNECT");
    }

    #[test]
    fn method_label_bounds_arbitrary_methods_to_other() {
        let arbitrary = Method::from_bytes(b"WHATEVER").unwrap();
        assert_eq!(method_label(&arbitrary), "other");
    }

    #[test]
    fn record_request_collapses_arbitrary_methods_into_a_single_other_series() {
        let (pipeline, m) = fixture();
        for name in [&b"FOO"[..], b"BAR", b"BAZ"] {
            m.record_request(
                &Method::from_bytes(name).unwrap(),
                "/v3/probe",
                200,
                Duration::from_millis(1),
            );
        }

        let text = pipeline.render();
        assert!(
            text.contains("keystone_http_requests_total{method=\"other\",route=\"/v3/probe\",status=\"200\"} 3\n"),
            "arbitrary attacker-supplied methods must not each mint their own series: {text}"
        );
        assert!(!text.contains("FOO"));
    }

    #[tokio::test]
    async fn middleware_bounds_arbitrary_method_label_to_other() {
        use axum::Router;
        use axum::body::Body;
        use tower::ServiceExt;

        let (pipeline, metrics) = fixture();
        let app: Router = Router::new()
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics));

        let _ = app
            .oneshot(
                Request::builder()
                    .method(Method::from_bytes(b"WEIRDMETHOD").unwrap())
                    .uri("/does/not/exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let text = pipeline.render();
        assert!(text.contains("method=\"other\""));
        assert!(!text.contains("WEIRDMETHOD"));
    }
}
