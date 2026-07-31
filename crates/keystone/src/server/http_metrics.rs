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
//! # HTTP request metrics (ADR 0031)
//!
//! Hand-rolled Prometheus text exposition for the HTTP request trio
//! (`keystone_http_requests_total`, `keystone_http_request_duration_seconds`,
//! `keystone_http_requests_in_flight`), consistent with the project's
//! decision not to depend on the `prometheus`/`metrics` crates (see
//! `crates/audit/src/metrics.rs` and
//! `doc/src/adr/0031-prometheus-metrics.md`).

use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;

use axum::extract::{Extension, MatchedPath, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;
use openstack_keystone_config::Interface;

/// Bucket upper bounds in seconds, tuned for Keystone's fast auth/token
/// paths (tighter low end than Prometheus client-library defaults).
const BUCKET_BOUNDS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// `((method, route), (bucket_counts, sum_seconds, count))` yielded by
/// [`HttpMetrics::duration_seconds_iter`].
type DurationSecondsEntry = ((&'static str, String), (Vec<(f64, u64)>, f64, u64));

/// Maps an [`axum::http::Method`] to a bounded label value for the
/// `method` Prometheus label: the 9 standard HTTP methods, or the literal
/// `"other"` for anything else.
///
/// `record_http_metrics` runs *before* axum's routing produces 404/405, so
/// an unauthenticated client can send arbitrary RFC-token HTTP methods
/// (hyper's `Method::Extension` accepts any token) straight into this
/// middleware. Without this bound, each distinct attacker-supplied method
/// string would mint its own permanent entry in `requests_total` /
/// `duration_seconds` and its own Prometheus series — unbounded map growth
/// and unbounded `/metrics` payload size (ADR 0031). Mirrors the `route`
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

/// Number of [`Interface`] variants; used to size the fixed-array in-flight
/// gauge storage in [`HttpMetrics`]. Must be kept in sync with the enum
/// (`interface_index` below matches on all variants exhaustively, so adding
/// a variant without updating this constant fails to compile).
const INTERFACE_COUNT: usize = 4;

/// Maps an [`Interface`] to its fixed-array index for the in-flight gauge.
const fn interface_index(interface: Interface) -> usize {
    match interface {
        Interface::Public => 0,
        Interface::Internal => 1,
        Interface::Admin => 2,
        Interface::Metrics => 3,
    }
}

/// A fixed-bucket histogram, storing per-bucket counts as `AtomicU64` plus
/// a sum (as micros, to keep it integer/atomic) and a total count.
pub struct Histogram {
    bucket_counts: [AtomicU64; BUCKET_BOUNDS.len()],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new() -> Self {
        Self {
            bucket_counts: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, value_seconds: f64) {
        for (bound, counter) in BUCKET_BOUNDS.iter().zip(self.bucket_counts.iter()) {
            if value_seconds <= *bound {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        let micros = (value_seconds * 1_000_000.0).round().max(0.0) as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// `(upper_bound, cumulative_count)` pairs, ascending, plus a final
    /// `(f64::INFINITY, total_count)` entry for the `+Inf` bucket.
    pub fn bucket_counts(&self) -> Vec<(f64, u64)> {
        let mut out: Vec<(f64, u64)> = BUCKET_BOUNDS
            .iter()
            .zip(self.bucket_counts.iter())
            .map(|(bound, counter)| (*bound, counter.load(Ordering::Relaxed)))
            .collect();
        out.push((f64::INFINITY, self.count()));
        out
    }

    pub fn sum(&self) -> f64 {
        self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state backing the ADR 0031 HTTP request metric trio. Lives in
/// `crates/keystone`, not `core` — `core` must stay HTTP-unaware. Reached
/// by the recording middleware and by `metrics_handler` via
/// `axum::Extension<Arc<HttpMetrics>>`, never through `ServiceState`.
pub struct HttpMetrics {
    requests_total: DashMap<(&'static str, String, u16), AtomicU64>,
    duration_seconds: DashMap<(&'static str, String), Histogram>,
    /// In-flight gauge, one slot per [`Interface`] variant (indexed via
    /// [`interface_index`]). `Interface` is a closed 4-variant enum and any
    /// single listener only ever touches one slot, so a fixed array of
    /// atomics avoids taking a `DashMap` write-lock (via
    /// `entry(..).or_insert_with(..)`, which write-locks the shard even
    /// when the key already exists — it always does here) on every single
    /// request.
    in_flight: [AtomicI64; INTERFACE_COUNT],
}

impl HttpMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: DashMap::new(),
            duration_seconds: DashMap::new(),
            in_flight: std::array::from_fn(|_| AtomicI64::new(0)),
        }
    }

    pub fn record_request(&self, method: &Method, route: &str, status: u16, elapsed: Duration) {
        let method = method_label(method);

        self.requests_total
            .entry((method, route.to_owned(), status))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.duration_seconds
            .entry((method, route.to_owned()))
            .or_default()
            .record(elapsed.as_secs_f64());
    }

    pub fn inc_in_flight(&self, interface: Interface) {
        self.in_flight[interface_index(interface)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_in_flight(&self, interface: Interface) {
        self.in_flight[interface_index(interface)].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn requests_total_iter(
        &self,
    ) -> impl Iterator<Item = ((&'static str, String, u16), u64)> + '_ {
        self.requests_total
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
    }

    pub fn duration_seconds_iter(&self) -> impl Iterator<Item = DurationSecondsEntry> + '_ {
        self.duration_seconds.iter().map(|entry| {
            let histogram = entry.value();
            (
                entry.key().clone(),
                (
                    histogram.bucket_counts(),
                    histogram.sum(),
                    histogram.count(),
                ),
            )
        })
    }

    pub fn in_flight_iter(&self) -> impl Iterator<Item = (Interface, i64)> + '_ {
        [
            Interface::Public,
            Interface::Internal,
            Interface::Admin,
            Interface::Metrics,
        ]
        .into_iter()
        .map(|interface| {
            (
                interface,
                self.in_flight[interface_index(interface)].load(Ordering::Relaxed),
            )
        })
    }
}

impl Default for HttpMetrics {
    fn default() -> Self {
        Self::new()
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

fn interface_label(interface: Interface) -> &'static str {
    match interface {
        Interface::Public => "public",
        Interface::Internal => "internal",
        Interface::Admin => "admin",
        Interface::Metrics => "metrics",
    }
}

/// Serialise the HTTP request metric trio as Prometheus text exposition
/// format (version 0.0.4).
pub fn format_prometheus_text(metrics: &HttpMetrics) -> String {
    let mut out = String::new();

    out.push_str(
        "# HELP keystone_http_requests_total Total HTTP requests by method, route, and status.\n",
    );
    out.push_str("# TYPE keystone_http_requests_total counter\n");
    for ((method, route, status), count) in metrics.requests_total_iter() {
        out.push_str(&format!(
            "keystone_http_requests_total{{method=\"{method}\",route=\"{route}\",status=\"{status}\"}} {count}\n"
        ));
    }

    out.push_str(
        "# HELP keystone_http_request_duration_seconds HTTP request latency by method and route.\n",
    );
    out.push_str("# TYPE keystone_http_request_duration_seconds histogram\n");
    for ((method, route), (buckets, sum, count)) in metrics.duration_seconds_iter() {
        for (bound, cumulative) in buckets {
            let le = if bound.is_infinite() {
                "+Inf".to_owned()
            } else {
                bound.to_string()
            };
            out.push_str(&format!(
                "keystone_http_request_duration_seconds_bucket{{method=\"{method}\",route=\"{route}\",le=\"{le}\"}} {cumulative}\n"
            ));
        }
        out.push_str(&format!(
            "keystone_http_request_duration_seconds_sum{{method=\"{method}\",route=\"{route}\"}} {sum}\n"
        ));
        out.push_str(&format!(
            "keystone_http_request_duration_seconds_count{{method=\"{method}\",route=\"{route}\"}} {count}\n"
        ));
    }

    out.push_str(
        "# HELP keystone_http_requests_in_flight In-flight HTTP requests by listener interface.\n",
    );
    out.push_str("# TYPE keystone_http_requests_in_flight gauge\n");
    for (interface, value) in metrics.in_flight_iter() {
        out.push_str(&format!(
            "keystone_http_requests_in_flight{{interface=\"{}\"}} {value}\n",
            interface_label(interface)
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_places_value_in_correct_and_higher_buckets() {
        let h = Histogram::new();
        h.record(0.02); // falls in 0.025 bucket and every bucket above it

        let counts = h.bucket_counts();
        let (bound_0_01, count_0_01) = counts[2];
        assert_eq!(bound_0_01, 0.01);
        assert_eq!(count_0_01, 0, "0.02 must not count in the 0.01 bucket");

        let (bound_0_025, count_0_025) = counts[3];
        assert_eq!(bound_0_025, 0.025);
        assert_eq!(count_0_025, 1, "0.02 must count in the 0.025 bucket");

        let (bound_5, count_5) = counts[10];
        assert_eq!(bound_5, 5.0);
        assert_eq!(count_5, 1, "0.02 must count in every bucket above it");

        let (inf_bound, inf_count) = *counts.last().unwrap();
        assert!(inf_bound.is_infinite());
        assert_eq!(inf_count, 1);
    }

    #[test]
    fn sum_and_count_accumulate() {
        let h = Histogram::new();
        h.record(0.1);
        h.record(0.2);
        assert_eq!(h.count(), 2);
        assert!((h.sum() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn record_request_increments_matching_counter_only() {
        let m = HttpMetrics::new();
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

        let counts: Vec<_> = m.requests_total_iter().collect();
        assert_eq!(
            counts.len(),
            2,
            "status 200 and 404 must be separate series"
        );
        let ok_count = counts
            .iter()
            .find(|((method, route, status), _)| {
                method == &Method::GET && route == "/v3/users/{user_id}" && *status == 200
            })
            .map(|(_, c)| *c);
        assert_eq!(ok_count, Some(1));
    }

    #[test]
    fn record_request_feeds_duration_histogram_for_route() {
        let m = HttpMetrics::new();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(15));

        let durations: Vec<_> = m.duration_seconds_iter().collect();
        assert_eq!(
            durations.len(),
            1,
            "same (method, route) shares one histogram"
        );
        let (_, (_, _sum, count)) = &durations[0];
        assert_eq!(*count, 2);
    }

    #[test]
    fn in_flight_gauge_increments_and_decrements() {
        let m = HttpMetrics::new();
        m.inc_in_flight(Interface::Public);
        m.inc_in_flight(Interface::Public);
        m.dec_in_flight(Interface::Public);

        let value = m
            .in_flight_iter()
            .find(|(iface, _)| *iface == Interface::Public)
            .map(|(_, v)| v);
        assert_eq!(value, Some(1));
    }

    #[test]
    fn format_prometheus_text_contains_help_and_type_for_all_three_metrics() {
        let m = HttpMetrics::new();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));
        m.inc_in_flight(Interface::Public);

        let text = format_prometheus_text(&m);
        assert!(text.contains("# TYPE keystone_http_requests_total counter"));
        assert!(text.contains("# TYPE keystone_http_request_duration_seconds histogram"));
        assert!(text.contains("# TYPE keystone_http_requests_in_flight gauge"));
        assert!(text.contains(
            "keystone_http_requests_total{method=\"GET\",route=\"/v3/users\",status=\"200\"} 1"
        ));
        assert!(text.contains("keystone_http_requests_in_flight{interface=\"public\"} 1"));
    }

    #[test]
    fn format_prometheus_text_histogram_has_le_buckets_and_inf() {
        let m = HttpMetrics::new();
        m.record_request(&Method::GET, "/v3/users", 200, Duration::from_millis(5));

        let text = format_prometheus_text(&m);
        assert!(text.contains(
            "keystone_http_request_duration_seconds_bucket{method=\"GET\",route=\"/v3/users\",le=\"+Inf\"}"
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

        let metrics = Arc::new(HttpMetrics::new());
        let app: Router = Router::new()
            .route("/v3/widgets/{id}", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics.clone()));

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

        let counts: Vec<_> = metrics.requests_total_iter().collect();
        assert_eq!(counts.len(), 1);
        let ((_, route, status), count) = &counts[0];
        assert_eq!(
            route, "/v3/widgets/{id}",
            "must record the template, not the raw path with the id"
        );
        assert_eq!(*status, 200);
        assert_eq!(*count, 1);
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
        let metrics = HttpMetrics::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = InFlightGuard::new(&metrics, Interface::Public);
            assert_eq!(
                metrics
                    .in_flight_iter()
                    .find(|(iface, _)| *iface == Interface::Public)
                    .map(|(_, v)| v),
                Some(1),
                "constructing the guard must increment the gauge"
            );
            panic!("simulated handler panic while request is in flight");
        }));

        assert!(result.is_err(), "the inner closure must have panicked");
        let value = metrics
            .in_flight_iter()
            .find(|(iface, _)| *iface == Interface::Public)
            .map(|(_, v)| v);
        assert_eq!(
            value,
            Some(0),
            "guard's Drop impl must decrement the gauge even when unwinding"
        );
    }

    #[tokio::test]
    async fn middleware_labels_unmatched_requests() {
        use axum::Router;
        use axum::body::Body;
        use tower::ServiceExt;

        let metrics = Arc::new(HttpMetrics::new());
        let app: Router = Router::new()
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics.clone()));

        let _ = app
            .oneshot(
                Request::builder()
                    .uri("/does/not/exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let counts: Vec<_> = metrics.requests_total_iter().collect();
        assert_eq!(counts.len(), 1);
        let ((_, route, _), _) = &counts[0];
        assert_eq!(route, "unmatched");
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
        let m = HttpMetrics::new();
        let m1 = Method::from_bytes(b"FOO").unwrap();
        let m2 = Method::from_bytes(b"BAR").unwrap();
        let m3 = Method::from_bytes(b"BAZ").unwrap();

        m.record_request(&m1, "/v3/probe", 200, Duration::from_millis(1));
        m.record_request(&m2, "/v3/probe", 200, Duration::from_millis(1));
        m.record_request(&m3, "/v3/probe", 200, Duration::from_millis(1));

        let counts: Vec<_> = m.requests_total_iter().collect();
        assert_eq!(
            counts.len(),
            1,
            "arbitrary attacker-supplied methods must not each mint their own series"
        );
        let ((method, _, _), count) = &counts[0];
        assert_eq!(*method, "other");
        assert_eq!(*count, 3);
    }

    #[tokio::test]
    async fn middleware_bounds_arbitrary_method_label_to_other() {
        use axum::Router;
        use axum::body::Body;
        use tower::ServiceExt;

        let metrics = Arc::new(HttpMetrics::new());
        let app: Router = Router::new()
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(metrics.clone()));

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

        let counts: Vec<_> = metrics.requests_total_iter().collect();
        assert_eq!(counts.len(), 1);
        let ((method, _, _), _) = &counts[0];
        assert_eq!(*method, "other");
    }
}
