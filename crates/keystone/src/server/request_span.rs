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

//! # OpenTelemetry server span (ADR 0040)
//!
//! One `http.server` span per request, parent of every span the handlers
//! create, carrying the request's HTTP attributes. It is separate from the
//! `request` span that `TraceLayer` makes for the local logs: that one has
//! `client.addr` and the raw `uri` as fields, and the OpenTelemetry layer
//! exports every field of a span it sees. The tracing setup therefore
//! excludes `request` from export and `http.server` from the log sinks
//! ([`SERVER_SPAN_TARGET`]).
//!
//! Only the route template (`http.route`, the Axum `MatchedPath`) identifies
//! the endpoint by default. The raw path embeds resource ids and the
//! authenticated user, project and domain are ids too, so those are added only
//! with `[otel] include_user_ids`; the caller's IP only with
//! `[otel] include_client_address`. Operators who export them can strip what
//! they do not want in the collector.
//!
//! The middleware is installed only when traces are being exported; without
//! it the request path is untouched.

use std::sync::Arc;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::Response;
use openstack_keystone_telemetry::TelemetrySettings;
use tracing::field::Empty;
use tracing::{Instrument, info_span};

/// `tracing` target of the span. The log sinks switch it off and the
/// OpenTelemetry layer is the only consumer.
pub const SERVER_SPAN_TARGET: &str = "openstack_keystone::otel";

/// Longest `User-Agent` copied into a span; the header is client controlled.
const MAX_USER_AGENT_CHARS: usize = 256;

/// What the server span carries beyond the always-on attributes.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestSpanOptions {
    /// Add the raw path and the authenticated user, project and domain ids.
    pub include_user_ids: bool,
    /// Add the caller's IP address as `client.address`.
    pub include_client_address: bool,
    /// Also emit the pre-stable `http.method`, `http.user_agent`,
    /// `http.status_code` and `http.url` names `oslo.middleware` uses.
    pub legacy_http_attributes: bool,
    /// Echo `traceparent` in the response.
    pub response_traceparent: bool,
}

impl From<&TelemetrySettings> for RequestSpanOptions {
    fn from(settings: &TelemetrySettings) -> Self {
        Self {
            include_user_ids: settings.include_user_ids,
            include_client_address: settings.include_client_address,
            legacy_http_attributes: settings.legacy_http_attributes,
            response_traceparent: settings.response_traceparent,
        }
    }
}

/// The options for the configured telemetry, or `None` when this build or
/// configuration does not export traces (no span, no overhead).
pub fn options_from_config(cfg: &crate::config::LoadedConfig) -> Option<Arc<RequestSpanOptions>> {
    use openstack_keystone_telemetry::{OTLP_COMPILED, OsloMiddlewareTracingConfig, OtelConfig};

    if !OTLP_COMPILED {
        return None;
    }
    let view = cfg.view();
    let resolved = openstack_keystone_telemetry::resolve(
        view.section::<OtelConfig>()?,
        view.section::<OsloMiddlewareTracingConfig>()?,
    )
    .ok()?;
    let settings = resolved.settings?;
    settings
        .traces_enabled
        .then(|| Arc::new(RequestSpanOptions::from(&settings)))
}

/// `http.request.method` value: the method when it is a standard one,
/// otherwise `_OTHER`, so a client cannot mint arbitrary attribute values.
fn method_attribute(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => "_OTHER",
    }
}

/// The `http.server` span; `$extra` adds fields on top of the common set.
macro_rules! server_span {
    ($name:expr, $method:expr $(, $($extra:tt)*)?) => {
        info_span!(
            target: SERVER_SPAN_TARGET,
            "http.server",
            otel.name = %$name,
            otel.kind = "server",
            otel.status_code = Empty,
            otel.status_description = Empty,
            http.request.method = $method,
            http.route = Empty,
            client.address = Empty,
            http.response.status_code = Empty,
            user_agent.original = Empty,
            openstack.request_id = Empty,
            url.path = Empty,
            http.method = Empty,
            http.user_agent = Empty,
            http.status_code = Empty,
            http.url = Empty,
            $($($extra)*)?
        )
    };
}

/// Create the `http.server` span for `req` and run the rest of the stack
/// inside it. Must sit inside the router layer (so `MatchedPath` is set) and
/// after `SetRequestIdLayer`.
pub async fn server_span(
    State(options): State<Arc<RequestSpanOptions>>,
    matched_path: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let method = method_attribute(req.method());
    let route = matched_path.as_ref().map(MatchedPath::as_str);
    // Low-cardinality by construction: the method is one of nine plus
    // `_OTHER`, the route is a template.
    let name = match route {
        Some(route) => format!("{method} {route}"),
        None => method.to_string(),
    };

    // The id fields exist only when opted in: a field that is not declared
    // cannot be recorded into later (see `record_initiator` in core), so
    // without `include_user_ids` the ids never reach the exporter.
    let span = if options.include_user_ids {
        server_span!(
            name,
            method,
            openstack.user_id = Empty,
            openstack.project_id = Empty,
            openstack.domain_id = Empty,
        )
    } else {
        server_span!(name, method)
    };

    if let Some(route) = route {
        span.record("http.route", route);
    }
    if let Some(user_agent) = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
    {
        let user_agent: String = user_agent.chars().take(MAX_USER_AGENT_CHARS).collect();
        span.record("user_agent.original", user_agent.as_str());
        if options.legacy_http_attributes {
            span.record("http.user_agent", user_agent.as_str());
        }
    }
    if let Some(request_id) = req
        .headers()
        .get("x-openstack-request-id")
        .and_then(|v| v.to_str().ok())
    {
        span.record("openstack.request_id", request_id);
    }
    if options.include_client_address
        // The peer address, or the proxy-resolved client address when
        // `enable_proxy_headers_parsing` rewrote it; absent on the admin UDS.
        && let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>()
    {
        span.record("client.address", addr.ip().to_string().as_str());
    }
    if options.legacy_http_attributes {
        span.record("http.method", method);
    }
    if options.include_user_ids {
        span.record("url.path", req.uri().path());
        if options.legacy_http_attributes {
            span.record("http.url", req.uri().path());
        }
    }
    #[cfg(feature = "otel")]
    openstack_keystone_telemetry::set_remote_parent(&span, req.headers());

    #[cfg_attr(not(feature = "otel"), allow(unused_mut))]
    let mut response = next.run(req).instrument(span.clone()).await;

    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if options.legacy_http_attributes {
        span.record("http.status_code", status.as_u16());
    }
    // Server errors only: a 4xx is the client's mistake, not the span's error.
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
        span.record(
            "otel.status_description",
            status.canonical_reason().unwrap_or("server error"),
        );
    }
    #[cfg(feature = "otel")]
    if options.response_traceparent {
        openstack_keystone_telemetry::inject_traceparent(&span, response.headers_mut());
    }
    response
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware::from_fn_with_state;
    use axum::routing::{any, get};
    use cadf::Initiator;
    use tower::ServiceExt as _;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Dispatch, Subscriber};
    use tracing_subscriber::layer::{Context, SubscriberExt as _};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::{Layer, Registry};

    use super::*;

    type Fields = HashMap<String, String>;

    /// Remembers the fields of every `http.server` span, including the ones
    /// recorded after creation.
    #[derive(Clone, Default)]
    struct Recorder {
        spans: Arc<Mutex<HashMap<u64, Fields>>>,
    }

    struct FieldVisitor<'a>(&'a mut Fields);

    impl Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Recorder {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _: Context<'_, S>) {
            if attrs.metadata().name() != "http.server" {
                return;
            }
            assert_eq!(attrs.metadata().target(), SERVER_SPAN_TARGET);
            let mut fields = Fields::new();
            attrs.record(&mut FieldVisitor(&mut fields));
            self.spans.lock().unwrap().insert(id.into_u64(), fields);
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
            if let Some(fields) = self.spans.lock().unwrap().get_mut(&id.into_u64()) {
                values.record(&mut FieldVisitor(fields));
            }
        }
    }

    fn router(options: RequestSpanOptions) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }
        async fn boom() -> (axum::http::StatusCode, &'static str) {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
        }
        async fn who() -> &'static str {
            cadf_record_initiator();
            "ok"
        }
        fn cadf_record_initiator() {
            openstack_keystone_core::audit_context::record_initiator(Initiator::new(
                "user-1".to_string(),
                Some("project-1".to_string()),
                Some("domain-1".to_string()),
                None,
            ));
        }
        Router::new()
            .route("/v3/users/{user_id}", get(ok))
            .route("/v3/boom", get(boom))
            .route("/v3/who", get(who))
            .route("/v3/any", any(ok))
            .layer(from_fn_with_state(Arc::new(options), server_span))
    }

    /// Send one request through `router(options)` and return the fields of
    /// the single `http.server` span it produced.
    async fn run_with(
        options: RequestSpanOptions,
        request: Request<Body>,
    ) -> (axum::http::Response<Body>, Fields) {
        let recorder = Recorder::default();
        let dispatch = Dispatch::new(Registry::default().with(recorder.clone()));
        let guard = tracing::dispatcher::set_default(&dispatch);
        let response = router(options).oneshot(request).await.unwrap();
        drop(guard);
        let spans = recorder.spans.lock().unwrap();
        assert_eq!(spans.len(), 1, "exactly one http.server span: {spans:?}");
        let fields = spans.values().next().cloned().unwrap();
        (response, fields)
    }

    async fn run(request: Request<Body>) -> Fields {
        run_with(RequestSpanOptions::default(), request).await.1
    }

    fn get_req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn named_after_the_route_template_not_the_path() {
        let fields = run(get_req("/v3/users/6fa1d8c0")).await;
        assert_eq!(fields["otel.name"], "GET /v3/users/{user_id}");
        assert_eq!(fields["http.route"], "/v3/users/{user_id}");
        assert_eq!(fields["http.request.method"], "GET");
        assert_eq!(fields["otel.kind"], "server");
        assert_eq!(fields["http.response.status_code"], "200");
        // Nothing carries the id the caller put in the path.
        assert!(
            fields.values().all(|v| !v.contains("6fa1d8c0")),
            "{fields:?}"
        );
        assert!(!fields.contains_key("url.path"));
        assert!(!fields.contains_key("otel.status_code"));
    }

    #[tokio::test]
    async fn unmatched_requests_are_named_by_method_only() {
        let (response, fields) = run_with(
            RequestSpanOptions::default(),
            get_req("/definitely/not/a/route/6fa1d8c0"),
        )
        .await;
        assert_eq!(response.status(), 404);
        assert_eq!(fields["otel.name"], "GET");
        assert!(!fields.contains_key("http.route"));
        assert_eq!(fields["http.response.status_code"], "404");
        // A client error is not a span error.
        assert!(!fields.contains_key("otel.status_code"));
        assert!(fields.values().all(|v| !v.contains("6fa1d8c0")));
    }

    #[tokio::test]
    async fn server_errors_mark_the_span_as_failed() {
        let fields = run(get_req("/v3/boom")).await;
        assert_eq!(fields["http.response.status_code"], "500");
        assert_eq!(fields["otel.status_code"], "ERROR");
        assert_eq!(fields["otel.status_description"], "Internal Server Error");
    }

    #[tokio::test]
    async fn non_standard_methods_cannot_mint_attribute_values() {
        let req = Request::builder()
            .method("BREW-6fa1d8c0")
            .uri("/v3/any")
            .body(Body::empty())
            .unwrap();
        let fields = run(req).await;
        assert_eq!(fields["http.request.method"], "_OTHER");
        assert_eq!(fields["otel.name"], "_OTHER /v3/any");
    }

    #[tokio::test]
    async fn request_id_and_a_bounded_user_agent_are_recorded() {
        let req = Request::builder()
            .uri("/v3/any")
            .header("x-openstack-request-id", "req-abc")
            .header("user-agent", "x".repeat(10_000))
            .body(Body::empty())
            .unwrap();
        let fields = run(req).await;
        assert_eq!(fields["openstack.request_id"], "req-abc");
        assert_eq!(
            fields["user_agent.original"].chars().count(),
            MAX_USER_AGENT_CHARS
        );
    }

    #[tokio::test]
    async fn ids_and_raw_path_are_off_by_default() {
        let fields = run(get_req("/v3/who")).await;
        for name in [
            "openstack.user_id",
            "openstack.project_id",
            "openstack.domain_id",
            "url.path",
        ] {
            assert!(!fields.contains_key(name), "{name} leaked: {fields:?}");
        }
    }

    #[tokio::test]
    async fn ids_and_raw_path_are_recorded_when_opted_in() {
        let (_, fields) = run_with(
            RequestSpanOptions {
                include_user_ids: true,
                ..Default::default()
            },
            get_req("/v3/who"),
        )
        .await;
        assert_eq!(fields["openstack.user_id"], "user-1");
        assert_eq!(fields["openstack.project_id"], "project-1");
        assert_eq!(fields["openstack.domain_id"], "domain-1");
        assert_eq!(fields["url.path"], "/v3/who");
    }

    fn req_from(addr: &str) -> Request<Body> {
        let mut req = get_req("/v3/any");
        req.extensions_mut()
            .insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        req
    }

    #[tokio::test]
    async fn the_client_address_is_off_by_default() {
        let fields = run(req_from("203.0.113.9:51234")).await;
        assert!(!fields.contains_key("client.address"), "{fields:?}");
        assert!(fields.values().all(|v| !v.contains("203.0.113.9")));
    }

    #[tokio::test]
    async fn the_client_address_is_recorded_when_opted_in_and_has_no_port() {
        let (_, fields) = run_with(
            RequestSpanOptions {
                include_client_address: true,
                ..Default::default()
            },
            req_from("203.0.113.9:51234"),
        )
        .await;
        assert_eq!(fields["client.address"], "203.0.113.9");
        // Independent of the id switch.
        assert!(!fields.contains_key("url.path"));
        assert!(!fields.contains_key("openstack.user_id"));
    }

    #[tokio::test]
    async fn no_peer_address_means_no_attribute() {
        // The admin Unix socket has no `ConnectInfo<SocketAddr>`.
        let (_, fields) = run_with(
            RequestSpanOptions {
                include_client_address: true,
                ..Default::default()
            },
            get_req("/v3/any"),
        )
        .await;
        assert!(!fields.contains_key("client.address"));
    }

    #[tokio::test]
    async fn legacy_attribute_names_are_opt_in() {
        let req = Request::builder()
            .uri("/v3/any")
            .header("user-agent", "curl/8")
            .body(Body::empty())
            .unwrap();
        let plain = run(req).await;
        for name in [
            "http.method",
            "http.status_code",
            "http.user_agent",
            "http.url",
        ] {
            assert!(!plain.contains_key(name), "{name}: {plain:?}");
        }

        let req = Request::builder()
            .uri("/v3/any")
            .header("user-agent", "curl/8")
            .body(Body::empty())
            .unwrap();
        let (_, legacy) = run_with(
            RequestSpanOptions {
                legacy_http_attributes: true,
                ..Default::default()
            },
            req,
        )
        .await;
        assert_eq!(legacy["http.method"], "GET");
        assert_eq!(legacy["http.status_code"], "200");
        assert_eq!(legacy["http.user_agent"], "curl/8");
        // The raw URL is still gated on `include_user_ids`.
        assert!(!legacy.contains_key("http.url"));
    }

    #[tokio::test]
    async fn the_principal_is_not_recorded_without_the_span_fields() {
        // `record_initiator` outside any span (or into one without the
        // fields) is a harmless no-op.
        openstack_keystone_core::audit_context::record_initiator(Initiator::new(
            "user-1".to_string(),
            None,
            None,
            None,
        ));
    }

    #[test]
    fn options_follow_the_telemetry_settings() {
        use openstack_keystone_telemetry::{OsloMiddlewareTracingConfig, OtelConfig, resolve};
        let otel: OtelConfig = serde_json::from_value(serde_json::json!({
            "enabled": true, "include_user_ids": true, "response_traceparent": true,
            "include_client_address": true
        }))
        .unwrap();
        let settings = resolve(&otel, &OsloMiddlewareTracingConfig::default())
            .unwrap()
            .settings
            .unwrap();
        let options = RequestSpanOptions::from(&settings);
        assert!(options.include_user_ids && options.response_traceparent);
        assert!(options.include_client_address);
        assert!(!options.legacy_http_attributes);
    }

    /// Trace context handling needs the real OpenTelemetry pipeline.
    #[cfg(feature = "otel")]
    mod trace_context {
        use openstack_keystone_telemetry::{
            OsloMiddlewareTracingConfig, OtelConfig, TelemetryGuard, init, resolve,
        };

        use super::*;

        const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

        /// A pipeline exporting to a closed port: spans are built and
        /// sampled, the batch export just fails in the background.
        fn pipeline() -> TelemetryGuard {
            let otel: OtelConfig = serde_json::from_value(serde_json::json!({
                "enabled": true,
                "traces_enabled": true,
                "metrics_enabled": false,
                "endpoint": "http://127.0.0.1:1",
                "sampler": "always_on",
                "timeout": 1,
            }))
            .unwrap();
            let settings = resolve(&otel, &OsloMiddlewareTracingConfig::default())
                .unwrap()
                .settings
                .unwrap();
            init(&settings, "test").unwrap()
        }

        async fn respond(
            options: RequestSpanOptions,
            traceparent: Option<&str>,
        ) -> axum::http::Response<Body> {
            let mut guard = pipeline();
            let dispatch =
                Dispatch::new(Registry::default().with(guard.tracing_layer::<Registry>().unwrap()));
            let default = tracing::dispatcher::set_default(&dispatch);
            let mut req = Request::builder().uri("/v3/any");
            if let Some(traceparent) = traceparent {
                req = req.header("traceparent", traceparent);
            }
            let response = router(options)
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            drop(default);
            tokio::task::spawn_blocking(move || guard.shutdown())
                .await
                .unwrap();
            response
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn the_response_continues_the_callers_trace_when_enabled() {
            let response = respond(
                RequestSpanOptions {
                    response_traceparent: true,
                    ..Default::default()
                },
                Some(&format!("00-{TRACE_ID}-00f067aa0ba902b7-01")),
            )
            .await;
            let value = response.headers()["traceparent"].to_str().unwrap();
            let parts: Vec<&str> = value.split('-').collect();
            assert_eq!(parts[1], TRACE_ID, "{value}");
            assert_ne!(parts[2], "00f067aa0ba902b7", "{value}");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn nothing_is_echoed_unless_enabled() {
            let response = respond(
                RequestSpanOptions::default(),
                Some(&format!("00-{TRACE_ID}-00f067aa0ba902b7-01")),
            )
            .await;
            assert!(!response.headers().contains_key("traceparent"));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_request_without_context_starts_a_new_trace() {
            let response = respond(
                RequestSpanOptions {
                    response_traceparent: true,
                    ..Default::default()
                },
                None,
            )
            .await;
            let value = response.headers()["traceparent"].to_str().unwrap();
            assert_ne!(value.split('-').nth(1).unwrap(), TRACE_ID);
        }
    }
}
