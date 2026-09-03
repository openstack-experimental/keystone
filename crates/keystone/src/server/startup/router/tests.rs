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

use axum::body::Body;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use utoipa::OpenApi;

use super::*;
use crate::api;
use crate::config::Interface;
use crate::server::http_metrics::format_prometheus_text as format_http_metrics_text;
use crate::server::startup::test_support::{test_config, test_startup};

async fn build_test_router(cfg: crate::config::Config) -> (Router, Option<Arc<HttpMetrics>>) {
    let startup = test_startup(cfg).await;
    let (main_router, _main_api) = api::openapi_router().split_for_parts();
    let openapi = api::ApiDoc::openapi();
    build(&startup, main_router, openapi)
        .await
        .expect("router assembly succeeds")
}

// Regression test for https://github.com/juhaku/utoipa/issues/1467:
// wrapping SwaggerUi in `NormalizePathLayer` turns its internal
// "/swagger-ui" -> "/swagger-ui/" redirect into an infinite loop. `build`
// keeps SwaggerUi outside the normalized service, so a direct request to
// "/swagger-ui/" must resolve without another redirect.
#[tokio::test]
async fn build_router_serves_swagger_ui_without_redirect_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _http_metrics) = build_test_router(test_config(tmp.path().to_path_buf())).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/swagger-ui/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "expected swagger-ui to serve directly, not redirect (utoipa#1467 regression)"
    );
}

// Issue #734: a route registered without a trailing slash must still resolve
// when the client requests it with one, since the layer wraps everything
// except SwaggerUi.
#[tokio::test]
async fn build_router_normalizes_trailing_slash_on_api_routes() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _http_metrics) = build_test_router(test_config(tmp.path().to_path_buf())).await;

    let response = app
        .oneshot(Request::builder().uri("/v3/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn build_router_records_http_metrics_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.interface_metrics.http_requests_enabled = true;
    let (app, http_metrics) = build_test_router(cfg).await;
    let http_metrics = http_metrics.expect("HttpMetrics must be Some when enabled");

    let _ = app
        .oneshot(Request::builder().uri("/v3/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let text = format_http_metrics_text(&http_metrics);
    // The matched-path template for this route is "/v3" (no trailing slash)
    // even though the request URI is "/v3/": `NormalizePathLayer` trims the
    // trailing slash before the request reaches the inner router.
    assert!(
        text.contains("keystone_http_requests_total{method=\"GET\",route=\"/v3\""),
        "expected a recorded /v3 request, got:\n{text}"
    );
}

#[tokio::test]
async fn build_router_skips_http_metrics_when_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.interface_metrics.http_requests_enabled = false;
    let (app, http_metrics) = build_test_router(cfg).await;
    assert!(
        http_metrics.is_none(),
        "HttpMetrics must be None when disabled"
    );

    let response = app
        .oneshot(Request::builder().uri("/v3/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "disabling metrics must not break normal routing"
    );
}

/// Reports whether an `Interface` extension is present on the request by the
/// time it reaches this handler. Guards the security-critical invariant that
/// `build`'s main `app` never gains an `Interface` extension:
/// `crates/core/src/api/auth.rs` reads that extension to gate the admin-SVID
/// auth short-circuit, and only connection-level listener code is supposed
/// to stamp it.
async fn interface_probe_handler(req: Request<Body>) -> String {
    match req.extensions().get::<Interface>() {
        Some(iface) => format!("present:{iface:?}"),
        None => "absent".to_owned(),
    }
}

#[tokio::test]
async fn build_router_never_inserts_interface_extension() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_config(tmp.path().to_path_buf());
    let startup = test_startup(cfg).await;
    let main_router: Router<ServiceState> = Router::new().route(
        "/__test_interface_probe",
        axum::routing::get(interface_probe_handler),
    );
    let openapi = api::ApiDoc::openapi();

    let (app, _http_metrics) = build(&startup, main_router, openapi)
        .await
        .expect("router assembly succeeds");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/__test_interface_probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        body, "absent",
        "build's main app must never stamp an Interface extension itself"
    );
}
