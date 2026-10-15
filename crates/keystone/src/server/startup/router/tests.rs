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
use crate::server::startup::test_support::{test_config, test_startup};

async fn build_test_router(cfg: crate::config::Config) -> (Router, Option<Arc<HttpMetrics>>) {
    let startup = test_startup(cfg).await;
    let (main_router, _main_api) = api::openapi_router(true).split_for_parts();
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
    assert!(
        http_metrics.is_some(),
        "HttpMetrics must be Some when enabled"
    );

    let _ = app
        .oneshot(Request::builder().uri("/v3/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let text = openstack_keystone_telemetry::metrics::render_prometheus();
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

async fn passkey_probe_handler(req: Request<Body>) -> &'static str {
    if req.extensions().get::<Arc<dyn PasskeyFactor>>().is_some() {
        "present"
    } else {
        "absent"
    }
}

// The OAuth2 provider only sees the passkey handle if `mount_extensions`
// layers it over the main routes, so a route of the main router has to get it
// when WebAuthn is enabled, and must not when it is not.
#[tokio::test]
async fn build_router_hands_the_passkey_factor_to_main_routes_only_when_enabled() {
    for enabled in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config(tmp.path().to_path_buf());
        cfg.webauthn.enabled = enabled;
        cfg.webauthn.relying_party = Some(crate::config::RelyingParty {
            id: "localhost".into(),
            name: None,
            origin: "http://localhost:8080".parse().unwrap(),
        });
        let startup = test_startup(cfg).await;
        let main_router: Router<ServiceState> = Router::new().route(
            "/__test_passkey_probe",
            axum::routing::get(passkey_probe_handler),
        );
        let (app, _http_metrics) = build(&startup, main_router, api::ApiDoc::openapi())
            .await
            .expect("router assembly succeeds");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/__test_passkey_probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, if enabled { "present" } else { "absent" });
    }
}

// ADR 0023 §2.1: a client-supplied `x-openstack-request-id` must never become
// the correlation id of the audit trail (spoofing guard); the server mints a
// fresh one and returns it.
#[tokio::test]
async fn client_supplied_request_id_is_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _http_metrics) = build_test_router(test_config(tmp.path().to_path_buf())).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v3/")
                .header("x-openstack-request-id", "req-attacker-chosen")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let id = response
        .headers()
        .get("x-openstack-request-id")
        .expect("the response carries the server-minted request id")
        .to_str()
        .unwrap();
    assert_ne!(id, "req-attacker-chosen");
    assert!(id.starts_with("req-"), "unexpected id format: {id}");
}

// A disabled OAuth2 provider is not mounted: its routes answer 404 and are
// absent from the OpenAPI document.
#[tokio::test]
async fn oauth2_routes_absent_when_disabled() {
    let (_, enabled_api) = api::openapi_router(true).split_for_parts();
    let (disabled_router, disabled_api) = api::openapi_router(false).split_for_parts();
    assert!(
        enabled_api
            .paths
            .paths
            .keys()
            .any(|p| p.starts_with("/v4/oauth2/"))
    );
    assert!(
        !disabled_api
            .paths
            .paths
            .keys()
            .any(|p| p.starts_with("/v4/oauth2/"))
    );

    let tmp = tempfile::tempdir().unwrap();
    let startup = test_startup(test_config(tmp.path().to_path_buf())).await;
    let (app, _) = build(&startup, disabled_router, api::ApiDoc::openapi())
        .await
        .expect("router assembly succeeds");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v4/oauth2/default/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

// A domain outside `[oauth2] enabled_domains` answers 404 before any handler
// runs.
#[tokio::test]
async fn oauth2_domain_outside_allowlist_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.oauth2.enabled_domains = Some(vec!["pilot".into()]);
    let (app, _) = build_test_router(cfg).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v4/oauth2/other/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

// The gate matches the raw path segment: a percent-encoded id never equals an
// allowlist entry, so it fails closed.
#[tokio::test]
async fn oauth2_gate_fails_closed_on_encoded_domain_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.oauth2.enabled_domains = Some(vec!["pilot".into()]);
    let (app, _) = build_test_router(cfg).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v4/oauth2/%70ilot/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

// Shared static assets are not per-domain and bypass the allowlist: the gate
// must not answer for them (an unknown asset is still the handler's 404, but
// an empty allowlist must not change the outcome vs. no allowlist).
#[tokio::test]
async fn oauth2_gate_exempts_static_assets() {
    let tmp = tempfile::tempdir().unwrap();
    let uri = "/v4/oauth2/static/missing.css";
    let (open, _) = build_test_router(test_config(tmp.path().to_path_buf())).await;
    let open_status = open
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status();

    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.oauth2.enabled_domains = Some(vec![]);
    let (gated, _) = build_test_router(cfg).await;
    let gated_status = gated
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status();
    assert_eq!(open_status, gated_status);
}
