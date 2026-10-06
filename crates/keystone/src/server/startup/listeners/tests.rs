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
use axum::http::Request;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::*;
use crate::server::startup::test_support::{test_config, test_state};

#[tokio::test]
async fn metrics_handler_includes_http_metrics_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.interface_metrics.http_requests_enabled = true;
    let state = test_state(cfg).await;

    let http_metrics = Arc::new(HttpMetrics::new());
    http_metrics.record_request(
        &axum::http::Method::GET,
        "/v3/probe",
        200,
        std::time::Duration::from_millis(1),
    );

    let app = Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .layer(Extension(http_metrics))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(
        "keystone_http_requests_total{method=\"GET\",route=\"/v3/probe\",status=\"200\"} 1"
    ));
}

#[tokio::test]
async fn metrics_handler_omits_http_metrics_when_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.interface_metrics.http_requests_enabled = false;
    let state = test_state(cfg).await;

    // No `Extension<Arc<HttpMetrics>>` layered at all, matching what
    // `spawn_metrics` does when the flag is off.
    let app = Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("keystone_http_requests_total"));
    // The always-on metrics must still be present.
    assert!(text.contains("keystone_audit_events_total"));
}

/// Pins the full `/metrics` response body as served today (audit series,
/// the auth-plugin load-failure counter and the HTTP series) against
/// `tests/golden/metrics_endpoint.prom` (ADR 0040).
#[tokio::test]
async fn metrics_endpoint_golden() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(tmp.path().to_path_buf());
    cfg.interface_metrics.http_requests_enabled = true;
    let state = test_state(cfg).await;
    state
        .auth_plugin_load_failures
        .write()
        .await
        .insert("geoip".to_string(), 1);

    let http_metrics = Arc::new(HttpMetrics::new());
    http_metrics.record_request(
        &axum::http::Method::GET,
        "/v3/probe",
        200,
        std::time::Duration::from_millis(1),
    );

    let app = Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .layer(Extension(http_metrics))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    openstack_keystone_metrics::assert_golden!("metrics_endpoint", text);
}
