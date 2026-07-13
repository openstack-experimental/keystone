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
//! # Keystone API
//!
//! Keystone is following the API first principles. The user or other services
//! interact with it using the API.
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub(crate) mod common;
pub mod error;
pub mod health;
pub mod types;
pub mod v3;
pub mod v4;

use crate::api::types::*;

/// OpenApi specification.
#[derive(OpenApi)]
#[openapi(
    info(version = "4.0.1"),
    modifiers(&SecurityAddon),
    nest(
      (path = "v3", api = v3::ApiDoc),
      (path = "v4", api = v4::ApiDoc),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "x-auth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-auth-token"))),
            );
        }
    }
}

/// Main API router.
pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/v3", v3::openapi_router())
        .nest("/v4", v4::openapi_router())
        .merge(health::openapi_router())
        .routes(routes!(version))
}

/// Version discovery endpoint.
#[utoipa::path(
    get,
    path = "/",
    description = "Version discovery",
    responses(
        (status = OK, description = "Versions", body = Versions),
    ),
    tag = "version"
)]
async fn version(
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let host = state
        .config_manager
        .config
        .read()
        .await
        .default
        .public_endpoint
        .clone()
        .map(|x| x.to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
        })
        .unwrap_or_else(|| "http://localhost".to_string());

    let res = Versions {
        versions: Values {
            values: vec![
                VersionBuilder::default()
                    .id("v3.14")
                    .status(VersionStatus::Stable)
                    .links(vec![Link::new(format!("{host}/v3"))])
                    .media_types(vec![MediaType::default()])
                    .build()?,
                VersionBuilder::default()
                    .id("v4.0")
                    .status(VersionStatus::Stable)
                    .links(vec![Link::new(format!("{host}/v4"))])
                    .media_types(vec![MediaType::default()])
                    .build()?,
            ],
        },
    };
    Ok((StatusCode::OK, Json(res)).into_response())
}

#[cfg(test)]
pub(crate) mod tests {
    pub use openstack_keystone_core::api::tests::{get_mocked_state, test_fixture_scoped};

    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Router, ServiceExt as AxumServiceExt};
    use tower::{Layer, ServiceExt};
    use tower_http::normalize_path::NormalizePathLayer;

    use super::openapi_router;
    use crate::provider::Provider;

    /// A request to a route with a trailing slash must be served by the same
    /// handler as the canonical (no-slash) path — no 404 and no redirect
    /// (issue #734). This guards both that the middleware is wired in and that
    /// `trim_trailing_slash` is the correct direction for this router, whose
    /// routes are registered canonically without a trailing slash.
    #[tokio::test]
    async fn trailing_slash_is_normalized() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let (router, _) = openapi_router().split_for_parts();
        let app = NormalizePathLayer::trim_trailing_slash().layer(router.with_state(state));

        // `/v3` is the canonical version-discovery route (needs no auth/DB).
        let canonical = app
            .clone()
            .oneshot(Request::builder().uri("/v3").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // `/v3/` must be normalized to `/v3` and hit the same handler.
        let with_slash = app
            .oneshot(Request::builder().uri("/v3/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_ne!(with_slash.status(), StatusCode::NOT_FOUND);
        assert!(!with_slash.status().is_redirection());
        assert_eq!(with_slash.status(), canonical.status());
    }

    /// Issue #358: the public listener captures the raw TCP peer address into a
    /// `ConnectInfo<SocketAddr>` request extension (the keystone-ng analogue of
    /// Python Keystone's WSGI `REMOTE_ADDR`). This verifies the capture works
    /// and composes with the #734 `NormalizePathLayer` wrap: a
    /// trailing-slash request still normalizes while `ConnectInfo` is
    /// populated. Driven fully in-process via `Connected<SocketAddr> for
    /// SocketAddr`, so no real socket is needed.
    #[tokio::test]
    async fn connect_info_is_captured_and_normalizes() {
        async fn echo_addr(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
            addr.to_string()
        }

        let router = Router::new().route("/echo", get(echo_addr));
        let app = NormalizePathLayer::trim_trailing_slash().layer(router);

        // Same make-service path the public listener uses; the explicit request
        // type satisfies inference (E0284), as in the binary.
        let make =
            AxumServiceExt::<Request<Body>>::into_make_service_with_connect_info::<SocketAddr>(app);
        let addr: SocketAddr = "192.0.2.4:5555".parse().unwrap();
        // `Connected<SocketAddr> for SocketAddr` lets us drive the make-service
        // with a fixed peer address instead of a live TCP connection.
        let svc = make.oneshot(addr).await.unwrap();

        // `/echo/` (trailing slash) must normalize to `/echo` AND the handler
        // must observe the injected peer address.
        let response = svc
            .oneshot(
                Request::builder()
                    .uri("/echo/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"192.0.2.4:5555");
    }

    /// Issue #358 follow-up: when proxy-header parsing is enabled (config-gated,
    /// off by default), the public listener wraps the router with the
    /// `rewrite_client_addr` layer, exactly as `spawn_public_listener` does:
    /// the layer sits on the outer `Router`, *outside* the #734
    /// `NormalizePathLayer` fallback. This drives that full production
    /// composition in-process and asserts that a `/echo/` request carrying
    /// `X-Forwarded-For` (a) still normalizes the trailing slash, (b) reaches
    /// the handler, and (c) delivers the *proxy-resolved* client address — not
    /// the raw TCP peer — proving the layer runs before routing/normalization
    /// and rewrites `ConnectInfo` end to end.
    #[tokio::test]
    async fn proxy_headers_rewrite_client_addr_and_normalize() {
        async fn echo_addr(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
            addr.ip().to_string()
        }

        let router = Router::new().route("/echo", get(echo_addr));
        // Mirror `build_router`: the API service is `NormalizePath`-wrapped and
        // mounted as the outer router's fallback.
        let normalized = NormalizePathLayer::trim_trailing_slash().layer(router);
        // The raw peer (10.0.0.9) must be a trusted proxy for the header to be
        // honoured, mirroring the `[oslo_middleware] trusted_proxies` allowlist.
        let proxy_config = std::sync::Arc::new(openstack_keystone_config::OsloMiddleware {
            enable_proxy_headers_parsing: true,
            trusted_header: openstack_keystone_config::ProxyHeader::XForwardedFor,
            trusted_proxies: vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()],
        });
        let app =
            Router::new()
                .fallback_service(normalized)
                .layer(axum::middleware::from_fn_with_state(
                    proxy_config,
                    crate::server::proxy_headers::rewrite_client_addr,
                ));

        let make =
            AxumServiceExt::<Request<Body>>::into_make_service_with_connect_info::<SocketAddr>(app);
        // Raw TCP peer is the reverse proxy; the header carries the real client.
        let peer: SocketAddr = "10.0.0.9:5555".parse().unwrap();
        let svc = make.oneshot(peer).await.unwrap();

        let response = svc
            .oneshot(
                Request::builder()
                    .uri("/echo/")
                    .header("x-forwarded-for", "203.0.113.7, 10.0.0.9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"203.0.113.7");
    }
}
