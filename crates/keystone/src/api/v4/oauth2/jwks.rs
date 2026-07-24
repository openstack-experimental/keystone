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
//! `GET /v4/oauth2/{domain_id}/jwks`: public JSON Web Key Set (ADR 0026 §3).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Publish a domain's active OAuth2 signing keys as a JWKS.
///
/// Unauthenticated by design (ADR 0026 §3): relying parties and edge proxies
/// must be able to fetch and cache this without a Keystone token.
/// `Cache-Control: public, max-age=300` aligns with the 300-second cache
/// refresh window relied on by the Python middleware (§3, "Key Lifecycle &
/// The Cache Invalidation Window"). Publishes both `Primary` and `Previous`
/// (when a rotation happened recently) — the multi-generational publishing
/// pool that keeps outstanding tokens verifiable during a key's grace
/// window.
#[utoipa::path(
    get,
    path = "/{domain_id}/jwks",
    operation_id = "/oauth2:jwks",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "JSON Web Key Set"),
        (status = NOT_FOUND, description = "No signing keys provisioned for this domain"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::jwks",
    level = "debug",
    skip(state),
    err(Debug)
)]
pub(super) async fn jwks(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Global per-IP rate-limit check (ADR-0022, Invariant 4, 8).
    // Unauthenticated endpoint — per-IP is the primary throttle applied
    // before any backend work.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    let jwk_set = state
        .provider
        .get_oauth2_key_provider()
        .jwks(&state, &domain_id)
        .await?;

    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(jwk_set),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, RateLimitSection};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair,
    };

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state as default_get_mocked_state;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_jwks_returns_single_key_and_cache_control_header() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "public, max-age=300"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_jwks_returns_two_keys_when_previous_present() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: Some(generate_keypair(SigningAlgorithm::Es256).unwrap()),
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks.keys.len(), 2);
    }

    #[tokio::test]
    async fn test_jwks_request_without_auth_header_still_succeeds() {
        // No `Auth` extractor and no `.extension(vsc)` on the request: this
        // endpoint must stay reachable without any authentication context.
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwks_returns_not_found_for_unknown_domain() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            Err(
                openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError::NotFound(
                    "domain-unknown".into(),
                ),
            )
        });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-unknown/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Global per-IP rate limiting fires before provider call (ADR-0022,
    /// Invariant 4, 8). The first request consumes the burst token and passes
    /// through to the provider; the second from the same IP must be rejected
    /// with 429 before `jwks()` is ever invoked.
    #[tokio::test]
    async fn test_jwks_rate_limit_returns_429_after_burst_exhausted() {
        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_key(mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.1:1234".parse().unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // First request — passes the rate limit, succeeds.
        let mut req1 = Request::builder()
            .uri("/domain-1/jwks")
            .body(Body::empty())
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        let resp1 = api.as_service().oneshot(req1).await.unwrap();
        assert_eq!(
            resp1.status(),
            StatusCode::OK,
            "first request must not be rate-limited"
        );

        // Second request from the same IP — burst exhausted → 429 + Retry-After.
        let mut req2 = Request::builder()
            .uri("/domain-1/jwks")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        let resp2 = api.as_service().oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second request must be rate-limited"
        );

        let retry_after = resp2
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("429 response must carry Retry-After header")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(
            retry_after >= 1,
            "Retry-After must be at least 1 second (ADR-0022 Invariant 10)"
        );
    }

    /// Different IPs have independent rate-limit quotas (ADR-0022 Invariant 5).
    /// Exhausting one client's burst must not affect another.
    #[tokio::test]
    async fn test_jwks_rate_limit_different_ips_have_independent_quotas() {
        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_key(mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let first_ip: SocketAddr = "192.0.2.1:1111".parse().unwrap();
        let second_ip: SocketAddr = "192.0.2.2:2222".parse().unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // First IP: consumes burst.
        let mut req1 = Request::builder()
            .uri("/domain-1/jwks")
            .body(Body::empty())
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(first_ip));
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::OK
        );

        // First IP: burst exhausted → 429.
        let mut req2 = Request::builder()
            .uri("/domain-1/jwks")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(first_ip));
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // Second IP: independent bucket, should succeed.
        let mut req3 = Request::builder()
            .uri("/domain-1/jwks")
            .body(Body::empty())
            .unwrap();
        req3.extensions_mut().insert(ConnectInfo(second_ip));
        assert_eq!(
            api.as_service().oneshot(req3).await.unwrap().status(),
            StatusCode::OK,
            "second IP must not be rate-limited"
        );
    }
}
