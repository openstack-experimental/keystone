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
//! `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration`: RFC 8414 /
//! OIDC Discovery 1.0 document (ADR 0026 §10, Phase 2).
//!
//! Suffix form (not RFC 8414 §3's literal insertion-before-path rule): a
//! bare cluster-root `/.well-known/openid-configuration` would collide
//! across domains with no way to disambiguate which domain's document is
//! being requested, and this keeps the discovery doc as a sibling of the
//! already-adopted `jwks_uri` pattern (`/v4/oauth2/{domain_id}/jwks`).
//! `/authorize` and `/token` are not functional until Phase 3/4; the URLs
//! below are contractual, same as any phased OIDC rollout.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde_json::json;

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub(super) async fn base_url(state: &ServiceState, headers: &HeaderMap) -> String {
    // Mirrors the fallback chain used by `api::v4::version`:
    // `public_endpoint` -> `Host` header -> `http://localhost`.
    state
        .config_manager
        .config
        .read()
        .await
        .default
        .public_endpoint
        .clone()
        .map(|x| x.to_string().trim_end_matches('/').to_owned())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
        })
        .unwrap_or_else(|| "http://localhost".to_string())
}

/// Publish the OIDC discovery document for a domain.
///
/// Unauthenticated by design, same as `jwks` (ADR 0026 §3): relying parties
/// must be able to fetch it without a Keystone token. 404s if the domain has
/// no signing keys provisioned yet (reuses `jwks()`'s own existence check).
#[utoipa::path(
    get,
    path = "/{domain_id}/.well-known/openid-configuration",
    operation_id = "/oauth2:well_known",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "OIDC discovery document"),
        (status = NOT_FOUND, description = "No signing keys provisioned for this domain"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::well_known",
    level = "debug",
    skip(state),
    err(Debug)
)]
pub(super) async fn well_known(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
) -> Result<impl IntoResponse, KeystoneApiError> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    // Existence check: 404 for a domain with no provisioned signing keys,
    // same signal `jwks.rs` uses.
    state
        .provider
        .get_oauth2_key_provider()
        .jwks(&state, &domain_id)
        .await?;

    let base = base_url(&state, &headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let signing_algorithm = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .signing_algorithm
        .to_string();

    let doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [signing_algorithm],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "device_code",
        ],
        "scopes_supported": ["openid", "profile", "email", "openstack:api"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "amr"],
    });

    Ok(Json(doc))
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
    use serde_json::Value;
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

    fn ok_mock() -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        mock
    }

    #[tokio::test]
    async fn test_well_known_has_required_fields() {
        let provider = Provider::mocked_builder().mock_oauth2_key(ok_mock());
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let doc: Value = serde_json::from_slice(&body).unwrap();
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ] {
            assert!(
                !doc.get(field).unwrap().is_null(),
                "missing required field {field}"
            );
        }
        assert_eq!(doc["issuer"], "http://localhost/v4/oauth2/domain-1");
    }

    #[tokio::test]
    async fn test_well_known_not_found_for_unprovisioned_domain() {
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
                    .uri("/domain-unknown/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_well_known_unauthenticated_reachability() {
        // No `Auth` extractor and no `.extension(vsc)`: must stay reachable
        // without any authentication context.
        let provider = Provider::mocked_builder().mock_oauth2_key(ok_mock());
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_well_known_rate_limit_returns_429_after_burst_exhausted() {
        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        let provider = Provider::mocked_builder()
            .mock_oauth2_key(ok_mock())
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

        let client_addr: SocketAddr = "203.0.113.5:1234".parse().unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let mut req1 = Request::builder()
            .uri("/domain-1/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::OK
        );

        let mut req2 = Request::builder()
            .uri("/domain-1/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
