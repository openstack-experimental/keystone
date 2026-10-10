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
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

use super::token::Oauth2TokenError;

/// Grant type URN for the OAuth 2.0 device authorization grant (RFC 8628 §3.4).
const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Grant type URN for OAuth 2.0 token exchange (RFC 8693).
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

/// OIDC Discovery 1.0 / RFC 8414 / RFC 8628 provider metadata.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct OpenIdConfiguration {
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Supported claim types.
    pub claim_types_supported: Vec<String>,
    /// Claims that may be present in issued tokens.
    pub claims_supported: Vec<String>,
    /// Supported PKCE code challenge methods (RFC 7636).
    pub code_challenge_methods_supported: Vec<String>,
    /// Device authorization endpoint URL (RFC 8628 §4).
    pub device_authorization_endpoint: String,
    /// Supported grant type identifiers.
    pub grant_types_supported: Vec<String>,
    /// JWS algorithms used to sign ID tokens.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Issuer identifier of the domain.
    pub issuer: String,
    /// JWKS document URL.
    pub jwks_uri: String,
    /// RP-Initiated Logout endpoint URL (OIDC RP-Initiated Logout 1.0).
    pub end_session_endpoint: String,
    /// Supported `prompt` values (OIDC Core §3.1.2.1).
    pub prompt_values_supported: Vec<String>,
    /// Whether the `request` parameter is supported.
    pub request_parameter_supported: bool,
    /// Whether the `request_uri` parameter is supported.
    pub request_uri_parameter_supported: bool,
    /// Supported `response_mode` values.
    pub response_modes_supported: Vec<String>,
    /// Supported `response_type` values.
    pub response_types_supported: Vec<String>,
    /// Token introspection endpoint URL (RFC 7662).
    pub introspection_endpoint: String,
    /// Client authentication methods accepted by the introspection endpoint
    /// (confidential clients only).
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    /// Token revocation endpoint URL (RFC 7009).
    pub revocation_endpoint: String,
    /// Client authentication methods accepted by the revocation endpoint.
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// Supported scope values.
    pub scopes_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// Client authentication methods accepted by the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// UserInfo endpoint URL (OIDC Core §5.3).
    pub userinfo_endpoint: String,
    /// JWS algorithms the UserInfo response may be signed with; `none`
    /// means a plain JSON response.
    pub userinfo_signing_alg_values_supported: Vec<String>,
}

impl Default for OpenIdConfiguration {
    fn default() -> Self {
        Self {
            authorization_endpoint: String::new(),
            claim_types_supported: strings(&["normal"]),
            claims_supported: strings(&[
                "amr",
                "at_hash",
                "aud",
                "auth_time",
                "email",
                "email_verified",
                "exp",
                "iat",
                "iss",
                "jti",
                "name",
                "nonce",
                "preferred_username",
                "scope",
                "sub",
                "token_use",
            ]),
            code_challenge_methods_supported: strings(&["S256"]),
            device_authorization_endpoint: String::new(),
            grant_types_supported: strings(&[
                "authorization_code",
                "client_credentials",
                "refresh_token",
                GRANT_TYPE_DEVICE_CODE,
                GRANT_TYPE_TOKEN_EXCHANGE,
            ]),
            id_token_signing_alg_values_supported: Vec::new(),
            issuer: String::new(),
            jwks_uri: String::new(),
            end_session_endpoint: String::new(),
            prompt_values_supported: strings(&["none", "login", "consent", "select_account"]),
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            response_modes_supported: strings(&["query"]),
            response_types_supported: strings(&["code"]),
            introspection_endpoint: String::new(),
            introspection_endpoint_auth_methods_supported: strings(&[
                "client_secret_basic",
                "client_secret_post",
            ]),
            revocation_endpoint: String::new(),
            revocation_endpoint_auth_methods_supported: strings(&["client_secret_basic"]),
            scopes_supported: strings(&["email", "openid", "openstack:api", "profile"]),
            subject_types_supported: strings(&["public"]),
            token_endpoint: String::new(),
            token_endpoint_auth_methods_supported: strings(&[
                "client_secret_basic",
                "client_secret_post",
                "none",
            ]),
            userinfo_endpoint: String::new(),
            userinfo_signing_alg_values_supported: strings(&["none"]),
        }
    }
}

/// Refuse to serve an issuer-bearing OP response unless the issuer is pinned.
///
/// Without `[DEFAULT] public_endpoint` the issuer would follow the request
/// `Host` header, letting a client pick the `iss` claim, the discovery
/// document and the device-flow `verification_uri`. Returns the RFC 6749
/// §5.2 `server_error` (503) unless `public_endpoint` is set or the
/// development-only `[oauth2] allow_host_header_issuer` override is on.
pub(super) async fn ensure_trusted_issuer(state: &ServiceState) -> Result<(), Oauth2TokenError> {
    if crate::api::common::oauth2_issuer_is_trusted(state).await {
        return Ok(());
    }
    tracing::error!(
        "OAuth2 OP request refused: [DEFAULT] public_endpoint is not set, so the \
         issuer would be derived from the Host header; configure public_endpoint \
         (or set [oauth2] allow_host_header_issuer = true for development only)"
    );
    Err(Oauth2TokenError::server_error_unavailable(
        "the OAuth2 provider is not configured with a public endpoint",
    ))
}

pub(super) async fn base_url(state: &ServiceState, headers: &HeaderMap) -> String {
    // Mirrors the fallback chain used by `api::common::public_base_url`:
    // `public_endpoint` -> `Host` header + `X-Forwarded-Proto` -> `http://localhost`.
    crate::api::common::public_base_url(state, headers)
        .await
        .trim_end_matches('/')
        .to_owned()
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
        (status = OK, description = "OIDC discovery document", body = OpenIdConfiguration),
        (status = NOT_FOUND, description = "No signing keys provisioned for this domain"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
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
) -> Result<Response, KeystoneApiError> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    if let Err(err) = ensure_trusted_issuer(&state).await {
        return Ok(err.into_response());
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

    let doc = OpenIdConfiguration {
        authorization_endpoint: format!("{issuer}/authorize"),
        device_authorization_endpoint: format!("{issuer}/device_authorization"),
        end_session_endpoint: format!("{issuer}/logout"),
        id_token_signing_alg_values_supported: vec![signing_algorithm],
        issuer: issuer.clone(),
        jwks_uri: format!("{issuer}/jwks"),
        introspection_endpoint: format!("{issuer}/introspect"),
        revocation_endpoint: format!("{issuer}/revoke"),
        token_endpoint: format!("{issuer}/token"),
        userinfo_endpoint: format!("{issuer}/userinfo"),
        ..OpenIdConfiguration::default()
    };

    Ok(Json(doc).into_response())
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

    use cadf::AuditDispatcher;
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
            "introspection_endpoint",
            "introspection_endpoint_auth_methods_supported",
            "revocation_endpoint",
            "revocation_endpoint_auth_methods_supported",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "userinfo_endpoint",
            "userinfo_signing_alg_values_supported",
            "end_session_endpoint",
            "prompt_values_supported",
        ] {
            assert!(
                !doc.get(field).unwrap().is_null(),
                "missing required field {field}"
            );
        }
        let issuer = "http://localhost/v4/oauth2/domain-1";
        assert_eq!(doc["issuer"], issuer);
        assert_eq!(
            doc["device_authorization_endpoint"],
            format!("{issuer}/device_authorization")
        );
        assert_eq!(
            doc["grant_types_supported"],
            serde_json::json!([
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ])
        );
        assert_eq!(
            doc["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
        );
        assert_eq!(
            doc["response_modes_supported"],
            serde_json::json!(["query"])
        );
        assert_eq!(doc["claim_types_supported"], serde_json::json!(["normal"]));
        assert_eq!(doc["request_parameter_supported"], false);
        assert_eq!(doc["request_uri_parameter_supported"], false);
        let claims = doc["claims_supported"].as_array().unwrap();
        for claim in ["nonce", "at_hash", "jti", "scope", "token_use", "email"] {
            assert!(claims.iter().any(|c| c == claim), "missing claim {claim}");
        }
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
            oauth2: openstack_keystone_config::Oauth2Provider {
                allow_host_header_issuer: true,
                ..Default::default()
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
