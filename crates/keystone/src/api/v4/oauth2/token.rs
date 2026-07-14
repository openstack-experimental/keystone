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
//! `POST /v4/oauth2/{domain_id}/token`: `client_credentials` grant (ADR 0026
//! §5, §7.A, §10 Phase 3).
//!
//! Only `grant_type=client_credentials` is implemented -- `authorization_code`
//! and `device_code` are Phase 4. Unauthenticated at the `Auth`-extractor
//! level: the client secret presented in the request body *is* the
//! credential, the same posture as `ApiKeyAuth`
//! (`openstack_keystone_core::api::api_key_auth`). Error responses follow
//! RFC 6749 §5.2 (`{"error", "error_description"}`), not `KeystoneApiError`'s
//! envelope -- this is a token endpoint, not an authenticated Keystone API.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use governor::clock::Clock as _;
use serde::{Deserialize, Serialize};

use openstack_keystone_core::oauth2_client::hydrate_client_credentials_context;
use openstack_keystone_core::oauth2_client::{build_access_token_claims, crypto};
use openstack_keystone_core_types::oauth2_client::GrantType;
use openstack_keystone_key_repository::asymmetric::{jwt_algorithm, to_encoding_key};

use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, build_initiator_unknown,
    emit_perimeter_authenticate_event,
};
use crate::keystone::ServiceState;

use super::well_known::base_url;

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(super) struct TokenForm {
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
}

/// RFC 6749 §5.2 token endpoint error response.
#[derive(Debug, Serialize)]
pub(super) struct Oauth2TokenError {
    #[serde(skip)]
    status: StatusCode,
    #[serde(skip)]
    retry_after: Option<u64>,
    error: &'static str,
    error_description: String,
}

impl Oauth2TokenError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            retry_after: None,
            error,
            error_description: description.into(),
        }
    }

    fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    fn unauthorized_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", description)
    }

    fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            description,
        )
    }

    fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    fn too_many_requests(retry_after: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: Some(retry_after),
            // RFC 6749 §5.2 predates 429 and has no dedicated error code for
            // rate limiting; `invalid_request` is the closest defined code
            // (malformed/unacceptable request). The `429` status + `Retry-After`
            // header are the authoritative signal for clients.
            error: "invalid_request",
            error_description: "rate limit exceeded".to_string(),
        }
    }

    fn internal(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_request",
            description,
        )
    }
}

impl IntoResponse for Oauth2TokenError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = self.retry_after;
        let mut response = (status, Json(self)).into_response();
        if let Some(retry_after) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry_after.into());
        }
        response
    }
}

/// Extract `client_id`/`client_secret` via HTTP Basic (`client_secret_basic`,
/// RFC 6749 §2.3.1), falling back to the form body if no `Authorization`
/// header is present. Basic auth takes precedence when both are given, per
/// RFC 6749 §2.3.1's recommendation against accepting credentials in the
/// body when Basic is available.
fn client_credentials_from_request(
    headers: &HeaderMap,
    form: &TokenForm,
) -> Option<(String, Option<String>)> {
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
    {
        let decoded = STANDARD.decode(basic).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (client_id, client_secret) = decoded.split_once(':')?;
        return Some((client_id.to_string(), Some(client_secret.to_string())));
    }
    form.client_id
        .clone()
        .map(|client_id| (client_id, form.client_secret.clone()))
}

/// `client_credentials` machine-to-machine grant (ADR 0026 §5, §7.A).
#[utoipa::path(
    post,
    path = "/{domain_id}/token",
    operation_id = "/oauth2:token",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Access token issued"),
        (status = BAD_REQUEST, description = "Malformed request, unsupported grant, or invalid scope"),
        (status = UNAUTHORIZED, description = "Invalid client credentials"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::token",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn token(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    Form(form): Form<TokenForm>,
) -> Result<Response, Oauth2TokenError> {
    let Some(grant_type) = form.grant_type.as_deref() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: grant_type",
        ));
    };
    if grant_type != "client_credentials" {
        return Err(Oauth2TokenError::unsupported_grant_type(format!(
            "grant_type `{grant_type}` is not supported; only `client_credentials` is implemented"
        )));
    }

    let Some((client_id, client_secret)) = client_credentials_from_request(&headers, &form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };

    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();

    // Step 1 (ADR 0026 §7.A "Pre-Hash Enforcement"): rate limit on the raw,
    // unverified client_id string, before any storage lookup or Argon2id
    // verification.
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let exec = openstack_keystone_core::auth::ExecutionContext::internal(&state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;

    let Some(client) = client.filter(|c| c.domain_id == domain_id) else {
        // Enumeration defense (ADR 0026 §7.A / mirrors ADR 0021 Invariant
        // 7): burn the same Argon2id cost a real "found but wrong secret"
        // verification would. Only normalizes cost *after* the lookup --
        // the pre-hash rate limiter above (keyed on raw client_id, checked
        // before this DB query) is the actual defense against the DB
        // lookup's own variable timing revealing client_id existence.
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    if !client.enabled || client.deleted_at.is_some() {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the client_credentials grant",
        ));
    }

    // RFC 6749 §4.4 requires a confidential client for client_credentials --
    // a public client has no secret to verify at all.
    let Some(secret_hash) = client.client_secret_hash.as_deref() else {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };
    let Some(presented_secret) = client_secret else {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    let verified = crypto::verify_secret(&presented_secret, secret_hash)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client secret argon2 verification errored");
            Oauth2TokenError::internal("client authentication failed")
        })?;
    if !verified {
        emit_perimeter_authenticate_event(
            &state.audit_dispatcher,
            &correlation_id.0,
            build_initiator_unknown(),
            "failure",
            Some("client authentication failed".to_string()),
        );
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    // Scope Validation (ADR 0026 §4): requested scope must be a subset of
    // `allowed_scopes`, reject-outright, never silently narrowed. Omitted
    // scope defaults to the client's full `allowed_scopes`.
    let granted_scope: Vec<String> = match &form.scope {
        Some(requested) => {
            let requested: Vec<String> = requested.split_whitespace().map(str::to_string).collect();
            if requested
                .iter()
                .any(|s| !client.allowed_scopes.iter().any(|allowed| allowed == s))
            {
                return Err(Oauth2TokenError::invalid_scope(
                    "requested scope exceeds the client's allowed_scopes",
                ));
            }
            requested
        }
        None => client.allowed_scopes.clone(),
    };

    let (vsc, ruleset_version) = hydrate_client_credentials_context(&state, &client)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client_credentials mapping ingress failed");
            Oauth2TokenError::invalid_client("client is not authorized for any scope")
        })?;

    let base = base_url(&state, &headers).await;
    let issuer = format!("{base}/v4/oauth2/{}", client.domain_id);
    let now = chrono::Utc::now().timestamp();
    let lifetime_seconds = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let exp = now + lifetime_seconds;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = build_access_token_claims(&client, &vsc, &issuer, jti, ruleset_version, now, exp)
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 access token claim construction failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let signing_key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(&state, &client.domain_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 signing key lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let encoding_key = to_encoding_key(&signing_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 signing key conversion failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(signing_key.algorithm));
    header.kid = Some(openstack_keystone_key_repository::asymmetric::derive_kid(
        &signing_key.public_key_der,
    ));
    let access_token = jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 access token signing failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;

    emit_perimeter_authenticate_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        build_initiator_from_vsc(&vsc),
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: lifetime_seconds,
        scope: granted_scope.join(" "),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
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
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core_types::auth::AuthenticationResultBuilder;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalIdentityInfoBuilder,
        PrincipalInfo, ScopeInfo,
    };
    use openstack_keystone_core_types::mapping::auth::MappingContext;
    use openstack_keystone_core_types::mapping::authorization::Authorization;
    use openstack_keystone_core_types::mapping::resolution::DomainResolutionMode;
    use openstack_keystone_core_types::mapping::resolution::IdentitySource;
    use openstack_keystone_core_types::mapping::rule::{
        IdentityBinding, MappingRule, MatchCriteria,
    };
    use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;
    use openstack_keystone_core_types::oauth2_client as provider_types;
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::mapping::MockMappingProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    async fn confidential_client() -> provider_types::OAuth2ClientResource {
        let cfg = openstack_keystone_config::Oauth2Provider {
            argon2_memory_kib: 8,
            argon2_time_cost: 1,
            argon2_parallelism: 1,
            ..Default::default()
        };
        let hash = openstack_keystone_core::oauth2_client::crypto::hash_secret(
            &secrecy::SecretString::from("s3cr3t".to_string()),
            &cfg,
        )
        .await
        .unwrap();
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: Some(hash),
            redirect_uris: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![provider_types::GrantType::ClientCredentials],
            require_pkce: false,
            allowed_scopes: vec!["openstack:api".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn matching_ruleset() -> MappingRuleSet {
        MappingRuleSet {
            mapping_id: "m1".to_string(),
            domain_id: Some("domain-1".to_string()),
            source: IdentitySource::OAuth2Client {
                provider_id: "provider-1".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![MappingRule {
                name: "always".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    identity_mode: None,
                    user_name: "client-1".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![Authorization::Domain {
                    domain_id: "domain-1".to_string(),
                    roles: vec![RoleRef {
                        id: "role-1".to_string(),
                        name: Some("member".to_string()),
                        domain_id: None,
                    }],
                }],
                groups: vec![],
            }],
            ruleset_version: 7,
        }
    }

    fn successful_auth_result() -> openstack_keystone_core_types::auth::AuthenticationResult {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Mapping(MappingContext {
                mapping_id: "m1".to_string(),
                matched_rule_name: "always".to_string(),
                virtual_user_id: "shadow-1".to_string(),
                is_system: false,
            }))
            .principal(PrincipalInfo {
                identity: IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id("shadow-1")
                        .resolved_user_name("client-1")
                        .issuer("oauth2_client:provider-1")
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .scope(ScopeInfo::Domain(
                        openstack_keystone_core_types::resource::Domain {
                            id: "domain-1".to_string(),
                            name: String::new(),
                            description: None,
                            enabled: true,
                            extra: Default::default(),
                        },
                    ))
                    .roles(vec![RoleRef {
                        id: "role-1".to_string(),
                        name: Some("member".to_string()),
                        domain_id: None,
                    }])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn ok_key_mock() -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_active_signing_key()
            .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        mock
    }

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/token")
            .method("POST")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_missing_grant_type_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("client_id=client-1&client_secret=s3cr3t"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_unsupported_grant_type() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=authorization_code&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_unknown_client_id_is_invalid_client() {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=unknown&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_without_client_credentials_grant_is_unauthorized_client() {
        let mut client = confidential_client().await;
        client.grant_types = vec![provider_types::GrantType::AuthorizationCode];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn test_wrong_secret_is_invalid_client() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=wrong",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_public_client_cannot_use_client_credentials() {
        let mut client = confidential_client().await;
        client.client_secret_hash = None;
        client.require_pkce = true;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_scope_outside_allowed_scopes_is_invalid_scope() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t&scope=not-allowed",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_successful_client_credentials_issues_signed_jwt() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_get_ruleset_by_source()
            .returning(|_, _, _| Ok(Some(matching_ruleset())));
        mapping_mock
            .expect_authenticate_by_mapping()
            .returning(|_, _| Ok(successful_auth_result()));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_mapping(mapping_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        let access_token = body["access_token"].as_str().unwrap();
        // Three dot-separated JWT segments, no signature validation here
        // (that belongs to the downstream middleware's own test suite).
        assert_eq!(access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_rate_limit_returns_429_before_client_lookup() {
        let config = Config {
            oauth2: openstack_keystone_config::Oauth2Provider {
                token_rate_limit_burst_size: 1,
                token_rate_limit_replenish_per_minute: 1,
                ..Default::default()
            },
            ..Config::default()
        };

        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // (mocked) client lookup, which reports "not found".
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut req2 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Second request for the same client_id, burst exhausted: rejected
        // by the rate limiter before any further client lookup or Argon2id
        // work (ADR 0026 §7.A).
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
