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
//! `GET|POST /v4/oauth2/{domain_id}/userinfo`: OIDC UserInfo endpoint
//! (OIDC Core §5.3, ADR 0026).
//!
//! Authenticated by the OIDC access token (`OidcAccessTokenClaims`) as an
//! RFC 6750 `Authorization: Bearer` credential. The token is verified
//! offline against the domain's signing keys and JTI revocation list, its
//! `aud` is resolved to a registered, enabled client of this domain and the
//! subject user must still exist and be enabled.
//!
//! Claims: `sub` always; `name`, `preferred_username`, `updated_at` with the
//! `profile` scope; `email` and `email_verified` with the `email` scope
//! (Keystone does not verify addresses, so `email_verified` is `false`
//! unless the user record explicitly says otherwise); plus the client's
//! `claims_template` output, built by the same code as the `id_token` so
//! both agree. The response is plain JSON (`userinfo_signing_alg_values_supported`
//! is `["none"]`).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use cadf::{Outcome, OutcomeReason};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::{
    TemplateScope, TokenVerificationError, verify_oidc_access_token,
};
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use crate::api::common::PeerAddr;
use crate::api::v4::oauth2::well_known::{base_url, ensure_trusted_issuer};
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

use super::html::no_store;
use super::token::Oauth2TokenError;

/// RFC 6750 §3 error response of the UserInfo endpoint.
#[derive(Debug)]
enum UserinfoError {
    /// Token valid but lacks the `openid` scope.
    InsufficientScope,
    Internal,
    /// Token missing/malformed/expired/revoked/foreign, or its user or
    /// client is gone. Deliberately a single indistinguishable answer.
    InvalidToken,
    /// No credentials presented: bare `WWW-Authenticate: Bearer`.
    MissingToken,
    TooManyRequests(u64),
    Unavailable(Oauth2TokenError),
}

impl IntoResponse for UserinfoError {
    fn into_response(self) -> Response {
        let (status, www_authenticate, description) = match self {
            Self::InsufficientScope => (
                StatusCode::FORBIDDEN,
                "Bearer error=\"insufficient_scope\", scope=\"openid\"".to_string(),
                Some("the access token does not include the openid scope"),
            ),
            Self::Internal => {
                return Oauth2TokenError::internal("userinfo request failed").into_response();
            }
            Self::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Bearer error=\"invalid_token\"".to_string(),
                Some("the access token is invalid"),
            ),
            Self::MissingToken => (StatusCode::UNAUTHORIZED, "Bearer".to_string(), None),
            Self::TooManyRequests(retry_after) => {
                return Oauth2TokenError::too_many_requests(retry_after).into_response();
            }
            Self::Unavailable(err) => return err.into_response(),
        };
        let mut response = match description {
            Some(description) => (
                status,
                Json(json!({
                    "error": if status == StatusCode::FORBIDDEN {
                        "insufficient_scope"
                    } else {
                        "invalid_token"
                    },
                    "error_description": description,
                })),
            )
                .into_response(),
            None => status.into_response(),
        };
        if let Ok(value) = HeaderValue::from_str(&www_authenticate) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        no_store(response)
    }
}

impl UserinfoError {
    /// The CADF `(outcome, outcome_reason)` of this rejection, so every
    /// failed bearer presentation is audited, not only the successes.
    ///
    /// The reasons are a closed, PII-free vocabulary: they name the class of
    /// rejection, never the token or the error text (ADR 0023 "Outcome
    /// Isolation").
    fn audit_outcome(&self) -> (Outcome, OutcomeReason) {
        let reason = match self {
            Self::InsufficientScope => "InsufficientScope",
            Self::Internal => "Internal",
            Self::InvalidToken => "InvalidToken",
            Self::MissingToken => "MissingToken",
            Self::TooManyRequests(_) => "TooManyRequests",
            Self::Unavailable(_) => "Unavailable",
        };
        (Outcome::Failure, OutcomeReason::literal(reason))
    }
}

/// Extract the RFC 6750 §2.1 bearer token from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token.trim()).filter(|t| !t.is_empty())
}

/// OIDC UserInfo endpoint (`GET`).
#[utoipa::path(
    get,
    path = "/{domain_id}/userinfo",
    operation_id = "/oauth2:userinfo:get",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "UserInfo claims", body = serde_json::Value),
        (status = UNAUTHORIZED, description = "Missing or invalid access token"),
        (status = FORBIDDEN, description = "Access token lacks the `openid` scope"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::userinfo::get",
    level = "debug",
    skip(state, headers)
)]
pub(super) async fn userinfo_get(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
) -> Response {
    userinfo_impl(&state, &domain_id, &headers, peer_addr, &correlation_id.0).await
}

/// OIDC UserInfo endpoint (`POST`, OIDC Core §5.3.1).
#[utoipa::path(
    post,
    path = "/{domain_id}/userinfo",
    operation_id = "/oauth2:userinfo:post",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "UserInfo claims", body = serde_json::Value),
        (status = UNAUTHORIZED, description = "Missing or invalid access token"),
        (status = FORBIDDEN, description = "Access token lacks the `openid` scope"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::userinfo::post",
    level = "debug",
    skip(state, headers)
)]
pub(super) async fn userinfo_post(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
) -> Response {
    userinfo_impl(&state, &domain_id, &headers, peer_addr, &correlation_id.0).await
}

async fn userinfo_impl(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    correlation_id: &str,
) -> Response {
    match userinfo_inner(state, domain_id, headers, peer_addr, correlation_id).await {
        Ok(claims) => no_store((StatusCode::OK, Json(claims)).into_response()),
        Err(err) => {
            // Every rejected bearer presentation leaves a record, not just
            // the accepted ones: without this, a burst of forged, revoked or
            // foreign tokens would be invisible in the audit trail. The
            // subject of a rejected token is unauthenticated, so the
            // initiator is unknown (its claims are request-supplied text and
            // must not be recorded as an identity, per the security model);
            // the target is the domain whose userinfo endpoint was probed,
            // since the `aud` client of an unverified token cannot be
            // trusted.
            let (outcome, reason) = err.audit_outcome();
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                correlation_id,
                "read",
                build_initiator_unknown(),
                domain_id,
                outcome,
                Some(reason),
            );
            err.into_response()
        }
    }
}

async fn userinfo_inner(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    correlation_id: &str,
) -> Result<Map<String, Value>, UserinfoError> {
    // The bearer token is itself a secret: throttle per source IP before
    // doing any lookup.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return Err(UserinfoError::TooManyRequests(retry_after.as_secs().max(1)));
    }
    ensure_trusted_issuer(state)
        .await
        .map_err(UserinfoError::Unavailable)?;

    let token = bearer_token(headers).ok_or(UserinfoError::MissingToken)?;

    let key_provider = state.provider.get_oauth2_key_provider();
    let jwks = match key_provider.jwks(state, domain_id).await {
        Ok(jwks) => jwks,
        // No signing keys: no token of this domain can exist.
        Err(Oauth2KeyProviderError::NotFound(_)) => return Err(UserinfoError::InvalidToken),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 userinfo: jwks lookup failed");
            return Err(UserinfoError::Internal);
        }
    };
    let revoked_jtis = key_provider
        .revoked_jtis(state, domain_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 userinfo: revocation list lookup failed");
            UserinfoError::Internal
        })?;

    let signing_algorithm = match state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .signing_algorithm
    {
        openstack_keystone_config::SigningAlgorithm::Es256 => SigningAlgorithm::Es256,
        openstack_keystone_config::SigningAlgorithm::Rs256 => SigningAlgorithm::Rs256,
    };
    let issuer = format!("{}/v4/oauth2/{domain_id}", base_url(state, headers).await);
    let claims =
        verify_oidc_access_token(token, &jwks, signing_algorithm, &[issuer], &revoked_jtis)
            .map_err(|e| match e {
                TokenVerificationError::InsufficientScope(_) => UserinfoError::InsufficientScope,
                e => {
                    tracing::debug!(error = %e, "oauth2 userinfo: token rejected");
                    UserinfoError::InvalidToken
                }
            })?;

    // `aud` is the relying party: it must still be a registered, enabled
    // client of this domain.
    let exec = ExecutionContext::internal(state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &claims.aud)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 userinfo: client lookup failed");
            UserinfoError::Internal
        })?
        .filter(|c| c.domain_id == domain_id && c.enabled && c.deleted_at.is_none())
        .ok_or(UserinfoError::InvalidToken)?;

    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &claims.sub)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 userinfo: user lookup failed");
            UserinfoError::Internal
        })?
        .filter(|u| u.enabled)
        .ok_or(UserinfoError::InvalidToken)?;

    let granted_scope: Vec<String> = claims.scope.split_whitespace().map(str::to_owned).collect();
    let extra = openstack_keystone_core::oauth2_client::id_token::build_extra_claims(
        &client,
        &user,
        &granted_scope,
        &TemplateScope::default(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "oauth2 userinfo: claims construction failed");
        UserinfoError::Internal
    })?;

    let mut body: Map<String, Value> = extra.into_iter().collect();
    // `sub` is authoritative and can never be overridden.
    body.insert("sub".to_string(), Value::String(claims.sub.clone()));

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "read",
        build_initiator_from_user_id(&user.id, &user.domain_id),
        &client.client_id,
        Outcome::Success,
        Some(OutcomeReason::literal("UserInfo")),
    );
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use serde_json::json;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair, to_encoding_key,
    };

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        json_body, public_authz_code_client, refresh_identity_mock, refresh_user,
    };
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::{Provider, ProviderBuilder};

    const ISSUER: &str = "http://localhost/v4/oauth2/domain-1";

    /// Token mint knobs; defaults produce a valid `openid profile email`
    /// access token for `client-1`.
    struct TokenSpec {
        scope: &'static str,
        exp_offset: i64,
        token_use: &'static str,
        sub: &'static str,
    }

    impl Default for TokenSpec {
        fn default() -> Self {
            Self {
                scope: "openid profile email",
                exp_offset: 900,
                token_use: "access",
                sub: "user-1",
            }
        }
    }

    /// Returns `(token, key mock)`; `revoked` is what `revoked_jtis()`
    /// serves.
    fn signed_token(spec: TokenSpec, revoked: HashSet<String>) -> (String, MockOauth2KeyProvider) {
        let now = chrono::Utc::now().timestamp();
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(material.kid.clone());
        let token = jsonwebtoken::encode(
            &header,
            &json!({
                "iss": ISSUER, "sub": spec.sub, "aud": "client-1",
                "exp": now + spec.exp_offset, "iat": now, "nbf": now,
                "jti": "jti-1", "scope": spec.scope, "token_use": spec.token_use,
            }),
            &to_encoding_key(&material).unwrap(),
        )
        .unwrap();
        let jwks = openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&ActiveKeys {
            primary: material,
            previous: None,
        })
        .unwrap();
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(move |_, _| Ok(jwks.clone()));
        mock.expect_revoked_jtis()
            .returning(move |_, _| Ok(revoked.clone()));
        (token, mock)
    }

    async fn client_mock() -> MockOauth2ClientProvider {
        let client = public_authz_code_client().await;
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        mock
    }

    fn user_mock(enabled: bool) -> crate::identity::MockIdentityProvider {
        let mut user = refresh_user(enabled, "domain-1");
        user.extra
            .insert("email".to_string(), json!("u@example.com"));
        refresh_identity_mock(Some(user))
    }

    /// Like `user_mock`, but with a real (UUID-shaped) id, since the audit
    /// sanitizer reduces non-UUID ids to `"unknown"`.
    fn user_mock_with_id(id: &str, enabled: bool) -> crate::identity::MockIdentityProvider {
        let user = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id(id)
            .domain_id("domain-1")
            .enabled(enabled)
            .name("user-1")
            .build()
            .unwrap();
        refresh_identity_mock(Some(user))
    }

    fn request(method: Method, authorization: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/domain-1/userinfo").method(method);
        if let Some(authorization) = authorization {
            builder = builder.header(header::AUTHORIZATION, authorization);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn call(
        provider: ProviderBuilder,
        method: Method,
        authorization: Option<&str>,
    ) -> axum::response::Response {
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        api.as_service()
            .oneshot(request(method, authorization))
            .await
            .unwrap()
    }

    fn www_authenticate(response: &axum::response::Response) -> &str {
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
    }

    async fn provider_for(
        token_spec: TokenSpec,
        revoked: HashSet<String>,
        user_enabled: bool,
    ) -> (String, ProviderBuilder) {
        let (token, key_mock) = signed_token(token_spec, revoked);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_identity(user_mock(user_enabled))
            .mock_oauth2_key(key_mock);
        (token, provider)
    }

    #[tokio::test]
    async fn test_get_and_post_return_scoped_claims() {
        for method in [Method::GET, Method::POST] {
            let (token, provider) = provider_for(TokenSpec::default(), HashSet::new(), true).await;
            let response = call(provider, method, Some(&format!("Bearer {token}"))).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["pragma"], "no-cache");
            let body = json_body(response).await;
            assert_eq!(body["sub"], "user-1");
            assert_eq!(body["preferred_username"], "user-1");
            assert_eq!(body["email"], "u@example.com");
            assert_eq!(body["email_verified"], false);
        }
    }

    #[tokio::test]
    async fn test_scope_gates_profile_and_email() {
        let spec = TokenSpec {
            scope: "openid",
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body, json!({"sub": "user-1"}));

        let spec = TokenSpec {
            scope: "openid email",
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        let body = json_body(response).await;
        assert_eq!(body["email"], "u@example.com");
        assert!(body.get("name").is_none());
    }

    #[tokio::test]
    async fn test_claims_template_applied() {
        let mut client = public_authz_code_client().await;
        client.claims_template = std::collections::HashMap::from([(
            "tenant".to_string(),
            "${user.domain_id}".to_string(),
        )]);
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let (token, key_mock) = signed_token(TokenSpec::default(), HashSet::new());
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_identity(user_mock(true))
            .mock_oauth2_key(key_mock);
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["tenant"], "domain-1");
    }

    #[tokio::test]
    async fn test_missing_token_is_401_bare_bearer() {
        let provider = Provider::mocked_builder();
        let response = call(provider, Method::GET, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate(&response), "Bearer");
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn test_invalid_token_is_401_invalid_token() {
        let (_, key_mock) = signed_token(TokenSpec::default(), HashSet::new());
        let provider = Provider::mocked_builder().mock_oauth2_key(key_mock);
        let response = call(provider, Method::GET, Some("Bearer not.a.jwt")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&response),
            "Bearer error=\"invalid_token\""
        );
        assert_eq!(json_body(response).await["error"], "invalid_token");
    }

    #[tokio::test]
    async fn test_non_bearer_scheme_is_401() {
        let provider = Provider::mocked_builder();
        let response = call(provider, Method::GET, Some("Basic Zm9vOmJhcg==")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate(&response), "Bearer");
    }

    #[tokio::test]
    async fn test_expired_token_is_401() {
        let spec = TokenSpec {
            exp_offset: -7200,
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&response),
            "Bearer error=\"invalid_token\""
        );
    }

    #[tokio::test]
    async fn test_revoked_jti_is_401() {
        let (token, provider) = provider_for(
            TokenSpec::default(),
            HashSet::from(["jti-1".to_string()]),
            true,
        )
        .await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&response),
            "Bearer error=\"invalid_token\""
        );
    }

    #[tokio::test]
    async fn test_id_token_is_rejected() {
        let spec = TokenSpec {
            token_use: "id",
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_openid_scope_is_403() {
        let spec = TokenSpec {
            scope: "profile email",
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(www_authenticate(&response).contains("insufficient_scope"));
    }

    #[tokio::test]
    async fn test_disabled_user_is_401() {
        let (token, provider) = provider_for(TokenSpec::default(), HashSet::new(), false).await;
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&response),
            "Bearer error=\"invalid_token\""
        );
    }

    #[tokio::test]
    async fn test_disabled_client_is_401() {
        let mut client = public_authz_code_client().await;
        client.enabled = false;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let (token, key_mock) = signed_token(TokenSpec::default(), HashSet::new());
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_identity(user_mock(true))
            .mock_oauth2_key(key_mock);
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_unknown_user_is_401() {
        let (token, key_mock) = signed_token(TokenSpec::default(), HashSet::new());
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_identity(refresh_identity_mock(None))
            .mock_oauth2_key(key_mock);
        let response = call(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Like `call`, but with a live audit dispatcher so the emitted records
    /// can be asserted.
    async fn call_with_audit(
        provider: ProviderBuilder,
        method: Method,
        authorization: Option<&str>,
    ) -> (axum::response::Response, cadf::AuditChannelReceivers) {
        let mut config = openstack_keystone_config::Config::default();
        config.oauth2.allow_host_header_issuer = true;
        let (state, receivers) = openstack_keystone_core::api::tests::get_mocked_state_with_audit(
            provider, true, config,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(method, authorization))
            .await
            .unwrap();
        (response, receivers)
    }

    #[tokio::test]
    async fn test_rejected_token_is_audited() {
        let (_, key_mock) = signed_token(TokenSpec::default(), HashSet::new());
        let provider = Provider::mocked_builder().mock_oauth2_key(key_mock);
        let (response, mut receivers) =
            call_with_audit(provider, Method::GET, Some("Bearer not.a.jwt")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let event = receivers
            .perimeter
            .try_recv()
            .expect("a rejected token must leave an audit record");
        assert_eq!(event.payload().action(), "read");
        assert_eq!(event.payload().outcome(), cadf::Outcome::Failure);
        assert_eq!(event.payload().initiator().id(), "unknown");
        assert_eq!(event.payload().target().id(), "domain-1");
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["reason"]["reasonCode"], "InvalidToken");
        assert!(receivers.perimeter.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_missing_token_is_audited() {
        let provider = Provider::mocked_builder();
        let (response, mut receivers) = call_with_audit(provider, Method::GET, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let event = receivers
            .perimeter
            .try_recv()
            .expect("a missing token must leave an audit record");
        assert_eq!(event.payload().outcome(), cadf::Outcome::Failure);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["reason"]["reasonCode"], "MissingToken");
    }

    #[tokio::test]
    async fn test_insufficient_scope_is_audited() {
        let spec = TokenSpec {
            scope: "profile email",
            ..Default::default()
        };
        let (token, provider) = provider_for(spec, HashSet::new(), true).await;
        let (response, mut receivers) =
            call_with_audit(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let event = receivers
            .perimeter
            .try_recv()
            .expect("an insufficient-scope token must leave an audit record");
        assert_eq!(event.payload().outcome(), cadf::Outcome::Failure);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["reason"]["reasonCode"], "InsufficientScope");
    }

    #[tokio::test]
    async fn test_successful_read_is_audited() {
        const USER_ID: &str = "0123456789abcdef0123456789abcdef";
        let spec = TokenSpec {
            sub: USER_ID,
            ..Default::default()
        };
        let (token, key_mock) = signed_token(spec, HashSet::new());
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_identity(user_mock_with_id(USER_ID, true))
            .mock_oauth2_key(key_mock);
        let (response, mut receivers) =
            call_with_audit(provider, Method::GET, Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let event = receivers
            .perimeter
            .try_recv()
            .expect("a successful read must leave an audit record");
        assert_eq!(event.payload().action(), "read");
        assert_eq!(event.payload().outcome(), cadf::Outcome::Success);
        assert_eq!(event.payload().initiator().id(), USER_ID);
        assert_eq!(event.payload().target().id(), "client-1");
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["reason"]["reasonCode"], "UserInfo");
        assert!(receivers.perimeter.try_recv().is_err());
    }
}
