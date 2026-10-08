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
//! `POST /v4/oauth2/{domain_id}/introspect`: RFC 7662 token introspection
//! (ADR 0026 §11, §13).
//!
//! The back-channel a service uses when it cannot accept the stateless
//! revocation window of access tokens: unlike offline verification it sees
//! the domain's JTI revocation list and the refresh-token store as they are
//! *now*.
//!
//! **Who may introspect.** Only an authenticated *confidential* client of the
//! same domain (client secret verified, exactly as on `/token`). Public
//! clients have no secret to prove and are rejected with `invalid_client`.
//! No dedicated capability flag is required: the token is not scoped to the
//! caller (a resource server introspects tokens minted for *other* clients),
//! and every domain-bound check below is what keeps the endpoint from
//! crossing domains.
//!
//! **No oracle.** Every unknown, malformed, expired, revoked, spent or
//! foreign-domain token answers `200 {"active": false}`; the response never
//! reveals why. Only an active token's claims are returned. For OpenStack
//! access tokens that includes the `openstack_context` (and
//! `delegation_context`) the caller will act on, which is safe to disclose
//! because the token's signature already binds it to the caller's domain.
//!
//! * **Access token**: signature, algorithm, `iss`, `exp`/`nbf`, `token_use`
//!   and the `jti` revocation list.
//! * **Refresh token**: `active = record exists && same domain && !spent &&
//!   !revoked && now <= expires_at && now < family_expires_at` (a
//!   `family_expires_at` of `0` is an uncapped legacy family). Parity with
//!   `redeem_refresh_token`, which rejects only `expires_at < now`: a token is
//!   usable through its expiry second, so introspection agrees.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use governor::clock::Clock as _;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use cadf::{Initiator, sanitize::sanitize_audit_id};
use cadf::{Outcome, OutcomeReason};
use openstack_keystone_core::oauth2_client::{
    IntrospectedAccessToken, verify_introspectable_access_token,
};
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use crate::api::common::PeerAddr;
use crate::api::v4::oauth2::well_known::{base_url, ensure_trusted_issuer};
use crate::audit::{CorrelationId, emit_oauth2_session_event};
use crate::keystone::ServiceState;

use super::html::no_store;
use super::token::{Oauth2TokenError, authenticate_client, client_credentials_from_parts};

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(super) struct IntrospectForm {
    /// The token to introspect (refresh token or access token).
    #[serde(default)]
    token: Option<String>,
    /// `refresh_token` or `access_token`; only a lookup-order hint
    /// (RFC 7662 §2.1). Unknown values are ignored.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// Client credentials in the body (`client_secret_post`); HTTP Basic
    /// takes precedence.
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// The inactive answer, identical for every failure cause.
fn inactive() -> Value {
    json!({"active": false})
}

/// RFC 7662 token introspection endpoint.
#[utoipa::path(
    post,
    path = "/{domain_id}/introspect",
    operation_id = "/oauth2:introspect",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Introspection response; `active` is false for any token that is not currently valid", body = Object),
        (status = BAD_REQUEST, description = "Missing `token` parameter"),
        (status = UNAUTHORIZED, description = "Invalid client credentials or public client"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::introspect",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn introspect(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    Form(form): Form<IntrospectForm>,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_parts(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    ) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(token) = form.token.as_deref().filter(|t| !t.is_empty()) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: token",
        ));
    };

    // Both limiters run before any lookup: the presented token is itself a
    // bearer secret, and the endpoint is a validity oracle for whoever holds
    // client credentials, so throttle per source IP as well as per client.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
    }
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    // Access-token verification pins `iss` to the issuer derived from
    // `base_url`; without a trusted issuer every token would be reported
    // inactive.
    ensure_trusted_issuer(&state).await?;

    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();
    let client = authenticate_client(
        &state,
        &oauth2_cfg,
        &domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;
    // Confidential clients only: a public client has no secret to prove its
    // identity, so anyone could introspect with its (public) client_id.
    if client.client_secret_hash.is_none() {
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    let ctx = IntrospectContext {
        state: &state,
        headers: &headers,
        domain_id: &domain_id,
        signing_algorithm: match oauth2_cfg.signing_algorithm {
            openstack_keystone_config::SigningAlgorithm::Es256 => SigningAlgorithm::Es256,
            openstack_keystone_config::SigningAlgorithm::Rs256 => SigningAlgorithm::Rs256,
        },
    };

    // The hint only picks which lookup runs first; a wrong hint must still
    // work (RFC 7662 §2.1).
    let access_first = form.token_type_hint.as_deref() == Some("access_token");
    let mut answer = if access_first {
        ctx.introspect_access_token(token).await?
    } else {
        ctx.introspect_refresh_token(token).await?
    };
    if answer.is_none() {
        answer = if access_first {
            ctx.introspect_refresh_token(token).await?
        } else {
            ctx.introspect_access_token(token).await?
        };
    }

    let active = answer.is_some();
    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "read",
        Initiator::new(
            sanitize_audit_id(&client_id),
            None,
            Some(sanitize_audit_id(&domain_id)),
            None,
        )
        .with_address(peer_addr.map(|a| a.ip().to_string())),
        &client_id,
        Outcome::Success,
        Some(OutcomeReason::literal(if active {
            "Active"
        } else {
            "Inactive"
        })),
    );

    Ok(no_store(
        (StatusCode::OK, Json(answer.unwrap_or_else(inactive))).into_response(),
    ))
}

struct IntrospectContext<'a> {
    state: &'a ServiceState,
    headers: &'a HeaderMap,
    domain_id: &'a str,
    signing_algorithm: SigningAlgorithm,
}

impl IntrospectContext<'_> {
    /// `Some(response)` if `token` is an active refresh token of this
    /// domain, `None` for anything else (unknown, spent, revoked, expired,
    /// foreign domain).
    async fn introspect_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<Value>, Oauth2TokenError> {
        let record = self
            .state
            .provider
            .get_oauth2_session_provider()
            .peek_refresh_token(self.state, token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 introspect: refresh token lookup failed");
                Oauth2TokenError::internal("token introspection failed")
            })?;
        let Some(record) = record else {
            return Ok(None);
        };

        let now = chrono::Utc::now().timestamp();
        let family_alive = record.family_expires_at == 0 || now < record.family_expires_at;
        if record.domain_id != self.domain_id
            || record.spent_at.is_some()
            || record.revoked_at.is_some()
            || record.expires_at < now
            || !family_alive
        {
            return Ok(None);
        }

        // The family cap bounds the token's usable lifetime.
        let exp = if record.family_expires_at == 0 {
            record.expires_at
        } else {
            record.expires_at.min(record.family_expires_at)
        };
        Ok(Some(json!({
            "active": true,
            "client_id": record.client_id,
            "sub": record.user_id,
            "scope": record.scope.join(" "),
            "exp": exp,
            "iat": record.issued_at,
            "token_use": "refresh",
        })))
    }

    /// `Some(response)` if `token` is a currently valid access token of
    /// this domain, `None` for anything else.
    async fn introspect_access_token(
        &self,
        token: &str,
    ) -> Result<Option<Value>, Oauth2TokenError> {
        let key_provider = self.state.provider.get_oauth2_key_provider();
        let jwks = match key_provider.jwks(self.state, self.domain_id).await {
            Ok(jwks) => jwks,
            // No signing keys: no token of this domain can exist.
            Err(Oauth2KeyProviderError::NotFound(_)) => return Ok(None),
            Err(e) => {
                tracing::warn!(error = %e, "oauth2 introspect: jwks lookup failed");
                return Err(Oauth2TokenError::internal("token introspection failed"));
            }
        };
        let revoked_jtis = key_provider
            .revoked_jtis(self.state, self.domain_id)
            .await
            .map_err(|e| {
                // Failing open here would report a revoked token as active.
                tracing::warn!(error = %e, "oauth2 introspect: revocation list lookup failed");
                Oauth2TokenError::internal("token introspection failed")
            })?;
        let base = base_url(self.state, self.headers).await;
        let issuer = format!("{base}/v4/oauth2/{}", self.domain_id);

        let verified = match verify_introspectable_access_token(
            token,
            &jwks,
            self.signing_algorithm,
            &[issuer],
            self.domain_id,
            &revoked_jtis,
        ) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let mut out = Map::new();
        out.insert("active".into(), json!(true));
        out.insert("token_type".into(), json!("Bearer"));
        match verified {
            IntrospectedAccessToken::Oidc(c) => {
                out.insert("scope".into(), json!(c.scope));
                // The OIDC access token's audience is the owning client.
                out.insert("client_id".into(), json!(c.aud));
                out.insert("sub".into(), json!(c.sub));
                out.insert("exp".into(), json!(c.exp));
                out.insert("iat".into(), json!(c.iat));
                out.insert("nbf".into(), json!(c.nbf));
                out.insert("aud".into(), json!(c.aud));
                out.insert("iss".into(), json!(c.iss));
                out.insert("jti".into(), json!(c.jti));
                out.insert("token_use".into(), json!(c.token_use));
            }
            IntrospectedAccessToken::OpenStack(c) => {
                out.insert("scope".into(), json!("openstack:api"));
                out.insert("client_id".into(), json!(c.client_id));
                out.insert("sub".into(), json!(c.sub));
                out.insert("exp".into(), json!(c.exp));
                out.insert("iat".into(), json!(c.iat));
                out.insert("nbf".into(), json!(c.nbf));
                out.insert("aud".into(), json!(c.aud));
                out.insert("iss".into(), json!(c.iss));
                out.insert("jti".into(), json!(c.jti));
                out.insert("token_use".into(), json!(c.token_use));
                match (
                    serde_json::to_value(&c.openstack_context),
                    serde_json::to_value(&c.delegation_context),
                ) {
                    (Ok(context), Ok(delegation)) => {
                        out.insert("openstack_context".into(), context);
                        out.insert("delegation_context".into(), delegation);
                    }
                    _ => {
                        tracing::warn!("oauth2 introspect: claim serialization failed");
                        return Err(Oauth2TokenError::internal("token introspection failed"));
                    }
                }
            }
        }
        Ok(Some(Value::Object(out)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
    use openstack_keystone_core_types::oauth2_session::RefreshToken;
    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair, to_encoding_key,
    };

    use crate::api::tests::get_mocked_state_with_config;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::confidential_client;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::{Provider, ProviderBuilder};

    const ISSUER: &str = "http://localhost/v4/oauth2/domain-1";

    fn introspect_request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/introspect")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn form(token: &str) -> String {
        format!("token={token}&client_id=client-1&client_secret=s3cr3t")
    }

    async fn client_mock() -> MockOauth2ClientProvider {
        let client = confidential_client().await;
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        mock
    }

    fn record(modify: impl FnOnce(&mut RefreshToken)) -> RefreshToken {
        let now = chrono::Utc::now().timestamp();
        let mut record = RefreshToken {
            token_id: "irrelevant".to_string(),
            family_id: "family-1".to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: "client-9".to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string(), "profile".to_string()],
            issued_at: now - 10,
            spent_at: None,
            revoked_at: None,
            revocation_reason: None,
            expires_at: now + 3600,
            family_expires_at: now + 7200,
            amr: vec![],
        };
        modify(&mut record);
        record
    }

    fn session_with(record: Option<RefreshToken>) -> MockOauth2SessionProvider {
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(move |_, _| Ok(record.clone()));
        session
    }

    fn no_keys_mock() -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks()
            .returning(|_, _| Err(Oauth2KeyProviderError::NotFound("domain-1".to_string())));
        mock
    }

    /// Sign `claims` and return `(token, key mock)` serving the matching
    /// JWKS and the given revoked `jti`s.
    fn signed(claims: Value, revoked: &[&str]) -> (String, MockOauth2KeyProvider) {
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(material.kid.clone());
        let token =
            jsonwebtoken::encode(&header, &claims, &to_encoding_key(&material).unwrap()).unwrap();
        let jwks = openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&ActiveKeys {
            primary: material,
            previous: None,
        })
        .unwrap();
        let revoked: HashSet<String> = revoked.iter().map(|s| s.to_string()).collect();
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks().returning(move |_, _| Ok(jwks.clone()));
        mock.expect_revoked_jtis()
            .returning(move |_, _| Ok(revoked.clone()));
        (token, mock)
    }

    fn oidc_claims(exp_offset: i64) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": ISSUER, "sub": "user-1", "aud": "client-9", "exp": now + exp_offset,
            "iat": now, "nbf": now, "jti": "jti-1", "scope": "openid",
            "token_use": "access",
        })
    }

    fn openstack_claims() -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": ISSUER, "sub": "shadow", "aud": "openstack-apis:domain-1",
            "client_id": "client-9", "exp": now + 900, "iat": now, "nbf": now,
            "jti": "jti-os", "keystone_ruleset_version": 1,
            "amr": ["client_credentials"], "token_use": "access",
            "delegation_context": {"auth_method": "plain"}, "user_id": "shadow", "user_name": "client-9",
            "user_domain_id": null, "scope_type": "unscoped", "roles": ["member"],
        })
    }

    fn dev_config() -> Config {
        Config {
            oauth2: openstack_keystone_config::Oauth2Provider {
                allow_host_header_issuer: true,
                ..Default::default()
            },
            ..Config::default()
        }
    }

    async fn call(provider: ProviderBuilder, body: &str) -> (StatusCode, Value) {
        call_with_config(provider, body, dev_config()).await
    }

    async fn call_with_config(
        provider: ProviderBuilder,
        body: &str,
        config: Config,
    ) -> (StatusCode, Value) {
        let state = get_mocked_state_with_config(provider, true, None, config).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(introspect_request(body))
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn assert_inactive(provider: ProviderBuilder, token: &str) {
        let (status, body) = call(provider, &form(token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"active": false}));
    }

    #[tokio::test]
    async fn test_active_refresh_token() {
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(Some(record(|_| {}))))
            .mock_oauth2_key(no_keys_mock());
        let (status, body) = call(provider, &form("rt")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true);
        assert_eq!(body["client_id"], "client-9");
        assert_eq!(body["sub"], "user-1");
        assert_eq!(body["scope"], "openid profile");
        assert!(body["exp"].is_i64());
    }

    #[tokio::test]
    async fn test_refresh_token_inactive_branches() {
        let now = chrono::Utc::now().timestamp();
        let cases: Vec<(&str, Option<RefreshToken>)> = vec![
            ("unknown", None),
            ("spent", Some(record(|r| r.spent_at = Some(now)))),
            ("revoked", Some(record(|r| r.revoked_at = Some(now)))),
            ("expired", Some(record(|r| r.expires_at = now - 1))),
            (
                "family expired",
                Some(record(|r| r.family_expires_at = now - 1)),
            ),
            (
                "foreign domain",
                Some(record(|r| r.domain_id = "domain-2".to_string())),
            ),
        ];
        for (name, rec) in cases {
            let provider = Provider::mocked_builder()
                .mock_oauth2_client(client_mock().await)
                .mock_oauth2_session(session_with(rec))
                .mock_oauth2_key(no_keys_mock());
            let (status, body) = call(provider, &form("rt")).await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert_eq!(body, json!({"active": false}), "{name}");
        }
    }

    #[tokio::test]
    async fn test_uncapped_legacy_family_is_active() {
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(Some(record(|r| r.family_expires_at = 0))))
            .mock_oauth2_key(no_keys_mock());
        let (_, body) = call(provider, &form("rt")).await;
        assert_eq!(body["active"], true);
    }

    #[tokio::test]
    async fn test_refresh_token_at_expiry_second_is_active() {
        // Parity with `redeem_refresh_token`, which rejects only
        // `expires_at < now`: a token whose expiry second is still current
        // can still be redeemed, so introspection must report it active.
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(Some(record(|r| {
                r.expires_at = chrono::Utc::now().timestamp() + 1;
            }))))
            .mock_oauth2_key(no_keys_mock());
        let (_, body) = call(provider, &form("rt")).await;
        assert_eq!(body["active"], true);
    }

    #[tokio::test]
    async fn test_active_oidc_access_token() {
        let (token, key_mock) = signed(oidc_claims(900), &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        let (status, body) = call(
            provider,
            &format!("{}&token_type_hint=access_token", form(&token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true);
        assert_eq!(body["client_id"], "client-9");
        assert_eq!(body["sub"], "user-1");
        assert_eq!(body["scope"], "openid");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["jti"], "jti-1");
        assert_eq!(body["iss"], ISSUER);
        assert!(body.get("openstack_context").is_none());
    }

    #[tokio::test]
    async fn test_active_openstack_access_token_has_context() {
        let (token, key_mock) = signed(openstack_claims(), &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        let (status, body) = call(provider, &form(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true);
        assert_eq!(body["client_id"], "client-9");
        assert_eq!(body["scope"], "openstack:api");
        assert_eq!(body["openstack_context"]["roles"], json!(["member"]));
        assert_eq!(body["openstack_context"]["user_id"], "shadow");
        assert_eq!(body["delegation_context"]["auth_method"], "plain");
    }

    #[tokio::test]
    async fn test_revoked_jti_is_inactive() {
        let (token, key_mock) = signed(oidc_claims(900), &["jti-1"]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        assert_inactive(provider, &token).await;
    }

    #[tokio::test]
    async fn test_expired_access_token_is_inactive() {
        let (token, key_mock) = signed(oidc_claims(-600), &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        assert_inactive(provider, &token).await;
    }

    #[tokio::test]
    async fn test_foreign_domain_access_token_is_inactive() {
        // Signed by another domain's key: the domain's JWKS cannot verify it.
        let (token, _other_domain_keys) = signed(oidc_claims(900), &[]);
        let (_, own_keys) = signed(oidc_claims(900), &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(own_keys);
        assert_inactive(provider, &token).await;
    }

    #[tokio::test]
    async fn test_foreign_issuer_is_inactive() {
        let mut claims = oidc_claims(900);
        claims["iss"] = json!("http://localhost/v4/oauth2/domain-2");
        let (token, key_mock) = signed(claims, &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        assert_inactive(provider, &token).await;
    }

    #[tokio::test]
    async fn test_id_token_is_inactive() {
        let mut claims = oidc_claims(900);
        claims["token_use"] = json!("id");
        let (token, key_mock) = signed(claims, &[]);
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        assert_inactive(provider, &token).await;
    }

    #[tokio::test]
    async fn test_unknown_token_is_inactive_without_keys() {
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(no_keys_mock());
        assert_inactive(provider, "garbage").await;
    }

    #[tokio::test]
    async fn test_revocation_list_error_is_500_not_active() {
        let mut key_mock = MockOauth2KeyProvider::default();
        key_mock.expect_jwks().returning(|_, _| {
            Ok(
                openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&ActiveKeys {
                    primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                    previous: None,
                })
                .unwrap(),
            )
        });
        key_mock
            .expect_revoked_jtis()
            .returning(|_, _| Err(Oauth2KeyProviderError::RaftNotAvailable));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session_with(None))
            .mock_oauth2_key(key_mock);
        let (status, _) = call(provider, &form("tok")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_public_client_is_401() {
        let mut client = confidential_client().await;
        client.client_secret_hash = None;
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);
        let (status, _) = call(provider, "token=x&client_id=client-1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bad_client_secret_is_401() {
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock().await);
        let (status, _) = call(provider, "token=x&client_id=client-1&client_secret=wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_token_is_400() {
        let provider = Provider::mocked_builder();
        let (status, _) = call(provider, "client_id=client-1&client_secret=s3cr3t").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_unset_public_endpoint_is_503() {
        let provider = Provider::mocked_builder().mock_oauth2_key(no_keys_mock());
        let (status, _) = call_with_config(provider, &form("a"), Config::default()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_rate_limited_by_ip_before_lookup() {
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..dev_config()
        };
        let mut client = MockOauth2ClientProvider::default();
        let resource = confidential_client().await;
        // Only the first (admitted) request may reach client lookup.
        client
            .expect_get_by_client_id()
            .times(1)
            .returning(move |_, _| Ok(Some(resource.clone())));
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .times(1)
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock())
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
        let addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut first = introspect_request(&form("a"));
        first.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            api.as_service().oneshot(first).await.unwrap().status(),
            StatusCode::OK
        );
        let mut second = introspect_request(&form("b"));
        second.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            api.as_service().oneshot(second).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
