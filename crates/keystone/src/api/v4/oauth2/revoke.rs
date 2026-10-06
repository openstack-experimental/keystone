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
//! `POST /v4/oauth2/{domain_id}/revoke`: RFC 7009 token revocation (ADR 0026).
//!
//! Lets a relying party end a session it holds a token for. Client
//! authentication, rate limiting and error format are shared with `/token`.
//!
//! Per RFC 7009 §2.2 the endpoint answers `200` with an empty body for every
//! authenticated request that is well-formed, including unknown, expired,
//! already-revoked and *foreign* tokens, so it is never an oracle for token
//! validity or ownership. Revocation only happens when the token verifiably
//! belongs to the authenticated client in this domain:
//!
//! * **Refresh token**: the whole rotation family is tombstoned (`rp_revoke`).
//! * **Access token**: its `jti` is added to the domain's JTI revocation list
//!   (`/jwks/revocation`) until the token's own `exp`, and its refresh family
//!   (`sid` claim) is revoked. Tokens without a `jti` (ID tokens) are ignored.
//!
//! OIDC access tokens carry a private `sid` claim (the refresh family id), so
//! revoking such an access token also ends its refresh family. The reverse
//! does not hold: revoking a refresh token does not revoke access tokens
//! already minted from its family (the list is keyed by `jti`, which the
//! server does not track per family); they expire on their own (short
//! lifetime) unless revoked individually.

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use governor::clock::Clock as _;
use serde::Deserialize;

use cadf::{Initiator, sanitize::sanitize_audit_id};
use cadf::{Outcome, OutcomeReason};
use openstack_keystone_core::oauth2_client::verify_revocable_access_token;
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use crate::api::common::PeerAddr;
use crate::api::v4::oauth2::well_known::base_url;
use crate::audit::{
    CorrelationId, emit_oauth2_refresh_family_revoked_event, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

use super::html::no_store;
use super::token::{Oauth2TokenError, authenticate_client, client_credentials_from_parts};

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(super) struct RevokeForm {
    /// The token to revoke (refresh token or access token).
    #[serde(default)]
    token: Option<String>,
    /// `refresh_token` or `access_token`; only a lookup-order hint
    /// (RFC 7009 §2.1). Unknown values are ignored.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// Client credentials in the body (`client_secret_post`); HTTP Basic
    /// takes precedence.
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Who performed the revocation: the authenticated client.
fn client_initiator(
    client_id: &str,
    domain_id: &str,
    peer_addr: Option<std::net::SocketAddr>,
) -> Initiator {
    Initiator::new(
        sanitize_audit_id(client_id),
        None,
        Some(sanitize_audit_id(domain_id)),
        None,
    )
    .with_address(peer_addr.map(|a| a.ip().to_string()))
}

/// RFC 7009 token revocation endpoint.
#[utoipa::path(
    post,
    path = "/{domain_id}/revoke",
    operation_id = "/oauth2:revoke",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Token revoked, or nothing to revoke"),
        (status = BAD_REQUEST, description = "Missing `token` parameter"),
        (status = UNAUTHORIZED, description = "Invalid client credentials"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::revoke",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn revoke(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    Form(form): Form<RevokeForm>,
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
    // bearer secret, so (as for the refresh grant) throttle per source IP
    // as well as per client.
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

    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();
    authenticate_client(
        &state,
        &oauth2_cfg,
        &domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;

    let ctx = RevokeContext {
        state: &state,
        headers: &headers,
        domain_id: &domain_id,
        client_id: &client_id,
        correlation_id: &correlation_id.0,
        peer_addr,
        signing_algorithm: match oauth2_cfg.signing_algorithm {
            openstack_keystone_config::SigningAlgorithm::Es256 => SigningAlgorithm::Es256,
            openstack_keystone_config::SigningAlgorithm::Rs256 => SigningAlgorithm::Rs256,
        },
    };

    // The hint only picks which lookup runs first; a wrong hint must still
    // work (RFC 7009 §2.1).
    let access_first = form.token_type_hint.as_deref() == Some("access_token");
    let mut handled = if access_first {
        ctx.revoke_access_token(token).await?
    } else {
        ctx.revoke_refresh_token(token).await?
    };
    if !handled {
        handled = if access_first {
            ctx.revoke_refresh_token(token).await?
        } else {
            ctx.revoke_access_token(token).await?
        };
    }
    if !handled {
        tracing::debug!("oauth2 revoke: token not found or not revocable");
    }

    Ok(no_store(StatusCode::OK.into_response()))
}

struct RevokeContext<'a> {
    state: &'a ServiceState,
    headers: &'a HeaderMap,
    domain_id: &'a str,
    client_id: &'a str,
    correlation_id: &'a str,
    peer_addr: Option<std::net::SocketAddr>,
    signing_algorithm: SigningAlgorithm,
}

impl RevokeContext<'_> {
    fn audit(&self, outcome: Outcome, reason: OutcomeReason) {
        emit_oauth2_session_event(
            &self.state.audit_dispatcher,
            self.correlation_id,
            "revoke",
            client_initiator(self.client_id, self.domain_id, self.peer_addr),
            self.client_id,
            outcome,
            Some(reason),
        );
    }

    /// Returns `true` if `token` was recognised as a refresh token (whether
    /// or not it was revoked), so the caller stops looking.
    async fn revoke_refresh_token(&self, token: &str) -> Result<bool, Oauth2TokenError> {
        let session = self.state.provider.get_oauth2_session_provider();
        let record = session
            .peek_refresh_token(self.state, token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 revoke: refresh token lookup failed");
                Oauth2TokenError::internal("token revocation failed")
            })?;
        let Some(record) = record else {
            return Ok(false);
        };

        // Never act on (or reveal anything about) another client's family.
        if record.client_id != self.client_id || record.domain_id != self.domain_id {
            self.audit(Outcome::Failure, OutcomeReason::literal("ForeignClient"));
            return Ok(true);
        }
        // Idempotent: an already-tombstoned family keeps its original
        // revocation stamp/reason.
        if record.revoked_at.is_some() {
            return Ok(true);
        }

        let reason = RefreshTokenRevocationReason::RpRevoke;
        session
            .revoke_refresh_token_family(self.state, &record.family_id, reason)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 revoke: family revocation failed");
                Oauth2TokenError::internal("token revocation failed")
            })?;
        emit_oauth2_refresh_family_revoked_event(
            &self.state.audit_dispatcher,
            self.correlation_id,
            client_initiator(self.client_id, self.domain_id, self.peer_addr),
            &record.family_id,
            reason.as_str(),
        );
        self.audit(Outcome::Success, OutcomeReason::literal("RefreshToken"));
        Ok(true)
    }

    /// Returns `true` if `token` was a valid access token owned by this
    /// client (and is now on the JTI revocation list).
    async fn revoke_access_token(&self, token: &str) -> Result<bool, Oauth2TokenError> {
        let key_provider = self.state.provider.get_oauth2_key_provider();
        let jwks = match key_provider.jwks(self.state, self.domain_id).await {
            Ok(jwks) => jwks,
            // No signing keys: no token of this domain can exist.
            Err(Oauth2KeyProviderError::NotFound(_)) => return Ok(false),
            Err(e) => {
                tracing::warn!(error = %e, "oauth2 revoke: jwks lookup failed");
                return Err(Oauth2TokenError::internal("token revocation failed"));
            }
        };
        let base = base_url(self.state, self.headers).await;
        let issuer = format!("{base}/v4/oauth2/{}", self.domain_id);

        // Any verification failure (bad signature, expired, wrong audience,
        // foreign owner, ID token, ...) is indistinguishable from "unknown
        // token" for the caller.
        let Ok(revocable) = verify_revocable_access_token(
            token,
            &jwks,
            self.signing_algorithm,
            &[issuer],
            self.domain_id,
            self.client_id,
        ) else {
            return Ok(false);
        };

        key_provider
            .revoke_jti(self.state, self.domain_id, &revocable.jti, revocable.exp)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 revoke: jti revocation failed");
                Oauth2TokenError::internal("token revocation failed")
            })?;

        // End the whole session: the `sid` claim names the refresh family
        // that minted this token. The signature was verified above and the
        // token belongs to this client, so the family is this client's too;
        // revocation is idempotent (unknown/already-revoked family is a
        // no-op). The token itself is already revoked at this point, so a
        // failure here is logged and audited but does not fail the request:
        // answering 5xx would imply the presented token is still live.
        if let Some(family_id) = revocable.sid.as_deref() {
            let reason = RefreshTokenRevocationReason::RpRevoke;
            match self
                .state
                .provider
                .get_oauth2_session_provider()
                .revoke_refresh_token_family(self.state, family_id, reason)
                .await
            {
                Ok(()) => emit_oauth2_refresh_family_revoked_event(
                    &self.state.audit_dispatcher,
                    self.correlation_id,
                    client_initiator(self.client_id, self.domain_id, self.peer_addr),
                    family_id,
                    reason.as_str(),
                ),
                Err(e) => {
                    tracing::error!(error = %e, family_id, "oauth2 revoke: family revocation failed after jti revoked");
                    self.audit(
                        Outcome::Failure,
                        OutcomeReason::literal("FamilyRevocationFailed"),
                    );
                }
            }
        }
        self.audit(Outcome::Success, OutcomeReason::literal("AccessToken"));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
    use openstack_keystone_core_types::oauth2_session::{
        Oauth2SessionProviderError, RefreshToken, RefreshTokenRevocationReason,
    };
    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair, to_encoding_key,
    };

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::confidential_client;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::{Provider, ProviderBuilder};

    const ISSUER: &str = "http://localhost/v4/oauth2/domain-1";

    fn revoke_request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/revoke")
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

    fn record(client_id: &str, revoked_at: Option<i64>) -> RefreshToken {
        RefreshToken {
            token_id: "irrelevant".to_string(),
            family_id: "family-1".to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: client_id.to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string()],
            issued_at: 1000,
            spent_at: None,
            revoked_at,
            revocation_reason: None,
            expires_at: 1000 + 2_592_000,
            family_expires_at: 0,
        }
    }

    fn no_keys_mock() -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_jwks()
            .returning(|_, _| Err(Oauth2KeyProviderError::NotFound("domain-1".to_string())));
        mock
    }

    /// Sign an OIDC access token for `aud` and return `(token, key mock)`
    /// whose `jwks()` serves the matching public key.
    fn signed_access_token(aud: &str, sid: Option<&str>) -> (String, MockOauth2KeyProvider) {
        let now = chrono::Utc::now().timestamp();
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(material.kid.clone());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": ISSUER, "sub": "user-1", "aud": aud, "exp": now + 900,
                "iat": now, "nbf": now, "jti": "jti-1", "scope": "openid",
                "token_use": "access", "sid": sid,
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
        (token, mock)
    }

    async fn call(provider: ProviderBuilder, body: &str) -> StatusCode {
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(revoke_request(body))
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        if status == StatusCode::OK {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty(), "RFC 7009 success has an empty body");
        }
        status
    }

    #[tokio::test]
    async fn test_unknown_token_is_200_noop() {
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        // No revoke_* expectations: any revocation call would panic.
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock());
        assert_eq!(call(provider, &form("nope")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_foreign_client_refresh_token_is_200_and_untouched() {
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(record("other-client", None))));
        session.expect_revoke_refresh_token_family().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock());
        assert_eq!(call(provider, &form("foreign")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_own_refresh_token_tombstones_family() {
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(record("client-1", None))));
        session
            .expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason| {
                family_id == "family-1" && *reason == RefreshTokenRevocationReason::RpRevoke
            })
            .times(1)
            .returning(|_, _, _| Ok(()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock());
        assert_eq!(
            call(
                provider,
                &format!("{}&token_type_hint=refresh_token", form("own"))
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_already_revoked_refresh_token_is_noop() {
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(record("client-1", Some(5)))));
        session.expect_revoke_refresh_token_family().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock());
        assert_eq!(call(provider, &form("own")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_own_access_token_jti_is_revoked() {
        let (token, mut key_mock) = signed_access_token("client-1", Some("family-sid"));
        key_mock
            .expect_revoke_jti()
            .withf(|_, domain_id, jti, _| domain_id == "domain-1" && jti == "jti-1")
            .times(1)
            .returning(|_, _, _, _| Ok(()));
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        session
            .expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason| {
                family_id == "family-sid" && *reason == RefreshTokenRevocationReason::RpRevoke
            })
            .times(1)
            .returning(|_, _, _| Ok(()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(key_mock);
        assert_eq!(
            call(
                provider,
                &format!("{}&token_type_hint=access_token", form(&token))
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_sid_family_failure_after_jti_revoked_is_200() {
        let (token, mut key_mock) = signed_access_token("client-1", Some("family-sid"));
        key_mock
            .expect_revoke_jti()
            .times(1)
            .returning(|_, _, _, _| Ok(()));
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        session
            .expect_revoke_refresh_token_family()
            .times(1)
            .returning(|_, _, _| Err(Oauth2SessionProviderError::RaftNotAvailable));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(key_mock);
        assert_eq!(
            call(
                provider,
                &format!("{}&token_type_hint=access_token", form(&token))
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_foreign_client_access_token_is_200_and_untouched() {
        let (token, mut key_mock) = signed_access_token("other-client", Some("family-sid"));
        key_mock.expect_revoke_jti().never();
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        session.expect_revoke_refresh_token_family().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(key_mock);
        assert_eq!(call(provider, &form(&token)).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_access_token_without_sid_only_revokes_jti() {
        let (token, mut key_mock) = signed_access_token("client-1", None);
        key_mock
            .expect_revoke_jti()
            .times(1)
            .returning(|_, _, _, _| Ok(()));
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        session.expect_revoke_refresh_token_family().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(key_mock);
        assert_eq!(call(provider, &form(&token)).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cross_domain_refresh_token_is_200_and_untouched() {
        let mut other_domain = record("client-1", None);
        other_domain.domain_id = "domain-2".to_string();
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(move |_, _| Ok(Some(other_domain.clone())));
        session.expect_revoke_refresh_token_family().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(no_keys_mock());
        assert_eq!(call(provider, &form("tok")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwks_backend_error_is_500() {
        let mut key_mock = MockOauth2KeyProvider::default();
        key_mock
            .expect_jwks()
            .returning(|_, _| Err(Oauth2KeyProviderError::RaftNotAvailable));
        let mut session = MockOauth2SessionProvider::default();
        session
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock().await)
            .mock_oauth2_session(session)
            .mock_oauth2_key(key_mock);
        assert_eq!(
            call(provider, &form("tok")).await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn test_bad_client_secret_is_401() {
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock().await);
        assert_eq!(
            call(provider, "token=x&client_id=client-1&client_secret=wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_missing_token_is_400() {
        let provider = Provider::mocked_builder();
        assert_eq!(
            call(provider, "client_id=client-1&client_secret=s3cr3t").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_rate_limited_by_ip_before_lookup() {
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
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

        let mut first = revoke_request(&form("a"));
        first.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            api.as_service().oneshot(first).await.unwrap().status(),
            StatusCode::OK
        );
        let mut second = revoke_request(&form("b"));
        second.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            api.as_service().oneshot(second).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
