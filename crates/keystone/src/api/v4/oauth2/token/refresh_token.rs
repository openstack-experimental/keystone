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
//! `refresh_token` grant (RFC 6749 §6, ADR 0026 §9).

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use cadf::OutcomeReason;
use governor::clock::Clock as _;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::RefreshTokenRedemption;
use openstack_keystone_core_types::oauth2_client::{GrantType, OidcAccessTokenClaims};
use openstack_keystone_core_types::oauth2_session::{RefreshToken, RefreshTokenRevocationReason};

use crate::audit::{
    Oauth2Grant, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_grant_event,
    emit_oauth2_refresh_family_revoked_event, emit_oauth2_refresh_reuse_critical_event,
    emit_oauth2_session_event,
};
use crate::keystone::ServiceState;
use openstack_keystone_core::oauth2_metrics::OAUTH2_METRICS;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// `refresh_token` grant (RFC 6749 §6, ADR 0026 §9 rotation + reuse
/// detection).
pub(super) async fn handle_refresh_token_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(presented_refresh_token) = form.refresh_token.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: refresh_token",
        ));
    };

    // Unlike `client_credentials` (where `client_id` is public per-client),
    // the refresh token bearer value is itself the secret -- rate limiting
    // only by `client_id` lets a holder of one stolen token brute-rotate it
    // at the client's full configured rate. Add the same global per-IP
    // limiter the `/authorize/login` browser path uses (§7.B) as a second,
    // independent dimension of defense.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
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

    let client = authenticate_client(
        state,
        oauth2_cfg,
        domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the refresh_token grant",
        ));
    }

    // The family is only as valid as the principal behind it: re-check
    // the user and domain on every refresh so a disabled/deleted user (or
    // disabled domain) cannot keep minting access tokens. Done *before*
    // redemption (via a read-only peek): redemption spends the presented
    // token, so a lookup failure after it would strand the client without
    // its new bearer. The decision is keyed on the stored family record,
    // never on the presented scope.
    let peeked = state
        .provider
        .get_oauth2_session_provider()
        .peek_refresh_token(state, &presented_refresh_token)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 refresh token lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    let family_jkt = peeked.as_ref().and_then(|r| r.dpop_jkt.clone());
    if let Some(record) = &peeked {
        // Never act on (or reveal anything about) another client's family.
        if record.client_id != client_id || record.domain_id != domain_id {
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                correlation_id,
                "authenticate",
                build_initiator_unknown(),
                &client_id,
                Outcome::Failure,
                Some(OutcomeReason::literal("ForeignClient")),
            );
            // Same message as an unknown/expired token: must not reveal
            // that the bearer exists and belongs to another client.
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token is invalid, expired, or already used",
            ));
        }
        // Already-revoked families fall through to redemption, which
        // rejects them without further side effects.
        if record.revoked_at.is_none()
            && let Some(reason) = refresh_principal_invalid_reason(state, record).await?
        {
            return Err(revoke_family_invalid_grant(
                state,
                correlation_id,
                &record.family_id,
                reason,
            )
            .await);
        }
    }

    // A bound family needs a proof on every refresh, even when DPoP has been
    // switched off since (ADR 0043 §3.3). A proof that is merely missing,
    // stale or replayed is a bad request and leaves the family alone.
    //
    // A token that was already rotated away is not held to that: presenting
    // it is reuse whatever proof comes with it, and redemption below must
    // see it to revoke the family and raise the critical audit event. A
    // proof gate in front would answer a thief without a proof with a plain
    // bad request and hide the reuse.
    let already_spent = peeked.as_ref().is_some_and(|r| r.spent_at.is_some());
    // A family issued unbound cannot take a key now: where DPoP is required
    // the unbound token is the very thing to cut off, and whoever holds it
    // could otherwise bind it to a key of their own with any valid proof.
    // The answer is that of an unknown token, so it reveals nothing about
    // the family. The client signs in again.
    if peeked.is_some() && family_jkt.is_none() && !already_spent {
        let mode = state
            .provider
            .get_oauth2_client_provider()
            .effective_dpop_mode(
                &ExecutionContext::internal(state),
                domain_id,
                client.dpop_bound_access_tokens,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "DPoP mode lookup failed");
                Oauth2TokenError::internal("token issuance failed")
            })?;
        if mode == openstack_keystone_config::DpopMode::Required {
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token is invalid, expired, or already used",
            ));
        }
    }
    let min_mode = if family_jkt.is_some() {
        openstack_keystone_config::DpopMode::Required
    } else {
        openstack_keystone_config::DpopMode::Disabled
    };
    let confirmation = if already_spent {
        None
    } else {
        super::dpop::bind_token_request(
            state,
            domain_id,
            headers,
            peer_addr,
            &client,
            min_mode,
            super::dpop::SourceLimit::Charged,
        )
        .await?
    };
    // A *valid* proof from another key means the refresh token is in the
    // wrong hands: revoke the family like a detected reuse.
    if let (Some(expected), Some(presented), Some(record)) = (
        family_jkt.as_deref(),
        confirmation.as_ref(),
        peeked.as_ref(),
    ) && !presented.matches(expected)
    {
        return Err(revoke_family_invalid_grant(
            state,
            correlation_id,
            &record.family_id,
            RefreshTokenRevocationReason::DpopKeyMismatch,
        )
        .await);
    }

    let redemption = state
        .provider
        .get_oauth2_session_provider()
        .redeem_refresh_token(
            state,
            &presented_refresh_token,
            &client_id,
            domain_id,
            confirmation.as_ref().map(|c| c.jkt.clone()),
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 refresh token redemption failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let (record, bearer) = match redemption {
        RefreshTokenRedemption::Invalid => {
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token is invalid, expired, or already used",
            ));
        }
        RefreshTokenRedemption::ReuseDetected { family_id, reason } => {
            OAUTH2_METRICS.record_refresh_reuse(domain_id, &client_id);
            emit_oauth2_refresh_reuse_critical_event(
                &state.audit_dispatcher,
                correlation_id,
                build_initiator_unknown(),
                &family_id,
                reason.as_str(),
            )
            .await;
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token has already been used; the session has been revoked",
            ));
        }
        RefreshTokenRedemption::Rotated { record, bearer } => (*record, bearer),
    };

    // Close the window between the pre-redemption check and the rotation:
    // if the principal was disabled/deleted in between, revoke now (the
    // family-wide revoke also tombstones the child just minted, whose
    // bearer is never handed out). Only a *definitive* "invalid" answer
    // acts here; a lookup error is ignored because the pre-check just
    // succeeded and failing now would strand the client with a lost
    // bearer (the next refresh re-validates anyway).
    if let Ok(Some(reason)) = refresh_principal_invalid_reason(state, &record).await {
        return Err(
            revoke_family_invalid_grant(state, correlation_id, &record.family_id, reason).await,
        );
    }

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;

    let access_claims = OidcAccessTokenClaims {
        iss: issuer,
        sub: record.user_id.clone(),
        aud: client_id.clone(),
        exp: now + access_lifetime,
        iat: now,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: record.scope.join(" "),
        token_use: "access".to_string(),
        family_id: Some(record.family_id.clone()),
        cnf: confirmation.clone(),
    };
    let access_token = sign_jwt(state, domain_id, &access_claims).await?;

    emit_oauth2_grant_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_user_id(&record.user_id, domain_id),
        Oauth2Grant {
            client_id: &client_id,
            grant_type: "refresh_token",
        },
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: super::dpop::token_type(confirmation.as_ref()),
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token: None,
        refresh_token: Some(bearer),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Revoke a refresh token family because its principal is no longer valid
/// and build the error to return: `invalid_grant` on success, `internal`
/// if the revocation itself failed (fail closed either way -- no token is
/// minted).
pub(super) async fn revoke_family_invalid_grant(
    state: &ServiceState,
    correlation_id: &str,
    family_id: &str,
    reason: RefreshTokenRevocationReason,
) -> Oauth2TokenError {
    match state
        .provider
        .get_oauth2_session_provider()
        .revoke_refresh_token_family(state, family_id, reason)
        .await
    {
        Ok(()) => {
            emit_oauth2_refresh_family_revoked_event(
                &state.audit_dispatcher,
                correlation_id,
                build_initiator_unknown(),
                family_id,
                reason.as_str(),
            );
            Oauth2TokenError::invalid_grant("refresh_token is invalid, expired, or already used")
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 refresh token family revocation failed");
            Oauth2TokenError::internal("token issuance failed")
        }
    }
}

/// Re-validate the user and domain a refresh token belongs to.
///
/// Returns the revocation reason when the principal is no longer valid
/// (user deleted, user disabled or moved out of the family's domain,
/// domain disabled/deleted), `None` when the rotation may proceed. A
/// failed lookup is an `Err` (fail closed: no token is minted and the
/// family is not revoked, since a lookup error is no evidence the
/// principal is invalid). Called before redemption, so the presented
/// token is still unspent and the client can simply retry.
pub(super) async fn refresh_principal_invalid_reason(
    state: &ServiceState,
    record: &RefreshToken,
) -> Result<Option<RefreshTokenRevocationReason>, Oauth2TokenError> {
    let exec = ExecutionContext::internal(state);
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &record.user_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 refresh token user lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    match user {
        None => return Ok(Some(RefreshTokenRevocationReason::UserDeleted)),
        Some(user) if !user.enabled => {
            return Ok(Some(RefreshTokenRevocationReason::UserDisabled));
        }
        Some(user) if user.domain_id != record.domain_id => {
            return Ok(Some(RefreshTokenRevocationReason::UserDomainChanged));
        }
        Some(_) => {}
    }

    let domain = state
        .provider
        .get_resource_provider()
        .get_domain(&exec, &record.domain_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 refresh token domain lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    if !domain.is_some_and(|d| d.enabled) {
        return Ok(Some(RefreshTokenRevocationReason::DomainDisabled));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use cadf::Outcome;

    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{extract::ConnectInfo, http::StatusCode};

    use sea_orm::DatabaseConnection;
    use serde_json::Value;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;

    use openstack_keystone_core_types::oauth2_client as provider_types;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        dpop_proof, dpop_test_jkt, json_body, jwt_claims, ok_key_mock, public_authz_code_client,
        refresh_identity_mock, refresh_resource_mock, refresh_user, request,
    };
    use crate::identity::MockIdentityProvider;

    use crate::oauth2_client::MockOauth2ClientProvider;

    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    use openstack_keystone_core::oauth2_session::RefreshTokenRedemption;
    use openstack_keystone_core_types::oauth2_session::RefreshToken;

    fn refresh_token_form(token: &str) -> String {
        format!("grant_type=refresh_token&client_id=client-1&refresh_token={token}")
    }

    fn sample_refresh_record(spent_at: Option<i64>) -> RefreshToken {
        RefreshToken {
            upstream: None,
            token_id: "irrelevant".to_string(),
            family_id: "family-1".to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string()],
            issued_at: 1000,
            spent_at,
            revoked_at: None,
            revocation_reason: None,
            expires_at: 1000 + 2_592_000,
            family_expires_at: 0,
            amr: vec![],
            dpop_jkt: None,
        }
    }

    #[tokio::test]
    async fn test_refresh_token_missing_param_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=refresh_token&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_refresh_token_reuse_detected_is_invalid_grant() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::ReuseDetected {
                    family_id: "family-1".to_string(),
                    reason: openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason::ReuseDetected,
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)));
        let (state, mut receivers) =
            openstack_keystone_core::api::tests::get_mocked_state_with_audit(provider, true, {
                let mut config = openstack_keystone_config::Config::default();
                config.oauth2.allow_host_header_issuer = true;
                config
            })
            .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("stolen-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");

        // Reuse is audited fail-closed: one record on the critical channel,
        // targeting the revoked family.
        let event = receivers
            .critical
            .try_recv()
            .expect("reuse must leave a critical audit record");
        assert_eq!(event.payload().action(), "oauth2/refresh_reuse_detected");
        assert_eq!(event.payload().outcome(), Outcome::Failure);
    }

    #[tokio::test]
    async fn test_refresh_token_rotation_success() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(sample_refresh_record(None)),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["access_token"].as_str().unwrap().split('.').count(), 3);
        assert_eq!(body["refresh_token"], "new-bearer-token");
        assert!(body.get("id_token").is_none());
        // The rotated family id rides along as `sid` for RFC 7009.
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["fid"], "family-1");
    }

    /// Run a refresh grant whose rotation succeeds and whose family, if
    /// revoked, must be revoked with `expected_reason` (`None` = the
    /// revoke call must never happen; mockall panics otherwise).
    async fn run_refresh_with_principal(
        identity_mock: MockIdentityProvider,
        resource_mock: MockResourceProvider,
        expected_reason: Option<
            openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason,
        >,
    ) -> (StatusCode, Value) {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        // `redeem_refresh_token` deliberately not configured: invalid
        // principals (and lookup errors) must be rejected before the
        // token is spent; mockall panics if redemption is reached.
        if let Some(expected) = expected_reason {
            session_mock
                .expect_revoke_refresh_token_family()
                .withf(move |_, family_id, reason| family_id == "family-1" && *reason == expected)
                .times(1)
                .returning(|_, _, _| Ok(()));
        }

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        let status = response.status();
        (status, json_body(response).await)
    }

    #[tokio::test]
    async fn test_refresh_token_disabled_user_revokes_family_invalid_grant() {
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason as R;
        let (status, body) = run_refresh_with_principal(
            refresh_identity_mock(Some(refresh_user(false, "domain-1"))),
            refresh_resource_mock(Some(true)),
            Some(R::UserDisabled),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert!(body.get("access_token").is_none());
        assert!(body.get("refresh_token").is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_deleted_user_revokes_family_invalid_grant() {
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason as R;
        let (status, body) = run_refresh_with_principal(
            refresh_identity_mock(None),
            refresh_resource_mock(Some(true)),
            Some(R::UserDeleted),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_user_domain_mismatch_revokes_family() {
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason as R;
        let (status, body) = run_refresh_with_principal(
            refresh_identity_mock(Some(refresh_user(true, "other-domain"))),
            refresh_resource_mock(Some(true)),
            Some(R::UserDomainChanged),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_disabled_domain_revokes_family_invalid_grant() {
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason as R;
        let (status, body) = run_refresh_with_principal(
            refresh_identity_mock(Some(refresh_user(true, "domain-1"))),
            refresh_resource_mock(Some(false)),
            Some(R::DomainDisabled),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_user_lookup_error_fails_closed_without_revoking() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Err(crate::identity::IdentityProviderError::UserNotFound(
                "boom".to_string(),
            ))
        });
        // No revoke expectation: a lookup error is not evidence the
        // principal is invalid, so this path must not revoke the family.
        let (status, body) =
            run_refresh_with_principal(identity_mock, refresh_resource_mock(Some(true)), None)
                .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.get("access_token").is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_lookup_error_leaves_token_unspent_and_retry_succeeds() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        // Redemption must happen exactly once: only on the retry.
        session_mock
            .expect_redeem_refresh_token()
            .times(1)
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(sample_refresh_record(None)),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        // First user lookup fails; every later one succeeds (the retry's
        // pre-check and post-rotation re-check).
        let mut identity_mock = MockIdentityProvider::default();
        let mut calls = 0;
        identity_mock.expect_get_user().returning(move |_, _| {
            calls += 1;
            if calls == 1 {
                Err(crate::identity::IdentityProviderError::UserNotFound(
                    "boom".to_string(),
                ))
            } else {
                Ok(Some(refresh_user(true, "domain-1")))
            }
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let first = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let retry = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(json_body(retry).await["refresh_token"], "new-bearer-token");
    }

    #[tokio::test]
    async fn test_refresh_token_user_disabled_between_precheck_and_rotation_revokes() {
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason as R;
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        session_mock
            .expect_redeem_refresh_token()
            .times(1)
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(sample_refresh_record(None)),
                    bearer: "new-bearer-token".to_string(),
                })
            });
        session_mock
            .expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason| family_id == "family-1" && *reason == R::UserDisabled)
            .times(1)
            .returning(|_, _, _| Ok(()));

        // Enabled for the pre-check, disabled by the post-rotation re-check.
        let mut identity_mock = MockIdentityProvider::default();
        let mut calls = 0;
        identity_mock.expect_get_user().returning(move |_, _| {
            calls += 1;
            Ok(Some(refresh_user(calls == 1, "domain-1")))
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"], "invalid_grant");
        assert!(body.get("refresh_token").is_none());
        assert!(body.get("access_token").is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_other_clients_family_rejected_before_redemption() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock.expect_peek_refresh_token().returning(|_, _| {
            let mut record = sample_refresh_record(None);
            record.client_id = "some-other-client".to_string();
            Ok(Some(record))
        });
        // `redeem_refresh_token` / `revoke_refresh_token_family`
        // deliberately not configured: a token belonging to another
        // client must stay unspent and untouched; mockall panics if
        // either is reached.

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)));
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("someone-elses-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_foreign_presentation_does_not_break_owner() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, bearer| {
                let mut record = sample_refresh_record(None);
                if bearer == "victim-token" {
                    record.client_id = "victim-client".to_string();
                }
                Ok(Some(record))
            });
        // Only the owner's redemption may reach the backend; a second
        // (foreign) call would exceed `times(1)` and panic.
        session_mock
            .expect_redeem_refresh_token()
            .times(1)
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(sample_refresh_record(None)),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let foreign = api
            .as_service()
            .oneshot(request(&refresh_token_form("victim-token")))
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
        let foreign_body = json_body(foreign).await;
        assert_eq!(foreign_body["error"], "invalid_grant");
        assert_eq!(
            foreign_body["error_description"],
            "refresh_token is invalid, expired, or already used"
        );

        let owner = api
            .as_service()
            .oneshot(request(&refresh_token_form("own-token")))
            .await
            .unwrap();
        assert_eq!(owner.status(), StatusCode::OK);
        assert_eq!(json_body(owner).await["refresh_token"], "new-bearer-token");
    }

    #[tokio::test]
    async fn test_refresh_token_grant_rate_limited_by_ip_before_lookup() {
        // A stolen refresh token bearer is itself the secret (unlike
        // client_credentials' public client_id) -- the global per-IP
        // limiter must reject brute-rotation attempts from one source IP
        // even before the (mocked, would otherwise always succeed) session
        // lookup runs.
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
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

        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_record(None))));
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(sample_refresh_record(None)),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock())
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

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request(&refresh_token_form("old-bearer-token"));
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::OK
        );

        let mut req2 = request(&refresh_token_form("another-bearer-token"));
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Burst exhausted: rejected by the IP limiter regardless of which
        // (still-valid, per the mock) token is presented next.
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    const TOKEN_URL: &str = "http://localhost/v4/oauth2/domain-1/token";

    /// How a [`dpop_state`] expects the family to be treated.
    struct Expect {
        /// Redemptions of the refresh token.
        redeems: usize,
        /// Whole-family revocations for a DPoP key mismatch.
        revocations: usize,
    }

    /// A state with DPoP `optional` and a refresh family bound to `family_jkt`.
    async fn dpop_state(
        family_jkt: Option<String>,
        expect: Expect,
    ) -> crate::keystone::ServiceState {
        dpop_state_in_mode(
            family_jkt,
            expect,
            openstack_keystone_config::DpopMode::Optional,
        )
        .await
    }

    /// As [`dpop_state`] with the effective mode of the client set to `mode`.
    async fn dpop_state_in_mode(
        family_jkt: Option<String>,
        expect: Expect,
        mode: openstack_keystone_config::DpopMode,
    ) -> crate::keystone::ServiceState {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(move |_, _, _| Ok(mode));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let jkt = family_jkt.clone();
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_peek_refresh_token()
            .returning(move |_, _| {
                let mut record = sample_refresh_record(None);
                record.dpop_jkt = jkt.clone();
                Ok(Some(record))
            });
        session_mock
            .expect_redeem_refresh_token()
            .times(expect.redeems)
            .returning(move |_, _, _, _, _| {
                let mut record = sample_refresh_record(None);
                record.dpop_jkt = family_jkt.clone();
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(record),
                    bearer: "rotated-bearer".to_string(),
                })
            });
        session_mock
            .expect_revoke_refresh_token_family()
            .withf(|_, family, reason| {
                family == "family-1"
                    && *reason
                        == openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason::DpopKeyMismatch
            })
            .times(expect.revocations)
            .returning(|_, _, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.oauth2.dpop = openstack_keystone_config::DpopMode::Optional;
        config.mapping.cluster_salt = Some("dpop-test-salt".to_string().into());
        openstack_keystone_core::api::tests::get_mocked_state_with_config(
            provider, true, None, config,
        )
        .await
    }

    fn with_proof(proof: Option<String>) -> axum::http::Request<axum::body::Body> {
        let mut req = request(&refresh_token_form("rt-1"));
        if let Some(proof) = proof {
            req.headers_mut().insert("DPoP", proof.parse().unwrap());
        }
        req
    }

    async fn fetch_nonce(api: &mut utoipa_axum::router::OpenApiRouter) -> String {
        let response = api
            .as_service()
            .oneshot(with_proof(Some(dpop_proof(TOKEN_URL, "nonce-probe", None))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let nonce = response.headers()["dpop-nonce"]
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(json_body(response).await["error"], "use_dpop_nonce");
        nonce
    }

    #[tokio::test]
    async fn test_bound_family_with_same_key_rotates_bound_tokens() {
        let state = dpop_state(
            Some(dpop_test_jkt()),
            Expect {
                redeems: 1,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api).await;

        let response = api
            .as_service()
            .oneshot(with_proof(Some(dpop_proof(
                TOKEN_URL,
                "jti-1",
                Some(&nonce),
            ))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(body["refresh_token"], "rotated-bearer");
        assert_eq!(
            jwt_claims(body["access_token"].as_str().unwrap())["cnf"]["jkt"],
            dpop_test_jkt()
        );
    }

    #[tokio::test]
    async fn test_bound_family_with_another_key_is_revoked() {
        let state = dpop_state(
            Some("A".repeat(43)),
            Expect {
                redeems: 0,
                revocations: 1,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api).await;

        let response = api
            .as_service()
            .oneshot(with_proof(Some(dpop_proof(
                TOKEN_URL,
                "jti-2",
                Some(&nonce),
            ))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_bound_family_without_proof_is_a_bad_request_not_a_revocation() {
        let state = dpop_state(
            Some(dpop_test_jkt()),
            Expect {
                redeems: 0,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(with_proof(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_dpop_proof");
    }

    /// A rotated-away token of a bound family is reuse whatever proof comes
    /// with it: redemption must see it, so the family is revoked and the
    /// critical event raised, not hidden behind a missing-proof error.
    #[tokio::test]
    async fn test_spent_token_of_bound_family_without_proof_is_reuse() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Optional));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock.expect_peek_refresh_token().returning(|_, _| {
            let mut record = sample_refresh_record(Some(1));
            record.dpop_jkt = Some(dpop_test_jkt());
            Ok(Some(record))
        });
        session_mock
            .expect_redeem_refresh_token()
            .times(1)
            .returning(|_, _, _, _, _| {
                Ok(RefreshTokenRedemption::ReuseDetected {
                    family_id: "family-1".to_string(),
                    reason: openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason::ReuseDetected,
                })
            });
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(refresh_resource_mock(Some(true)))
            .mock_oauth2_key(ok_key_mock());
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.oauth2.dpop = openstack_keystone_config::DpopMode::Optional;
        config.mapping.cluster_salt = Some("dpop-test-salt".to_string().into());
        let state = openstack_keystone_core::api::tests::get_mocked_state_with_config(
            provider, true, None, config,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(with_proof(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_nonce_challenge_neither_rotates_nor_revokes() {
        let state = dpop_state(
            Some(dpop_test_jkt()),
            Expect {
                redeems: 0,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        assert!(!fetch_nonce(&mut api).await.is_empty());
    }

    #[tokio::test]
    async fn test_replayed_proof_is_a_bad_request_not_a_revocation() {
        let state = dpop_state(
            Some(dpop_test_jkt()),
            Expect {
                redeems: 1,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api).await;
        let proof = dpop_proof(TOKEN_URL, "jti-replay", Some(&nonce));

        let first = api
            .as_service()
            .oneshot(with_proof(Some(proof.clone())))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = api
            .as_service()
            .oneshot(with_proof(Some(proof)))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(second).await["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn test_unbound_family_with_proof_gets_bound_access_token() {
        let state = dpop_state(
            None,
            Expect {
                redeems: 1,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api).await;

        let response = api
            .as_service()
            .oneshot(with_proof(Some(dpop_proof(
                TOKEN_URL,
                "jti-3",
                Some(&nonce),
            ))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["token_type"], "DPoP");
    }

    #[tokio::test]
    async fn test_unbound_family_without_proof_stays_bearer() {
        let state = dpop_state(
            None,
            Expect {
                redeems: 1,
                revocations: 0,
            },
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(with_proof(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["token_type"], "Bearer");
    }

    /// Where DPoP is required an unbound family cannot be bound by a refresh
    /// with a proof of any key: the holder of a stolen unbound token would
    /// otherwise take it over. Nothing is redeemed and the answer is that of
    /// an unknown token.
    #[tokio::test]
    async fn test_unbound_family_is_not_bound_where_dpop_is_required() {
        let state = dpop_state_in_mode(
            None,
            Expect {
                redeems: 0,
                revocations: 0,
            },
            openstack_keystone_config::DpopMode::Required,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        // Refused before any nonce is asked for.
        for proof in [Some(dpop_proof(TOKEN_URL, "jti-required", None)), None] {
            let response = api.as_service().oneshot(with_proof(proof)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json_body(response).await["error"], "invalid_grant");
        }
    }
}
