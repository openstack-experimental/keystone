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
//! `authorization_code` grant (RFC 6749 §4.1.3).

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use governor::clock::Clock as _;

use openstack_keystone_core::oauth2_client::{
    IdTokenParams, TemplateScope, build_id_token_claims, pkce,
};
use openstack_keystone_core::oauth2_session::IssueRefreshTokenRequest;
use openstack_keystone_core_types::oauth2_client::{GrantType, OidcAccessTokenClaims};

use crate::audit::{build_initiator_from_user_id, emit_oauth2_grant_event};
use crate::keystone::ServiceState;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// `authorization_code` grant (RFC 6749 §4.1.3, ADR 0026 §10 Phase 4).
pub(super) async fn handle_authorization_code_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(code) = form.code.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: code",
        ));
    };
    let Some(redirect_uri) = form.redirect_uri.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: redirect_uri",
        ));
    };
    let Some(code_verifier) = form.code_verifier.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: code_verifier",
        ));
    };

    // Step 1 (ADR 0026 §7.A): pre-hash rate limit, before any lookup.
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
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the authorization_code grant",
        ));
    }

    let record = state
        .provider
        .get_oauth2_session_provider()
        .redeem_authorization_code(state, &code)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 authorization code redemption failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    let Some(record) = record else {
        return Err(Oauth2TokenError::invalid_grant(
            "authorization code is invalid, expired, or already redeemed",
        ));
    };

    if record.client_id != client_id
        || record.domain_id != domain_id
        || record.redirect_uri != redirect_uri
    {
        return Err(Oauth2TokenError::invalid_grant(
            "authorization code does not match this client_id/redirect_uri",
        ));
    }
    if record.code_challenge_method != "S256"
        || !pkce::verify_code_challenge(&code_verifier, &record.code_challenge)
    {
        return Err(Oauth2TokenError::invalid_grant("PKCE verification failed"));
    }

    if record.scope.iter().any(|s| s == "openstack:api") {
        // Full `OpenStackAccessTokenClaims` issuance on this grant requires
        // resolving a project/domain authorization scope for the token,
        // which the `/authorize` consent step does not yet collect in this
        // phase (its own scope validation already rejects `openstack:api`
        // outright for the same reason -- this is the token-minting side
        // of that same guard, defense in depth against ever silently
        // downgrading a client that explicitly asked for OpenStack
        // authorization data to a bare identity token).
        return Err(Oauth2TokenError::invalid_scope(
            "openstack:api on the authorization_code grant is not yet supported",
        ));
    }

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let id_lifetime = i64::from(oauth2_cfg.id_token_lifetime_minutes) * 60;

    // Issued before the access token so the token can carry the session id
    // (`sid`) of its refresh family for RFC 7009 revocation.
    let (sid, refresh_token) = if client.grant_types.contains(&GrantType::RefreshToken) {
        let (record_rt, bearer) = state
            .provider
            .get_oauth2_session_provider()
            .issue_refresh_token(
                state,
                IssueRefreshTokenRequest {
                    domain_id: domain_id.to_string(),
                    client_id: client.client_id.clone(),
                    user_id: record.user_id.clone(),
                    scope: record.scope.clone(),
                },
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 refresh token issuance failed");
                Oauth2TokenError::internal("token issuance failed")
            })?;
        (Some(record_rt.family_id), Some(bearer))
    } else {
        (None, None)
    };

    let signed = async {
        let access_claims = OidcAccessTokenClaims {
            iss: issuer.clone(),
            sub: record.user_id.clone(),
            aud: client_id.clone(),
            exp: now + access_lifetime,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: record.scope.join(" "),
            token_use: "access".to_string(),
            sid: sid.clone(),
        };
        let access_token = sign_jwt(state, domain_id, &access_claims).await?;

        let id_claims = build_id_token_claims(
            state,
            &client,
            IdTokenParams {
                issuer,
                user_id: record.user_id.clone(),
                client_id: client_id.clone(),
                now,
                lifetime: id_lifetime,
                auth_time: record.auth_time,
                nonce: record.nonce.clone(),
                amr: record.amr.clone(),
                at_hash: Some(compute_at_hash(&access_token)),
            },
            &record.scope,
            &TemplateScope::default(),
        )
        .await
        .map_err(id_token_error)?;
        let id_token = sign_jwt(state, domain_id, &id_claims).await?;
        Ok::<_, Oauth2TokenError>((access_token, id_token))
    }
    .await;
    let (access_token, id_token) = match signed {
        Ok(tokens) => tokens,
        Err(e) => {
            discard_refresh_family(state, sid.as_deref()).await;
            return Err(e);
        }
    };

    emit_oauth2_grant_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_user_id(&record.user_id, domain_id),
        &client.client_id,
        "authorization_code",
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token: Some(id_token),
        refresh_token,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {

    use axum::http::StatusCode;

    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        json_body, jwt_claims, ok_key_mock, public_authz_code_client, refresh_identity_mock,
        refresh_resource_mock, refresh_user, request,
    };

    use crate::oauth2_client::MockOauth2ClientProvider;

    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    use openstack_keystone_core_types::oauth2_session::AuthorizationCode;

    // RFC 7636 Appendix B worked example.
    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn sample_authz_code(scope: Vec<String>) -> AuthorizationCode {
        AuthorizationCode {
            code: "code-1".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            redirect_uri: "https://rp.example.com/callback".to_string(),
            code_challenge: PKCE_CHALLENGE.to_string(),
            code_challenge_method: "S256".to_string(),
            scope,
            nonce: Some("nonce-1".to_string()),
            auth_time: 1000,
            amr: vec!["pwd".to_string()],
            created_at: 1000,
            expires_at: 1060,
        }
    }

    fn authz_code_form(code_verifier: &str) -> String {
        format!(
            "grant_type=authorization_code&client_id=client-1&code=code-1&redirect_uri=https://rp.example.com/callback&code_verifier={code_verifier}"
        )
    }

    #[tokio::test]
    async fn test_authorization_code_missing_code_is_invalid_request() {
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
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_authorization_code_pkce_mismatch_is_invalid_grant() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));

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
            .oneshot(request(&authz_code_form("wrong-verifier")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_authorization_code_redemption_miss_is_invalid_grant() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(None));

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
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_authorization_code_openstack_api_scope_is_rejected() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| {
                Ok(Some(sample_authz_code(vec![
                    "openid".to_string(),
                    "openstack:api".to_string(),
                ])))
            });

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
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_authorization_code_id_token_has_profile_email_and_template() {
        let mut client = public_authz_code_client().await;
        client.claims_template = std::collections::HashMap::from([(
            "tenant".to_string(),
            "${user.domain_id}".to_string(),
        )]);
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| {
                Ok(Some(sample_authz_code(vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ])))
            });

        let mut user = refresh_user(true, "domain-1");
        user.extra
            .insert("email".to_string(), serde_json::json!("u@example.com"));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_identity(refresh_identity_mock(Some(user)))
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let claims = jwt_claims(body["id_token"].as_str().unwrap());
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["tenant"], "domain-1");
        assert_eq!(claims["email"], "u@example.com");
        assert_eq!(claims["email_verified"], false);
        assert!(claims.get("name").is_some());
    }

    #[tokio::test]
    async fn test_authorization_code_success_issues_id_and_access_token() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["access_token"].as_str().unwrap().split('.').count(), 3);
        assert_eq!(body["id_token"].as_str().unwrap().split('.').count(), 3);
        assert!(body.get("refresh_token").is_none());
        // No refresh family, hence no session id.
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert!(claims.get("sid").is_none());
    }

    #[tokio::test]
    async fn test_authorization_code_access_token_carries_refresh_family_as_sid() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            openstack_keystone_core_types::oauth2_client::GrantType::AuthorizationCode,
            openstack_keystone_core_types::oauth2_client::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));
        session_mock.expect_issue_refresh_token().returning(|_, _| {
            Ok((
                openstack_keystone_core_types::oauth2_session::RefreshToken {
                    token_id: "irrelevant".to_string(),
                    family_id: "family-9".to_string(),
                    parent_token_id: None,
                    domain_id: "domain-1".to_string(),
                    client_id: "client-1".to_string(),
                    user_id: "user-1".to_string(),
                    scope: vec!["openid".to_string()],
                    issued_at: 1000,
                    spent_at: None,
                    revoked_at: None,
                    revocation_reason: None,
                    expires_at: 1000 + 2_592_000,
                    family_expires_at: 0,
                },
                "refresh-bearer".to_string(),
            ))
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["refresh_token"], "refresh-bearer");
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["sid"], "family-9");
    }

    #[tokio::test]
    async fn test_signing_failure_discards_undelivered_refresh_family() {
        use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
        use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;

        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            openstack_keystone_core_types::oauth2_client::GrantType::AuthorizationCode,
            openstack_keystone_core_types::oauth2_client::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));
        session_mock.expect_issue_refresh_token().returning(|_, _| {
            Ok((
                openstack_keystone_core_types::oauth2_session::RefreshToken {
                    token_id: "irrelevant".to_string(),
                    family_id: "family-9".to_string(),
                    parent_token_id: None,
                    domain_id: "domain-1".to_string(),
                    client_id: "client-1".to_string(),
                    user_id: "user-1".to_string(),
                    scope: vec!["openid".to_string()],
                    issued_at: 1000,
                    spent_at: None,
                    revoked_at: None,
                    revocation_reason: None,
                    expires_at: 1000 + 2_592_000,
                    family_expires_at: 0,
                },
                "refresh-bearer".to_string(),
            ))
        });
        // The bearer is never delivered, so the family must be discarded.
        session_mock
            .expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason| {
                family_id == "family-9" && *reason == RefreshTokenRevocationReason::IssuanceFailed
            })
            .times(1)
            .returning(|_, _, _| Ok(()));

        let mut key_mock = crate::oauth2_key::MockOauth2KeyProvider::default();
        key_mock
            .expect_active_signing_key()
            .returning(|_, _| Err(Oauth2KeyProviderError::NotFound("domain-1".to_string())));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(key_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
