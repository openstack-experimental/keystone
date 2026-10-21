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
//! RFC 8693 Token Exchange grant.

use std::collections::HashSet;

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use governor::clock::Clock as _;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::ServiceListParameters;
use openstack_keystone_core_types::oauth2_client::{Audience, GrantType};

use crate::audit::{build_initiator_from_vsc, emit_oauth2_session_event};
use crate::keystone::ServiceState;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// RFC 8693 Token Exchange grant (ADR 0026 §12 "v2 shape", implemented as
/// the follow-up amendment the ADR itself defers this grant's concrete
/// shape to). Trades an existing Keystone-native delegated credential
/// (trust or application credential; EC2 deferred) for a native
/// `OpenStackAccessTokenClaims`. Gating: the exchanging client must hold
/// `token-exchange` in its own `grant_types` -- SystemAdmin-only to enable,
/// mirroring `pre_authorized`'s gating (ADR 0026 §5), enforced at client
/// create/update time, not here.
pub(super) async fn handle_token_exchange_grant(
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
    let Some(subject_token) = form.subject_token.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: subject_token",
        ));
    };

    // Step 1 (ADR 0026 §7.A): pre-hash rate limit, inherited by every
    // `/token` sub-path, before any lookup or subject_token validation.
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
    if !client.grant_types.contains(&GrantType::TokenExchange) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the token-exchange grant",
        ));
    }

    // The exchanged token is bound to the key of the proof, when the client
    // sends one or the effective mode demands it (ADR 0043 §4). Checked
    // before the subject token, so a nonce challenge costs no validation.
    let confirmation = super::dpop::bind_token_request(
        state,
        domain_id,
        headers,
        peer_addr,
        &client,
        openstack_keystone_config::DpopMode::Disabled,
    )
    .await?;

    let (vsc, delegation_context, credential_expires_at) =
        openstack_keystone_core::oauth2_client::validate_subject_token(state, &subject_token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 token exchange subject_token rejected");
                Oauth2TokenError::invalid_grant(
                    "subject_token is invalid, expired, or carries no exchangeable delegation",
                )
            })?;

    // The Keystone-native tokens this grant accepts carry no confirmation
    // claim. A subject token that does is a sender-constrained token whose
    // proof (`ath` over the subject token) this grant cannot check, so it is
    // refused rather than traded for an unbound token (ADR 0043 §4).
    if subject_token_carries_cnf(&subject_token) {
        return Err(Oauth2TokenError::invalid_grant(
            "a DPoP-bound subject_token cannot be exchanged",
        ));
    }

    let audience = requested_audience(state, &form.audience).await?;

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let jti = uuid::Uuid::new_v4().to_string();

    let mut claims = openstack_keystone_core::oauth2_client::build_token_exchange_claims(
        &client,
        &vsc,
        delegation_context,
        credential_expires_at,
        &issuer,
        jti,
        now,
        now + access_lifetime,
        audience,
    )
    .map_err(|e| {
        use openstack_keystone_core::oauth2_client::TokenExchangeError;

        match e {
            TokenExchangeError::CrossDomainSubjectToken => {
                tracing::warn!(error = %e, "subject_token's scope belongs to a different domain than this token endpoint");
                Oauth2TokenError::invalid_grant(
                    "subject_token's scope belongs to a different domain than this token endpoint",
                )
            }
            TokenExchangeError::MissingSubjectTokenExpiry => {
                tracing::warn!(error = %e, "subject_token is missing an expiry claim");
                Oauth2TokenError::invalid_grant(
                    "subject_token is missing an expiry claim, cannot be exchanged",
                )
            }
            TokenExchangeError::CredentialChainExpired => {
                tracing::warn!(error = %e, "subject_token or application credential chain is already expired or expires too soon");
                Oauth2TokenError::invalid_grant(
                    "subject_token or application credential expiry does not permit token exchange",
                )
            }
            _ => {
                tracing::error!(error = %e, "unexpected error occurred during token exchange");
                Oauth2TokenError::internal("token issuance failed")
            }
        }
    })?;
    let token_type = super::dpop::token_type(confirmation.as_ref());
    claims.cnf = confirmation;
    let access_token = sign_jwt(state, domain_id, &claims).await?;

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_vsc(&vsc),
        &client_id,
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type,
        expires_in: claims.exp - now,
        scope: "openstack:api".to_string(),
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Whether `token` is a JWT whose payload has a `cnf` claim, or one whose
/// payload cannot be read. The payload is read without verifying anything:
/// the caller has already validated the token and only uses this to fail
/// closed on a token type it cannot honour, so a JWT-shaped token that cannot
/// be inspected counts as carrying a confirmation rather than as plain.
/// Tokens that are not JWT-shaped (the opaque Fernet tokens) have no claims.
fn subject_token_carries_cnf(token: &str) -> bool {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .is_none_or(|claims| claims.as_object().is_none_or(|o| o.contains_key("cnf")))
}

/// Upper bound on `audience` values per request; there are far fewer service
/// types than this in any deployment.
const MAX_AUDIENCE_VALUES: usize = 16;

/// Resolve the RFC 8693 `audience` request values (ADR 0036 §7.1) to the
/// `aud` claim: the control-plane default when none was requested, otherwise
/// the narrowing to the requested service types. Each value must be a service
/// type present in the catalog, so no token is minted that no service accepts.
pub(super) async fn requested_audience(
    state: &ServiceState,
    requested: &[String],
) -> Result<Audience, Oauth2TokenError> {
    if requested.is_empty() {
        return Ok(Audience::control_plane());
    }
    if requested.len() > MAX_AUDIENCE_VALUES {
        return Err(Oauth2TokenError::invalid_target("too many audience values"));
    }
    let exec = ExecutionContext::internal(state);
    let known: HashSet<String> = state
        .provider
        .get_catalog_provider()
        .list_services(&exec, &ServiceListParameters::default())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 token exchange audience lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?
        .into_iter()
        .filter(|service| service.enabled)
        .filter_map(|service| service.r#type)
        .collect();
    let mut service_types: Vec<&str> = Vec::new();
    for value in requested {
        if value.is_empty() {
            return Err(Oauth2TokenError::invalid_target(
                "audience must not be empty",
            ));
        }
        if !known.contains(value) {
            return Err(Oauth2TokenError::invalid_target(format!(
                "audience `{value}` is not a known service type"
            )));
        }
        service_types.push(value);
    }
    Ok(Audience::narrowed(&service_types))
}

#[cfg(test)]
mod tests {

    use axum::http::StatusCode;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
    };

    use openstack_keystone_core_types::oauth2_client as provider_types;
    use openstack_keystone_core_types::role::RoleRef;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        confidential_client, dpop_proof, dpop_test_jkt, json_body, ok_key_mock, request,
    };

    use super::subject_token_carries_cnf;
    use crate::oauth2_client::MockOauth2ClientProvider;

    use crate::provider::Provider;

    async fn token_exchange_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            grant_types: vec![provider_types::GrantType::TokenExchange],
            ..confidential_client().await
        }
    }

    async fn exchange_with_app_cred_expiries(
        subject_expires_at: chrono::DateTime<chrono::Utc>,
        app_cred_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> axum::response::Response {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(move |_, _, _, _| {
                Ok(app_cred_delegated_vsc(
                    subject_expires_at,
                    app_cred_expires_at,
                ))
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        api.as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=some-existing-token",
            ))
            .await
            .unwrap()
    }

    fn trust_delegated_vsc() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::identity::UserResponseBuilder;
        use openstack_keystone_core_types::resource::{Domain, Project};
        use openstack_keystone_core_types::trust::Trust;

        let user = UserResponseBuilder::default()
            .id("trustee-1")
            .domain_id("domain-1")
            .enabled(true)
            .name("trustee")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(vec![RoleRef {
                domain_id: None,
                id: "role-1".to_string(),
                name: Some("member".to_string()),
            }])
            .scope(ScopeInfo::Project {
                project: Project {
                    id: "project-1".to_string(),
                    domain_id: "domain-1".to_string(),
                    enabled: true,
                    name: "project".to_string(),
                    ..Default::default()
                },
                project_domain: Domain {
                    id: "domain-1".to_string(),
                    name: "domain".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            })
            .build()
            .unwrap();
        let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Trust {
                trust: Trust {
                    id: "trust-1".to_string(),
                    impersonation: false,
                    project_id: Some("project-1".to_string()),
                    trustor_user_id: "trustor-1".to_string(),
                    trustee_user_id: "trustee-1".to_string(),
                    ..Default::default()
                },
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    openstack_keystone_core_types::auth::UserIdentityInfoBuilder::default()
                        .user_id("trustee-1")
                        .user(user)
                        .user_domain(Domain {
                            id: "domain-1".to_string(),
                            name: "domain".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn app_cred_delegated_vsc(
        subject_expires_at: chrono::DateTime<chrono::Utc>,
        app_cred_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::identity::UserResponseBuilder;
        use openstack_keystone_core_types::resource::{Domain, Project};

        let user = UserResponseBuilder::default()
            .id("user-1")
            .domain_id("domain-1")
            .enabled(true)
            .name("user")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(vec![RoleRef {
                domain_id: None,
                id: "role-1".to_string(),
                name: Some("member".to_string()),
            }])
            .scope(ScopeInfo::Project {
                project: Project {
                    id: "project-1".to_string(),
                    domain_id: "domain-1".to_string(),
                    enabled: true,
                    name: "project".to_string(),
                    ..Default::default()
                },
                project_domain: Domain {
                    id: "domain-1".to_string(),
                    name: "domain".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            })
            .build()
            .unwrap();
        let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential:
                    openstack_keystone_core_types::application_credential::ApplicationCredential {
                        access_rules: None,
                        description: None,
                        expires_at: Some(app_cred_expires_at),
                        id: "app-cred-1".to_string(),
                        name: "app-cred".to_string(),
                        project_id: "project-1".to_string(),
                        roles: vec![],
                        unrestricted: false,
                        user_id: "user-1".to_string(),
                    },
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    openstack_keystone_core_types::auth::UserIdentityInfoBuilder::default()
                        .user_id("user-1")
                        .user(user)
                        .user_domain(Domain {
                            id: "domain-1".to_string(),
                            name: "domain".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .expires_at(subject_expires_at)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    #[tokio::test]
    async fn test_token_exchange_success_issues_signed_jwt_with_app_cred_delegation() {
        let now = chrono::Utc::now();
        let app_cred_expires_at = now + chrono::Duration::seconds(120);
        let subject_expires_at = now + chrono::Duration::seconds(300);
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(move |_, _, _, _| {
                Ok(app_cred_delegated_vsc(
                    subject_expires_at,
                    app_cred_expires_at,
                ))
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=some-existing-token",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        let access_token = body["access_token"].as_str().unwrap();
        let token_parts: Vec<_> = access_token.split('.').collect();
        assert_eq!(token_parts.len(), 3);
        let claims_json = URL_SAFE_NO_PAD.decode(token_parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        let exp = claims["exp"].as_i64().unwrap();
        let iat = claims["iat"].as_i64().unwrap();
        assert_eq!(exp, app_cred_expires_at.timestamp());
        assert_eq!(body["expires_in"].as_i64().unwrap(), exp - iat);
    }

    fn jwt_payload(access_token: &str) -> serde_json::Value {
        use base64::Engine as _;
        let payload = access_token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Run a token-exchange request with `extra` appended to the form body and
    /// a catalog that knows exactly the `compute` and `network` services.
    async fn exchange_with(extra: &str) -> axum::response::Response {
        use openstack_keystone_core_types::catalog::Service;

        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut token_mock = crate::token::MockTokenProvider::default();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        token_mock
            .expect_validate_to_context()
            .returning(move |_, _, _, _| Ok(app_cred_delegated_vsc(expires_at, expires_at)));
        let mut catalog_mock = crate::catalog::MockCatalogProvider::default();
        catalog_mock.expect_list_services().returning(|_, _| {
            Ok(["compute", "network"]
                .into_iter()
                .map(|t| Service {
                    enabled: true,
                    extra: Default::default(),
                    id: format!("svc-{t}"),
                    r#type: Some(t.to_string()),
                })
                .collect())
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_catalog(catalog_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        api.as_service()
            .oneshot(request(&format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=some-existing-token{extra}"
            )))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_token_exchange_default_audience_is_control_plane() {
        let response = exchange_with("").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let claims = jwt_payload(body["access_token"].as_str().unwrap());
        assert_eq!(claims["aud"], "openstack-apis");
    }

    #[tokio::test]
    async fn test_token_exchange_audience_narrows_to_service_types() {
        let response = exchange_with("&audience=compute&audience=network").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let claims = jwt_payload(body["access_token"].as_str().unwrap());
        assert_eq!(
            claims["aud"],
            serde_json::json!(["openstack-apis:compute", "openstack-apis:network"])
        );

        let response = exchange_with("&audience=compute").await;
        let claims = jwt_payload(json_body(response).await["access_token"].as_str().unwrap());
        assert_eq!(claims["aud"], "openstack-apis:compute");
    }

    #[tokio::test]
    async fn test_token_exchange_unknown_audience_is_invalid_target() {
        let response = exchange_with("&audience=compute&audience=nonexistent").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_target");

        // The retired domain-bound form is not a service type either.
        let response = exchange_with("&audience=openstack-apis%3Adomain-1").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_target");

        let response = exchange_with("&audience=").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_target");
    }

    #[tokio::test]
    async fn test_token_exchange_audience_count_is_bounded() {
        let many = (0..=super::MAX_AUDIENCE_VALUES)
            .map(|i| format!("&audience=svc{i}"))
            .collect::<String>();
        let response = exchange_with(&many).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_target");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_trust_delegation() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(|_, _, _, _| Ok(trust_delegated_vsc()));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=some-existing-token",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_missing_subject_token_is_invalid_request() {
        let state2 = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api2 = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state2);

        let response = api2
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_token_exchange_client_without_grant_is_unauthorized() {
        // `confidential_client()` only holds `ClientCredentials`, not
        // `TokenExchange`.
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
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
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_non_delegated_subject_token() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(|_, _, _, _| {
                let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
                    .authentication_context(AuthenticationContext::Password)
                    .principal(PrincipalInfo {
                        identity: IdentityInfo::User(
                            openstack_keystone_core_types::auth::UserIdentityInfoBuilder::default()
                                .user_id("user-1")
                                .build()
                                .unwrap(),
                        ),
                    })
                    .authorization(
                        AuthzInfoBuilder::default()
                            .roles(vec![])
                            .scope(ScopeInfo::Unscoped)
                            .build()
                            .unwrap(),
                    )
                    .build();
                Ok(openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc))
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=a-password-authenticated-token",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_already_expired_app_cred() {
        let now = chrono::Utc::now();
        let response = exchange_with_app_cred_expiries(
            now + chrono::Duration::seconds(300),
            now - chrono::Duration::seconds(60),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_app_cred_expiring_now() {
        // The handler takes its own `now` after this one, so an expiry equal
        // to this `now` always leaves a lifetime <= 0.
        let now = chrono::Utc::now();
        let response =
            exchange_with_app_cred_expiries(now + chrono::Duration::seconds(300), now).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_expired_subject_token() {
        // Still-valid app credential; the subject token expiry is the limit.
        let now = chrono::Utc::now();
        let response = exchange_with_app_cred_expiries(
            now - chrono::Duration::seconds(60),
            now + chrono::Duration::seconds(300),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    const TOKEN_URL: &str = "http://localhost/v4/oauth2/domain-1/token";
    const EXCHANGE_FORM: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=";

    /// A state with DPoP mode `mode` where `validate_to_context` may run
    /// `validations` times.
    async fn dpop_state(
        mode: openstack_keystone_config::DpopMode,
        validations: usize,
    ) -> crate::keystone::ServiceState {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(move |_, _, _| Ok(mode));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .times(validations)
            .returning(|_, _, _, _| {
                let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
                Ok(app_cred_delegated_vsc(expires_at, expires_at))
            });
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_oauth2_key(ok_key_mock());
        let mut config = openstack_keystone_config::Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.oauth2.dpop = mode;
        config.mapping.cluster_salt = Some("dpop-test-salt".to_string().into());
        openstack_keystone_core::api::tests::get_mocked_state_with_config(
            provider, true, None, config,
        )
        .await
    }

    fn exchange_request(
        subject_token: &str,
        proof: Option<String>,
    ) -> axum::http::Request<axum::body::Body> {
        let mut req = request(&format!("{EXCHANGE_FORM}{subject_token}"));
        if let Some(proof) = proof {
            req.headers_mut().insert("DPoP", proof.parse().unwrap());
        }
        req
    }

    async fn fetch_nonce(api: &mut utoipa_axum::router::OpenApiRouter) -> String {
        let response = api
            .as_service()
            .oneshot(exchange_request(
                "tok",
                Some(dpop_proof(TOKEN_URL, "nonce-probe", None)),
            ))
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
    async fn test_exchange_with_proof_issues_bound_token() {
        let state = dpop_state(openstack_keystone_config::DpopMode::Optional, 1).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api).await;

        let response = api
            .as_service()
            .oneshot(exchange_request(
                "tok",
                Some(dpop_proof(TOKEN_URL, "jti-1", Some(&nonce))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(
            jwt_payload(body["access_token"].as_str().unwrap())["cnf"]["jkt"],
            dpop_test_jkt()
        );
    }

    #[tokio::test]
    async fn test_exchange_without_proof_stays_bearer_while_optional() {
        let state = dpop_state(openstack_keystone_config::DpopMode::Optional, 1).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(exchange_request("tok", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        assert!(
            jwt_payload(body["access_token"].as_str().unwrap())
                .get("cnf")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_exchange_without_proof_is_rejected_while_required() {
        // The subject token is never validated: the proof is checked first.
        let state = dpop_state(openstack_keystone_config::DpopMode::Required, 0).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(exchange_request("tok", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn test_dpop_bound_subject_token_is_refused() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let bound = format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"cnf":{"jkt":"abc"}}"#)
        );
        let state = dpop_state(openstack_keystone_config::DpopMode::Disabled, 1).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(exchange_request(&bound, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[test]
    fn test_subject_token_carries_cnf() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let jwt = |payload: &str| format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload));
        assert!(subject_token_carries_cnf(&jwt(r#"{"cnf":{"jkt":"k"}}"#)));
        assert!(!subject_token_carries_cnf(&jwt(r#"{"sub":"u"}"#)));
        assert!(!subject_token_carries_cnf("fernet-looking-opaque-token"));
        assert!(!subject_token_carries_cnf("a.b"));
        // A padded payload is still read.
        let padded = format!("h.{}=.s", URL_SAFE_NO_PAD.encode(r#"{"cnf":{}}"#));
        assert!(subject_token_carries_cnf(&padded));
        // JWT-shaped but unreadable: fail closed.
        assert!(subject_token_carries_cnf("h.!!!.s"));
        assert!(subject_token_carries_cnf(&jwt("not json")));
        assert!(subject_token_carries_cnf(&jwt("[1]")));
    }
}
