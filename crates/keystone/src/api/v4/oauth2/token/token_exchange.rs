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

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use governor::clock::Clock as _;

use openstack_keystone_core_types::oauth2_client::GrantType;

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

    let (vsc, delegation_context) =
        openstack_keystone_core::oauth2_client::validate_subject_token(state, &subject_token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 token exchange subject_token rejected");
                Oauth2TokenError::invalid_grant(
                    "subject_token is invalid, expired, or carries no exchangeable delegation",
                )
            })?;

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = openstack_keystone_core::oauth2_client::build_token_exchange_claims(
        &client,
        &vsc,
        delegation_context,
        &issuer,
        jti,
        now,
        now + access_lifetime,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "oauth2 token exchange claim construction failed");
        match e {
            openstack_keystone_core::oauth2_client::TokenExchangeError::CrossDomainSubjectToken => {
                Oauth2TokenError::invalid_grant(
                    "subject_token's scope belongs to a different domain than this token endpoint",
                )
            }
            _ => Oauth2TokenError::internal("token issuance failed"),
        }
    })?;
    let access_token = sign_jwt(state, domain_id, &claims).await?;

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_vsc(&vsc),
        &client_id,
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: "openstack:api".to_string(),
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {

    use axum::http::StatusCode;

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
        confidential_client, json_body, ok_key_mock, request,
    };

    use crate::oauth2_client::MockOauth2ClientProvider;

    use crate::provider::Provider;

    async fn token_exchange_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            grant_types: vec![provider_types::GrantType::TokenExchange],
            ..confidential_client().await
        }
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

    fn app_cred_delegated_vsc() -> openstack_keystone_core::auth::ValidatedSecurityContext {
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
                        expires_at: None,
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
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    #[tokio::test]
    async fn test_token_exchange_success_issues_signed_jwt_with_app_cred_delegation() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(|_, _, _, _| Ok(app_cred_delegated_vsc()));

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
        assert_eq!(access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_trust_delegation() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
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
}
