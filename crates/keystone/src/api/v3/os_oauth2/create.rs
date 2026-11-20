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
//! OAuth2.0 Client Credentials Grant Flow (RFC 6749 §4.4).

use axum::{
    Json,
    extract::{Form, State},
    http::HeaderMap,
    response::IntoResponse,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::api::v3::auth::token::create::create_inner;
use crate::api::v3::auth::token::types::{
    ApplicationCredentialAuth, AuthRequest, AuthRequestInner, CreateTokenParameters, Identity,
};
use crate::api::v3::os_oauth2::types::{OAuth2TokenRequest, OAuth2TokenResponse};
use crate::audit::{CorrelationId, resolve_audit_ip};
use crate::keystone::ServiceState;

/// Extract client_id and client_secret from the `Authorization: Basic` header.
fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, SecretString)> {
    let header = headers.get(axum::http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), SecretString::from(pass.to_string())))
}

/// Issue an OAuth2.0 access token via the client credentials grant.
///
/// `POST /v3/OS-OAUTH2/token`
///
/// Accepts `application/x-www-form-urlencoded` with `grant_type=client_credentials`.
/// Client credentials are accepted via HTTP Basic auth or form body fields.
#[utoipa::path(
    post,
    path = "/",
    description = "Issue OAuth2.0 access token",
    responses(
        (status = OK, description = "OAuth2 token", body = OAuth2TokenResponse),
        (status = BAD_REQUEST, description = "Invalid request or unsupported grant type"),
        (status = UNAUTHORIZED, description = "Client authentication failed"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "OS-OAUTH2"
)]
#[tracing::instrument(
    name = "api::v3::os_oauth2::token::post",
    level = "debug",
    skip(state, form)
)]
pub(super) async fn create(
    CorrelationId(cid): CorrelationId,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    Form(form): Form<OAuth2TokenRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let grant_type = form
        .grant_type
        .as_deref()
        .ok_or(KeystoneApiError::OAuth2InvalidRequest(
            "The parameter grant_type is required.".into(),
        ))?;

    if grant_type != "client_credentials" {
        return Err(KeystoneApiError::OAuth2UnsupportedGrantType(format!(
            "The parameter grant_type '{}' is not supported.",
            grant_type
        )));
    }

    let (client_id, client_secret) = if let Some((id, secret)) = extract_basic_auth(&headers) {
        // Basic auth takes precedence when no client_cert is present,
        // matching the Python behaviour.
        (id, secret)
    } else if let (Some(id), Some(secret)) = (form.client_id, form.client_secret) {
        (id, secret)
    } else {
        return Err(KeystoneApiError::OAuth2InvalidClient(
            "Client authentication failed.".into(),
        ));
    };

    let auth_request = AuthRequest {
        auth: AuthRequestInner {
            identity: Identity {
                methods: vec!["application_credential".to_string()],
                application_credential: Some(ApplicationCredentialAuth {
                    id: Some(client_id),
                    name: None,
                    secret: client_secret,
                    user: None,
                }),
                password: None,
                token: None,
                totp: None,
                extra: Default::default(),
            },
            scope: None,
        },
    };

    let query = CreateTokenParameters {
        nocatalog: Some(true),
    };

    let audit_ip = resolve_audit_ip(&state, &headers, peer_addr).await;

    let mut known_initiator = None;
    let result = create_inner(
        &state,
        query,
        auth_request,
        &headers,
        peer_addr,
        audit_ip,
        &cid,
        &mut known_initiator,
    )
    .await;
    let (vsc, _keystone_response) = result.map_err(|e| match e {
        KeystoneApiError::UnauthorizedNoContext => {
            KeystoneApiError::OAuth2InvalidClient("Client authentication failed.".into())
        }
        other => other,
    })?;

    let access_token = state
        .provider
        .get_token_provider()
        .encode_token(vsc.token()?)?;

    let expires_in = state.config_manager.config.read().await.token.expiration;

    Ok(Json(OAuth2TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in as i64,
    }))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::super::openapi_router;
    use crate::api::error::KeystoneApiError;
    use crate::api::v3::os_oauth2::types::OAuth2TokenResponse;
    use crate::application_credential::MockApplicationCredentialProvider;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::MockTokenProvider;
    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core_types::application_credential::*;
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::resource::{Domain, DomainBuilder, Project};
    use openstack_keystone_core_types::token::ProjectScopePayload;

    /// Build a test state with mocked application credential authentication.
    async fn test_state_with_appcred(
        token_mock: MockTokenProvider,
    ) -> crate::keystone::ServiceState {
        let project = Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let user_domain = Domain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };
        let project_domain = Domain {
            id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };

        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::ApplicationCredential {
                application_credential: ApplicationCredential {
                    id: "app_cred_id".into(),
                    name: "app_cred_name".into(),
                    project_id: "pid".into(),
                    access_rules: None,
                    description: None,
                    expires_at: None,
                    roles: vec![],
                    unrestricted: false,
                    user_id: "uid".into(),
                },
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();

        let mut appcred_mock = MockApplicationCredentialProvider::default();
        appcred_mock
            .expect_authenticate_by_application_credential()
            .returning(move |_, _| Ok(auth.clone()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            use openstack_keystone_core_types::identity::UserResponse;
            Ok(Some(UserResponse {
                id: "uid".into(),
                name: "uname".into(),
                domain_id: "user_domain_id".into(),
                enabled: true,
                default_project_id: None,
                extra: std::collections::HashMap::new(),
                federated: None,
                options: openstack_keystone_core_types::identity::UserOptions::default(),
                password_expires_at: None,
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| Ok(Some(project.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(move |_, _| Ok(Some(user_domain.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(move |_, _| Ok(Some(project_domain.clone())));

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .mock_application_credential(appcred_mock)
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_token(token_mock)
            .build()
            .unwrap();

        Arc::new(
            Service::new(
                ConfigManager::not_watched(Config::default()),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    fn successful_token_mock() -> MockTokenProvider {
        let vsc = {
            use openstack_keystone_core_types::auth::AuthzInfoBuilder;
            use openstack_keystone_core_types::resource::ProjectRefBuilder;
            use openstack_keystone_core_types::role::RoleRefBuilder;
            use openstack_keystone_core_types::token::FernetToken;

            let user_resp = openstack_keystone_core_types::identity::UserResponseBuilder::default()
                .id("uid")
                .name("uname".to_string())
                .domain_id("user_domain_id".to_string())
                .enabled(true)
                .build()
                .unwrap();
            let fernet_payload = ProjectScopePayload {
                user_id: "uid".into(),
                methods: Vec::from(["application_credential".to_string()]),
                project_id: "pid".into(),
                ..Default::default()
            };
            let authz = AuthzInfoBuilder::default()
                .roles(vec![
                    RoleRefBuilder::default()
                        .id("member")
                        .name("member")
                        .build()
                        .unwrap(),
                ])
                .scope(ScopeInfo::Project {
                    project: ProjectRefBuilder::default()
                        .id("pid")
                        .domain_id("pdid")
                        .enabled(true)
                        .name("pname")
                        .build()
                        .unwrap(),
                    project_domain:
                        openstack_keystone_core_types::resource::DomainRefBuilder::default()
                            .id("pdid")
                            .name("pdname")
                            .enabled(true)
                            .build()
                            .unwrap(),
                })
                .build()
                .unwrap();
            let sc = SecurityContext::test_build()
                .authentication_context(AuthenticationContext::ApplicationCredential {
                    application_credential: ApplicationCredential {
                        id: "app_cred_id".into(),
                        name: "app_cred_name".into(),
                        project_id: "pid".into(),
                        access_rules: None,
                        description: None,
                        expires_at: None,
                        roles: vec![],
                        unrestricted: false,
                        user_id: "uid".into(),
                    },
                    token: None,
                })
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("uid")
                            .user(user_resp)
                            .user_domain(
                                DomainBuilder::default()
                                    .id("user_domain_id")
                                    .name("user_domain_name")
                                    .enabled(true)
                                    .build()
                                    .unwrap(),
                            )
                            .build()
                            .unwrap(),
                    ),
                })
                .token(FernetToken::ProjectScope(fernet_payload))
                .authorization(authz)
                .build();
            openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
        };
        let vsc_clone = vsc.clone();
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc_clone.clone()));
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("oauth2-access-token".to_string()));
        token_mock
    }

    fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
        let encoded = BASE64.encode(format!("{client_id}:{client_secret}"));
        format!("Basic {encoded}")
    }

    // --- Success cases ---

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_client_credentials_basic_auth() {
        let state = test_state_with_appcred(successful_token_mock()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        header::AUTHORIZATION,
                        basic_auth_header("app_cred_id", "app_cred_secret"),
                    )
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: OAuth2TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.access_token, "oauth2-access-token");
        assert_eq!(res.token_type, "Bearer");
        assert!(res.expires_in > 0);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_client_credentials_form_body() {
        let state = test_state_with_appcred(successful_token_mock()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=client_credentials&client_id=app_cred_id&client_secret=app_cred_secret",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: OAuth2TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.token_type, "Bearer");
    }

    // --- Validation errors ---

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_missing_grant_type() {
        let state = test_state_with_appcred(MockTokenProvider::default()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        header::AUTHORIZATION,
                        basic_auth_header("app_cred_id", "secret"),
                    )
                    .body(Body::from(""))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_unsupported_grant_type() {
        let state = test_state_with_appcred(MockTokenProvider::default()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=authorization_code"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_missing_credentials() {
        let state = test_state_with_appcred(MockTokenProvider::default()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_oauth2_invalid_credentials() {
        // Use a mock that rejects the credential
        let mut appcred_mock = MockApplicationCredentialProvider::default();
        appcred_mock
            .expect_authenticate_by_application_credential()
            .returning(|_, _| Err(ApplicationCredentialProviderError::AuthenticationFailed));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));

        let provider = Provider::mocked_builder()
            .mock_application_credential(appcred_mock)
            .mock_identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(Config::default()),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        header::AUTHORIZATION,
                        basic_auth_header("bad_id", "bad_secret"),
                    )
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
