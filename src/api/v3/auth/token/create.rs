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
//! Create token (authenticate).

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use crate::api::v3::auth::token::common::{authenticate_request, get_authz_info};
use crate::api::v3::auth::token::types::{
    AuthRequest, CreateTokenParameters, Token as ApiResponseToken, TokenResponse,
};
use crate::api::{Catalog, error::KeystoneApiError};
use crate::catalog::CatalogApi;
use crate::keystone::ServiceState;
use crate::token::TokenApi;

/// Authenticate user issuing a new token.
#[utoipa::path(
    post,
    path = "/",
    description = "Issue token",
    params(CreateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(name = "api::v3::token::post", level = "debug", skip(state, req))]
pub(super) async fn create(
    Query(query): Query<CreateTokenParameters>,
    State(state): State<ServiceState>,
    Json(req): Json<AuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let authed_info = authenticate_request(&state, &req).await?;
    let authz_info = get_authz_info(&state, &req).await?;
    if let Some(restriction_id) = &authed_info.token_restriction_id {
        let restriction = state
            .provider
            .get_token_provider()
            .get_token_restriction(&state, restriction_id, true)
            .await?
            .ok_or(KeystoneApiError::InternalError(
                "token restriction {restriction_id} not found".to_string(),
            ))?;
        if !restriction.allow_rescope && req.auth.scope.is_some() {
            return Err(KeystoneApiError::AuthenticationRescopeForbidden);
        }
    }

    let mut token =
        state
            .provider
            .get_token_provider()
            .issue_token(authed_info, authz_info, None)?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await?;

    let mut api_token = TokenResponse {
        token: ApiResponseToken::from_provider_token(&state, &token).await?,
    };
    if !query.nocatalog.is_some_and(|x| x) {
        let catalog: Catalog = state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into();
        api_token.token.catalog = Some(catalog);
    }
    return Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response());
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use crate::api::v3::auth::token::types::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::auth::AuthenticatedInfo;
    use crate::catalog::MockCatalogProvider;
    use crate::config::Config;
    use crate::identity::{
        MockIdentityProvider,
        types::{UserPasswordAuthRequest, UserResponse},
    };
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::resource::{
        MockResourceProvider,
        types::{Domain, Project},
    };
    use crate::token::{MockTokenProvider, ProjectScopePayload, Token as ProviderToken};

    use super::super::openapi_router;

    #[tokio::test]
    #[traced_test]
    async fn test_post() {
        let config = Config::default();
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
        let mut assignment_mock = MockAssignmentProvider::default();
        let mut catalog_mock = MockCatalogProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password == "pass"
                    && req.name == Some("uname".to_string())
            })
            .returning(|_, _| {
                Ok(AuthenticatedInfo::builder()
                    .user_id("uid")
                    .user(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "udid".into(),
                        enabled: true,
                        ..Default::default()
                    })
                    .build()
                    .unwrap())
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
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_issue_token().returning(|_, _, _| {
            Ok(ProviderToken::ProjectScope(ProjectScopePayload {
                user_id: "bar".into(),
                methods: Vec::from(["password".to_string()]),
                user: Some(UserResponse {
                    id: "uid".to_string(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }),
                project_id: "pid".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_populate_role_assignments()
            .returning(|_, _| Ok(()));
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::ProjectScope(ProjectScopePayload {
                    user_id: "bar".into(),
                    methods: Vec::from(["password".to_string()]),
                    user: Some(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "user_domain_id".into(),
                        ..Default::default()
                    }),
                    project_id: "pid".into(),
                    project: Some(Project {
                        id: "pid".into(),
                        domain_id: "pdid".into(),
                        enabled: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .assignment(assignment_mock)
            .catalog(catalog_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(vec!["password"], res.token.methods);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_post_project_disabled() {
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| {
                Ok(AuthenticatedInfo::builder()
                    .user_id("uid")
                    .user(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "udid".into(),
                        enabled: true,
                        ..Default::default()
                    })
                    .build()
                    .unwrap())
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| {
                Ok(Some(Project {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: false,
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
