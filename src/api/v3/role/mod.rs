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

use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;
use types::{Role, RoleCreate, RoleList, RoleListParameters, RoleResponse};

pub mod types;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show))
}

/// List roles
#[utoipa::path(
    get,
    path = "/",
    params(RoleListParameters),
    description = "List roles",
    responses(
        (status = OK, description = "List of roles", body = RoleList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_list", level = "debug", skip(state))]
async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<RoleListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let roles: Vec<Role> = state
        .provider
        .get_assignment_provider()
        .list_roles(&state, &query.into())
        .await
        .map_err(KeystoneApiError::assignment)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(RoleList { roles })
}

/// Get single role
#[utoipa::path(
    get,
    path = "/{role_id}",
    description = "Get role by ID",
    params(),
    responses(
        (status = OK, description = "Role object", body = RoleResponse),
        (status = 404, description = "Role not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_get", level = "debug", skip(state))]
async fn show(
    Auth(user_auth): Auth,
    Path(role_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_assignment_provider()
        .get_role(&state, &role_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "role".into(),
                identifier: role_id,
            })
        })?
}

/// Create Role
#[utoipa::path(
    post,
    path = "/",
    request_body = RoleCreate,
    description = "Create a new role",
    responses(
        (status = CREATED, description = "Role created", body = RoleResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_create", level = "debug", skip(state))]
async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<RoleCreate>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload
        .validate()
        .map_err(|e| KeystoneApiError::BadRequest(e.to_string()))?;

    // Create the role
    let created_role = state
        .provider
        .get_assignment_provider()
        .create_role(&state, payload.into())
        .await
        .map_err(KeystoneApiError::assignment)?;

    // Return response with 201 Created status
    Ok((
        StatusCode::CREATED,
        Json(RoleResponse {
            role: created_role.into(),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::role::types::{
        Role as ApiRole, //GroupCreate as ApiGroupCreate, GroupCreateRequest,
        RoleList,
        RoleResponse,
    };
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Role, RoleCreate, RoleListParameters},
    };

    use crate::config::Config;

    use crate::keystone::{Service, ServiceState};
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;

    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    use crate::tests::api::get_mocked_state_unauthed;

    fn get_mocked_state(assignment_mock: MockAssignmentProvider) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_token()
            .returning(|_, _, _, _, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .token(token_mock)
            .build()
            .unwrap();

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![Role {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiRole {
                id: "1".into(),
                name: "2".into(),
                // for some reason when deserializing missing value appears still as an empty
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.roles
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain&name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: RoleList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state_unauthed();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        assignment_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "bar".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiRole {
                id: "bar".into(),
                extra: Some(json!({})),
                ..Default::default()
            },
            res.role,
        );
    }

    #[tokio::test]
    async fn test_create() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_create_role()
            .withf(|_, role_create: &RoleCreate| {
                role_create.name == "new_role"
                    && role_create.domain_id.as_deref() == Some("domain1")
                    && role_create.description.as_deref() == Some("A new role")
            })
            .returning(|_, _| {
                Ok(Role {
                    id: "new_role_id".into(),
                    name: "new_role".into(),
                    domain_id: Some("domain1".into()),
                    description: Some("A new role".into()),
                    ..Default::default()
                })
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let payload = json!({
            "id": "",
            "name": "new_role",
            "domain_id": "domain1",
            "description": "A new role",
            "extra": {}
        });

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiRole {
                id: "new_role_id".into(),
                name: "new_role".into(),
                domain_id: Some("domain1".into()),
                description: Some("A new role".into()),
                extra: Some(json!({}))
            },
            res.role,
        );
    }
}
