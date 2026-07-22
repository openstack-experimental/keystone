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

//! Update role API.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Role, RoleResponse, RoleUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing role
#[utoipa::path(
    patch,
    path = "/{role_id}",
    description = "Update role by ID",
    params(),
    responses(
        (status = OK, description = "Updated role", body = RoleResponse),
        (status = 404, description = "Role not found", example = json!(KeystoneApiError::NotFound{resource: "role".into(), identifier: "id = 1".into()}))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(role_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<RoleUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    // Fetch the current role to pass it as existing object into the policy
    // evaluation
    let current = state
        .provider
        .get_role_provider()
        .get_role(&ExecutionContext::from_auth(&state, &user_auth), &role_id)
        .await?;

    let existing_role = current.as_ref().map(|c| json!({"role": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/role/update",
            &user_auth,
            json!({"role": req.role}),
            existing_role,
        )
        .await?;

    match current {
        Some(_) => {
            let role = state
                .provider
                .get_role_provider()
                .update_role(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &role_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(RoleResponse {
                    role: Role::from(role),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "role".into(),
            identifier: role_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::role::RoleBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::types::*;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_update_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    RoleBuilder::default()
                        .id("foo")
                        .name("old_name")
                        .build()
                        .unwrap(),
                ))
            });
        role_mock
            .expect_update_role()
            .withf(|_, id: &'_ str, _| id == "foo")
            .returning(|_, _, _| {
                Ok(RoleBuilder::default()
                    .id("foo")
                    .name("new_name")
                    .build()
                    .unwrap())
            });

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = RoleUpdateRequest {
            role: RoleUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role.name, "new_name");
        assert_eq!(res.role.id, "foo");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = RoleUpdateRequest {
            role: RoleUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    RoleBuilder::default()
                        .id("foo")
                        .name("old_name")
                        .build()
                        .unwrap(),
                ))
            });

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = RoleUpdateRequest {
            role: RoleUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = RoleUpdateRequest {
            role: RoleUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_update_rejects_put() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"role":{"name":"updated"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
