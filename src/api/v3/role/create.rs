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
//! # Create role API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{RoleCreate, RoleResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;

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
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<RoleCreate>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload.validate()?;

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
    use serde_json::json;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use super::super::tests::get_mocked_state;
    use crate::api::v3::role::types::{Role as ApiRole, RoleResponse};
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Role, RoleCreate},
    };

    #[tokio::test]
    async fn test_create() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_create_role()
            .withf(|_, role_create: &RoleCreate| {
                role_create.name == "new_role"
                    && role_create.domain_id.as_deref() == Some("domain1")
                    && role_create.description.as_deref() == Some("A new role")
                    && role_create.id.is_none()
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
