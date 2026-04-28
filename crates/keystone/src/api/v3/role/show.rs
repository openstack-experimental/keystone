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
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v3::role::{Role, RoleResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

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
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(role_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_role_provider()
        .get_role(&state, &role_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/role/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(RoleResponse {
                role: Role::from(current),
            }),
        )
            .into_response()),
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
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_get_not_found_not_allowed() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_role(role_mock),
            false,
            None,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
