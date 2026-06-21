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

//! Delete role imply rule.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

/// Delete a role imply rule.
#[utoipa::path(
    delete,
    path = "/{prior_role_id}/implies/{implied_role_id}",
    operation_id = "/roles/prior_role/implies/implied_role:delete",
    params(
        ("prior_role_id" = String, Path, description = "The prior role ID."),
        ("implied_role_id" = String, Path, description = "The implied role ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Role imply rule deleted."),
        (status = 404, description = "Role not found", example = json!({"error": "Not Found"})),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "roles"
)]
#[tracing::instrument(
    name = "api::role_imply_delete",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path((prior_role_id, implied_role_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Policy enforcement first
    state
        .policy_enforcer
        .enforce(
            "identity/role/imply_rule/delete",
            &user_auth,
            json!({
                "role_imply_rule": {
                    "prior_role_id": prior_role_id,
                    "implied_role_id": implied_role_id
                }
            }),
            None,
        )
        .await?;

    // Delete the imply rule
    state
        .provider
        .get_role_provider()
        .delete_role_imply_rule(&state, &prior_role_id, &implied_role_id)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use crate::api::tests::{get_mocked_state, mocked_builder, test_fixture_scoped};
    use crate::api::v3::role::openapi_router;

    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_delete_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_delete_role_imply_rule()
            .withf(|_, prior: &str, implied: &str| prior == "prior_id" && implied == "implied_id")
            .returning(|_, _, _| Ok(()));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/prior_id/implies/implied_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_delete_role_imply_rule()
            .returning(|_, _, _| Ok(()));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(mocked_builder().mock_role(role_mock), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/prior_id/implies/implied_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let state = get_mocked_state(mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/prior_id/implies/implied_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
