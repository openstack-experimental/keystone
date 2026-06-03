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

//! Check role imply rule existence.

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

/// Check if a role imply rule exists.
#[utoipa::path(
    head,
    path = "/{prior_role_id}/implies/{implied_role_id}",
    operation_id = "/roles/prior_role/implies/implied_role:check",
    params(
        ("prior_role_id" = String, Path, description = "The prior role ID."),
        ("implied_role_id" = String, Path, description = "The implied role ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Role imply rule exists."),
        (status = 404, description = "Role imply rule not found", example = json!({"error": "Not Found"})),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "roles"
)]
#[tracing::instrument(
    name = "api::role_imply_check",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn check(
    Auth(user_auth): Auth,
    Path((prior_role_id, implied_role_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Policy enforcement first
    state
        .policy_enforcer
        .enforce(
            "identity/role/imply_rule/show",
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

    // Check if the imply rule exists
    let exists = state
        .provider
        .get_role_provider()
        .check_role_imply_rule(&state, &prior_role_id, &implied_role_id)
        .await?;

    if exists {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(KeystoneApiError::NotFound {
            resource: "role_imply_rule".into(),
            identifier: format!("{}/{}", prior_role_id, implied_role_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::openapi_router;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_check_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_check_role_imply_rule()
            .withf(|_, prior: &str, implied: &str| prior == "prior_id" && implied == "implied_id")
            .returning(|_, _, _| Ok(true));

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
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
    async fn test_check_not_found() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_check_role_imply_rule()
            .withf(|_, prior: &str, implied: &str| prior == "prior_id" && implied == "implied_id")
            .returning(|_, _, _| Ok(false));

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/prior_id/implies/implied_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_check_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_check_role_imply_rule()
            .returning(|_, _, _| Ok(false));

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
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
    async fn test_check_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/prior_id/implies/implied_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
