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

//! Get role imply rule.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::v3::role::RoleImplyResponse;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

/// Get a role imply rule.
#[utoipa::path(
    get,
    path = "/{prior_role_id}/implies/{implied_role_id}",
    operation_id = "/roles/prior_role/implies/implied_role:get",
    params(
        ("prior_role_id" = String, Path, description = "The prior role ID."),
        ("implied_role_id" = String, Path, description = "The implied role ID.")
    ),
    responses(
        (status = OK, description = "Role imply rule details.", body = RoleImplyResponse),
        (status = 404, description = "Role imply rule not found", example = json!({"error": "Not Found"})),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "roles"
)]
#[tracing::instrument(
    name = "api::role_imply_get",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn get(
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

    // Get the imply rule
    let role_imply = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &prior_role_id, &implied_role_id)
        .await?
        .ok_or(KeystoneApiError::NotFound {
            resource: "role_imply_rule".into(),
            identifier: format!("{}/{}", prior_role_id, implied_role_id),
        })?;

    Ok((
        StatusCode::OK,
        Json(RoleImplyResponse {
            role_inference: role_imply.into(),
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
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::role::{RoleImplyBuilder, RoleRefBuilder};

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::openapi_router;
    use crate::api::v3::role::types::RoleImplyResponse;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_get_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role_imply_rule()
            .withf(|_, prior: &str, implied: &str| prior == "prior_id" && implied == "implied_id")
            .returning(|_, _, _| {
                Ok(Some(
                    RoleImplyBuilder::default()
                        .prior_role(
                            RoleRefBuilder::default()
                                .id("prior_id")
                                .name("Prior")
                                .build()
                                .unwrap(),
                        )
                        .implied_role(
                            RoleRefBuilder::default()
                                .id("implied_id")
                                .name("Implied")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ))
            });

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
                    .uri("/prior_id/implies/implied_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleImplyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role_inference.prior_role.id, "prior_id");
        assert_eq!(res.role_inference.implied_role.id, "implied_id");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role_imply_rule()
            .withf(|_, prior: &str, implied: &str| prior == "prior_id" && implied == "implied_id")
            .returning(|_, _, _| Ok(None));

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
    async fn test_get_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role_imply_rule()
            .returning(|_, _, _| Ok(None));

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
    async fn test_get_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/prior_id/implies/implied_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
