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
    extract::{Path, State},
    response::IntoResponse,
};

use super::types::RoleResponse;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;

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
    use crate::assignment::{MockAssignmentProvider, types::Role};

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
}
