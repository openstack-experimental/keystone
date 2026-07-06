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
use serde_json::json;
use validator::Validate;

use super::types::{User, UserResponse, UserUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing user
#[utoipa::path(
    put,
    path = "/{user_id}",
    description = "Update user by ID",
    params(),
    responses(
        (status = OK, description = "Updated user", body = UserResponse),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::update_user", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<UserUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    req.validate()?;

    // Fetch the current user to pass it as existing object into the policy
    // evaluation
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::from_auth(&state, &user_auth), &user_id)
        .await?;

    let existing_user = current.as_ref().map(|c| json!({"user": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/user/update",
            &user_auth,
            json!({"user": req.user.to_policy_input()}),
            existing_user,
        )
        .await?;

    match current {
        Some(_) => {
            let user = state
                .provider
                .get_identity_provider()
                .update_user(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &user_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(UserResponse {
                    user: User::from(user),
                }),
            ))
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::user::types::{
        UserResponse as ApiUserResponse, UserUpdateBuilder as ApiUserUpdate, UserUpdateRequest,
    };
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_update() {
        let mut identity_mock = MockIdentityProvider::default();

        // Mock get_user to return the existing user
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("old_name")
                        .build()
                        .unwrap(),
                ))
            });

        // Mock update_user to return the updated user
        identity_mock
            .expect_update_user()
            .withf(
                |_, id: &'_ str, _: &openstack_keystone_core_types::identity::UserUpdate| {
                    id == "bar"
                },
            )
            .returning(|_, _, _| {
                Ok(UserResponseBuilder::default()
                    .id("bar")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .name("new_name")
                    .build()
                    .unwrap())
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let update_req = UserUpdateRequest {
            user: ApiUserUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let updated_user: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated_user.user.name, "new_name");
        assert_eq!(updated_user.user.id, "bar");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut identity_mock = MockIdentityProvider::default();

        // Mock get_user to return None (user not found)
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let update_req = UserUpdateRequest {
            user: ApiUserUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/missing")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_policy_denied() {
        let mut identity_mock = MockIdentityProvider::default();

        // Mock get_user to return the existing user (called before policy check)
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("old_name")
                        .build()
                        .unwrap(),
                ))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            false, // policy denied
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let update_req = UserUpdateRequest {
            user: ApiUserUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let update_req = UserUpdateRequest {
            user: ApiUserUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar")
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
