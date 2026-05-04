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
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{User, UserCreateRequest, UserListParameters, UserResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Create user
#[utoipa::path(
    post,
    path = "/",
    description = "Create new user",
    responses(
        (status = CREATED, description = "New user", body = UserResponse),
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::create_user", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    Query(query): Query<UserListParameters>,
    State(state): State<ServiceState>,
    Json(req): Json<UserCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    req.validate()?;
    state
        .policy_enforcer
        .enforce(
            "identity/user/create",
            &user_auth,
            serde_json::to_value(&req.user)?,
            None,
        )
        .await?;
    let user = state
        .provider
        .get_identity_provider()
        .create_user(&state, req.into())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            user: User::from(user),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::identity::{UserCreate, UserResponseBuilder};

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::user::types::{
        UserCreateBuilder as ApiUserCreate, UserCreateRequest, UserResponse as ApiUserResponse,
    };
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .withf(|_, req: &UserCreate| req.domain_id == "domain" && req.name == "name")
            .returning(|_, req| {
                Ok(UserResponseBuilder::default()
                    .id("bar")
                    .domain_id(req.domain_id.clone())
                    .enabled(true)
                    .name(req.name.clone())
                    .build()
                    .unwrap())
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: ApiUserCreate::default()
                .domain_id("domain")
                .name("name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let created_user: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(created_user.user.name, user.user.name);
    }
}
