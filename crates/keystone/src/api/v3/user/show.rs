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

use super::types::{User, UserResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Get single user
#[utoipa::path(
    get,
    path = "/{user_id}",
    params(),
    responses(
        (status = OK, description = "Single user", body = UserResponse),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&state, &user_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(UserResponse {
                user: User::from(current),
            }),
        )),
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
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::user::types::{UserBuilder as ApiUser, UserResponse as ApiUserResponse};
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
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
        let res: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiUser::default()
                .id("bar")
                .domain_id("user_domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap(),
            res.user,
        );
    }
}
