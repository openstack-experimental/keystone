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
//! # Set user password
//!
//! Unauthenticated endpoint that validates the original password and sets the
//! new password. The original password serves as authentication.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use secrecy::SecretString;
use validator::Validate;

use crate::api::error::KeystoneApiError;
use crate::api::v3::user::types::UserPasswordRequest;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::UserPasswordAuthRequest;

/// Set or change user password.
///
/// This is an unauthenticated call. The `original_password` field is used to
/// authenticate the user, and upon successful verification the `password` field
/// becomes the new password. If the user is not a local user (i.e., a
/// federated user), a `409 Conflict` is returned.
#[utoipa::path(
    post,
    path = "/{user_id}/password",
    description = "Set or change user password",
    request_body = UserPasswordRequest,
    responses(
        (status = NO_CONTENT, description = "Password changed successfully"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Original password is incorrect"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Password change not supported for nonlocal user"),
        (status = 500, description = "Internal error")
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::change_user_password", level = "debug", skip(state))]
pub(super) async fn change_password(
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<UserPasswordRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let ctx = ExecutionContext::internal(&state);
    let identity = state.provider.get_identity_provider();

    let auth_req = UserPasswordAuthRequest {
        id: Some(user_id.clone()),
        name: None,
        domain: None,
        password: SecretString::clone(&req.user.original_password),
    };

    let _ = identity.authenticate_by_password(&ctx, &auth_req).await?;

    identity
        .update_user_password(
            &ctx,
            &user_id,
            req.user.original_password,
            SecretString::clone(&req.user.password),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::user::types::UserPasswordRequest;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use openstack_keystone_core::auth::AuthenticationResult;
    use openstack_keystone_core::identity::IdentityProviderError;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthenticationResultBuilder, IdentityInfo, PrincipalInfo,
        UserIdentityInfoBuilder,
    };
    use secrecy::SecretString;

    use super::super::types::UserPassword;

    fn make_password_request() -> UserPasswordRequest {
        UserPasswordRequest {
            user: UserPassword {
                original_password: SecretString::from("old"),
                password: SecretString::from("new_secret"),
            },
        }
    }

    fn make_auth_result() -> AuthenticationResult {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("bar")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let auth_result = make_auth_result();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(move |_ctx, _req| Ok(auth_result.clone()));
        identity_mock
            .expect_update_user_password()
            .returning(|_, _, _, _| Ok(()));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
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
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar/password")
                    .body(Body::from(
                        serde_json::to_string(&make_password_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_change_password_wrong_password() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| {
                Err(IdentityProviderError::Authentication {
                    source:
                        openstack_keystone_core::auth::AuthenticationError::UserNameOrPasswordWrong,
                })
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
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
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar/password")
                    .body(Body::from(
                        serde_json::to_string(&make_password_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_change_password_nonlocal_user() {
        let auth_result = make_auth_result();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(move |_ctx, _req| Ok(auth_result.clone()));
        identity_mock
            .expect_update_user_password()
            .returning(|_, _, _, _| {
                Err(IdentityProviderError::Conflict(
                    "cannot update password for nonlocal user".to_string(),
                ))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
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
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar/password")
                    .body(Body::from(
                        serde_json::to_string(&make_password_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_change_password_validation_error() {
        let overlong_password: UserPassword = serde_json::from_str(&format!(
            r#"{{"original_password":"old","password":"{}"}}"#,
            "x".repeat(73)
        ))
        .unwrap();
        let req = UserPasswordRequest {
            user: overlong_password,
        };

        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar/password")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
