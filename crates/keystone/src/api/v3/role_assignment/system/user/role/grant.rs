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

//! System user role: put.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;

use openstack_keystone_core_types::assignment::AssignmentCreate;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::{api::auth::Auth, assignment::AssignmentApi, identity::IdentityApi, role::RoleApi};

/// Assign role to user on system
///
/// Assigns a role to a user on the system.
#[utoipa::path(
    put,
    path = "/system/users/{user_id}/roles/{role_id}",
    operation_id = "/system/user/role:put",
    params(
        ("role_id" = String, Path, description = "The role ID."),
        ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Grant is created."),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::v3::system_user_role_grant",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn grant(
    Auth(user_auth): Auth,
    Path((user_id, role_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let (user, role) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
        state
            .provider
            .get_role_provider()
            .get_role(&state, &role_id),
    );
    let user = user?.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    let role = role?.ok_or_else(|| {
        info!("Role {} was not found", role_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;

    state
        .policy_enforcer
        .enforce(
            "identity/system/user/role/grant",
            &user_auth,
            json!({"user": user, "role": role}),
            None,
        )
        .await?;

    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &state,
            AssignmentCreate::user_system(user.id, "system", role.id, false),
        )
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
    use tracing_test::traced_test;

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::*;
    use openstack_keystone_core_types::role::*;

    use crate::api::tests::{get_mocked_state, mocked_builder, test_fixture_scoped};
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;

    use crate::role::MockRoleProvider;

    #[tokio::test]
    #[traced_test]
    async fn test_all_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_create_grant()
            .withf(|_, params: &AssignmentCreate| {
                params.role_id == "role_id"
                    && params.actor_id == "user_id"
                    && params.target_id == "system"
                    && params.r#type == AssignmentType::UserSystem
                    && !params.inherited
            })
            .returning(|_, _| {
                Ok(Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                    implied_via: None,
                })
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(
                    RoleBuilder::default()
                        .id("role_id")
                        .name("new_role")
                        .build()
                        .unwrap(),
                ))
            });

        let provider_builder = mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_role(role_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider_builder, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/system/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_all_found_not_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(
                    RoleBuilder::default()
                        .id("role_id")
                        .name("new_role")
                        .build()
                        .unwrap(),
                ))
            });

        let provider_builder = mocked_builder()
            .mock_identity(identity_mock)
            .mock_role(role_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider_builder, false, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/system/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_user_not_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(
                    RoleBuilder::default()
                        .id("role_id")
                        .name("new_role")
                        .build()
                        .unwrap(),
                ))
            });

        let provider_builder = mocked_builder()
            .mock_identity(identity_mock)
            .mock_role(role_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider_builder, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/system/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_role_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| Ok(None));

        let provider_builder = mocked_builder()
            .mock_identity(identity_mock)
            .mock_role(role_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider_builder, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/system/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
