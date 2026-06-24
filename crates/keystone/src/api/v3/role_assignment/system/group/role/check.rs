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

//! System group role: get.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;

use openstack_keystone_core_types::assignment::Assignment;
use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::{api::auth::Auth, assignment::AssignmentApi, identity::IdentityApi, role::RoleApi};

/// Check whether group has role assignment on system.
///
/// Validates that a group has a role on the system.
#[utoipa::path(
    head,
    path = "/system/groups/{group_id}/roles/{role_id}",
    operation_id = "/system/group/role:check",
    params(
      ("role_id" = String, Path, description = "The role ID."),
      ("group_id" = String, Path, description = "The group ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Grant is present."),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::system_group_role_check",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn check(
    Auth(user_auth): Auth,
    Path((group_id, role_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        group_id: Some(group_id.clone()),
        system_id: Some("system".into()),
        effective: Some(true),
        include_names: Some(false),
        resolve_implied_roles: false,
        ..Default::default()
    };
    let (group, role, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_group(&state, &group_id),
        state
            .provider
            .get_role_provider()
            .get_role(&state, &role_id),
        state
            .provider
            .get_assignment_provider()
            .list_role_assignments(&state, &query_params)
    );
    let group = group?.ok_or_else(|| {
        info!("Group {} was not found", group_id);
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
            "identity/system/group/role/check",
            &user_auth,
            json!({"group": group, "role": role}),
            None,
        )
        .await?;

    let grants: Vec<Assignment> = assignments?.into_iter().collect();

    if grants.into_iter().any(|x| x.role_id == role_id) {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
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
    use tracing_test::traced_test;

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::GroupBuilder as CoreGroupBuilder;
    use openstack_keystone_core_types::role::*;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    #[traced_test]
    async fn test_check_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "group_id")
            .returning(|_, _| {
                Ok(Some(
                    CoreGroupBuilder::default()
                        .id("group_id")
                        .domain_id("group_domain_id")
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.group_id.as_ref().is_some_and(|x| x == "group_id")
                    && params.system_id.as_ref().is_some_and(|x| x == "system")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "group_id".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::GroupSystem,
                    inherited: false,
                    implied_via: None,
                }])
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

        let provider_builder = Provider::mocked_builder()
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
                    .method("HEAD")
                    .uri("/system/groups/group_id/roles/role_id")
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
    async fn test_check_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "group_id")
            .returning(|_, _| {
                Ok(Some(
                    CoreGroupBuilder::default()
                        .id("group_id")
                        .domain_id("group_domain_id")
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.group_id.as_ref().is_some_and(|x| x == "group_id")
                    && params.system_id.as_ref().is_some_and(|x| x == "system")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| Ok(vec![]));

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

        let provider_builder = Provider::mocked_builder()
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
                    .method("HEAD")
                    .uri("/system/groups/group_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_check_not_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "group_id")
            .returning(|_, _| {
                Ok(Some(
                    CoreGroupBuilder::default()
                        .id("group_id")
                        .domain_id("group_domain_id")
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.group_id.as_ref().is_some_and(|x| x == "group_id")
                    && params.system_id.as_ref().is_some_and(|x| x == "system")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "group_id".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::GroupSystem,
                    inherited: false,
                    implied_via: None,
                }])
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

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
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
                    .method("HEAD")
                    .uri("/system/groups/group_id/roles/role_id")
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
    async fn test_check_group_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "group_id")
            .returning(|_, _| Ok(None));

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.system_id.as_ref().is_some_and(|x| x == "system")
            })
            .returning(|_, _| Ok(vec![]));

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

        let provider_builder = Provider::mocked_builder()
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
                    .method("HEAD")
                    .uri("/system/groups/group_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
