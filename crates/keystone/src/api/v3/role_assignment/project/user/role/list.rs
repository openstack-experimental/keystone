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

//! Project user role: list.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use serde_json::json;
use tracing::info;

use crate::api::error::KeystoneApiError;
use crate::api::v3::role::types::{Role, RoleList};
use crate::keystone::ServiceState;
use crate::{
    api::auth::Auth,
    assignment::{AssignmentApi, types::RoleAssignmentListParameters},
    identity::IdentityApi,
    resource::ResourceApi,
};

/// Check whether user has role assignment on project.
///
/// Validates that a user has a role on a project.
#[utoipa::path(
    get,
    path = "/projects/{project_id}/users/{user_id}/roles",
    operation_id = "/project/user/role:list",
    params(
      ("project_id" = String, Path, description = "The project ID."),
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = OK, description = "Roles listed successfully.", body = RoleList),
        (status = FORBIDDEN, description = "User does not have permission to list roles."),
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::project_user_role_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path((project_id, user_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Get project and user for policy enforcement
    let (project, user) = tokio::join!(
        state
            .provider
            .get_resource_provider()
            .get_project(&state, &project_id),
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id)
    );

    let project = project?.ok_or_else(|| {
        info!("Project {} was not found", project_id);
        KeystoneApiError::NotFound {
            resource: "project".into(),
            identifier: project_id.clone(),
        }
    })?;

    let user = user?.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "user".into(),
            identifier: user_id.clone(),
        }
    })?;

    // Enforce policy
    state
        .policy_enforcer
        .enforce(
            "identity/project/user/role/list",
            &user_auth,
            json!({
                "user": user,
                "project": project,
                "target": user  // The user being queried
            }),
            None,
        )
        .await?;

    // Get roles
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        project_id: Some(project_id.clone()),
        effective: Some(true),
        include_names: Some(false),
        ..Default::default()
    };

    let roles: Vec<Role> = state
        .provider
        .get_assignment_provider()
        .list_user_roles_on_project(&state, &query_params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    Ok((StatusCode::OK, Json(RoleList { roles })).into_response())
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

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::{MockAssignmentProvider, types::*};
    use crate::identity::{MockIdentityProvider, types::*};
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Project};
    use crate::role::{MockRoleProvider, types::*};

    #[tokio::test]
    #[traced_test]
    async fn test_list_no_roles_allowed() {
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
            .expect_list_user_roles_on_project()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| Ok(vec![]));

        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        // Policy enforcement allowed
        let state = get_mocked_state(provider_builder, true, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_single_role_allowed() {
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
            .expect_list_user_roles_on_project()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![
                    RoleBuilder::default()
                        .id("role_id")
                        .name("role_name")
                        .build()
                        .unwrap(),
                ])
            });

        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(provider_builder, true, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_multiple_roles_allowed() {
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
            .expect_list_user_roles_on_project()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![
                    RoleBuilder::default()
                        .id("role_id_1")
                        .name("role_name_1")
                        .build()
                        .unwrap(),
                    RoleBuilder::default()
                        .id("role_id_2")
                        .name("role_name_2")
                        .build()
                        .unwrap(),
                    RoleBuilder::default()
                        .id("role_id_3")
                        .name("role_name_3")
                        .build()
                        .unwrap(),
                ])
            });

        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(provider_builder, true, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_policy_forbidden() {
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

        let assignment_mock = MockAssignmentProvider::default();
        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        // Policy enforcement NOT allowed
        let state = get_mocked_state(provider_builder, false, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None));

        let assignment_mock = MockAssignmentProvider::default();
        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(provider_builder, true, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_project_not_found() {
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

        let assignment_mock = MockAssignmentProvider::default();
        let role_mock = MockRoleProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, _| Ok(None));

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(provider_builder, true, None, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
