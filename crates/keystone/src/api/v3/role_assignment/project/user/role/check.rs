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

//! Project user role: get.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::json;
use tracing::info;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::{
    api::auth::Auth,
    assignment::{AssignmentApi, types::RoleAssignmentListParameters},
    identity::IdentityApi,
    resource::ResourceApi,
    role::RoleApi,
};

/// Check whether user has role assignment on project.
///
/// Validates that a user has a role on a project.
#[utoipa::path(
    head,
    path = "/projects/{project_id}/users/{user_id}/roles/{role_id}",
    operation_id = "/project/user/role:check",
    params(
      ("role_id" = String, Path, description = "The user ID."),
      ("project_id" = String, Path, description = "The project ID."),
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Grant is present."),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::project_user_role_check",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn check(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path((project_id, user_id, role_id)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        project_id: Some(project_id.clone()),
        effective: Some(true),
        include_names: Some(false),
        ..Default::default()
    };
    // Use join instead of try_join to have more constant latency preventing timing
    // attacks.
    let (user, role, project, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
        state
            .provider
            .get_role_provider()
            .get_role(&state, &role_id),
        state
            .provider
            .get_resource_provider()
            .get_project(&state, &project_id),
        state
            .provider
            .get_assignment_provider()
            .list_role_assignments(&state, &query_params)
    );
    let user = user?.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    let project = project?.ok_or_else(|| {
        info!("Project {} was not found", project_id);
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

    policy
        .enforce(
            "identity/project/user/role/check",
            &user_auth,
            json!({"user": user, "role": role, "project": project}),
            None,
        )
        .await?;

    let grants: Vec<crate::assignment::types::Assignment> = assignments?.into_iter().collect();

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
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
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
    async fn test_check_found_allowed() {
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
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "project_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });
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
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, true, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_check_found_allowed_no_grant() {
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
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id2".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "project_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });
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
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, true, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
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
    async fn test_check_found_not_allowed() {
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
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "project_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });

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
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, false, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
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
    async fn test_check_user_not_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None));
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| Ok(vec![]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });

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
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, true, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
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
    async fn test_check_project_not_found_allowed() {
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
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| Ok(vec![]));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, _| Ok(None));
        let provider_builder = Provider::mocked_builder()
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, true, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
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
    async fn test_check_role_not_found_allowed() {
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
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id.is_none()
                    && params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| Ok(vec![]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| Ok(None));

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
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .role(role_mock);
        let state = get_mocked_state(provider_builder, true, None);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/projects/project_id/users/user_id/roles/role_id")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
