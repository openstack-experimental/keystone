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

//! Project user role: put
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
    assignment::{AssignmentApi, types::AssignmentCreate},
    identity::IdentityApi,
    resource::ResourceApi,
};

/// Assign role to group on project
///
/// Assigns a role to a group on a project.
#[utoipa::path(
    put,
    path = "/projects/{project_id}/users/{user_id}/roles/{role_id}",
    operation_id = "/project/user/role:put",
    params(
      ("role_id" = String, Path, description = "The user ID."),
      ("project_id" = String, Path, description = "The project ID."),
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
    name = "api::v3::project_user_role_grant",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn grant(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path((project_id, user_id, role_id)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Use join instead of try_join to have more constant latency preventing timing
    // attacks.
    let (user, role, project) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
        state
            .provider
            .get_assignment_provider()
            .get_role(&state, &role_id),
        state
            .provider
            .get_resource_provider()
            .get_project(&state, &project_id),
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
            "identity/project/user/role/grant",
            &user_auth,
            json!({"user": user, "role": role, "project": project}),
            None,
        )
        .await?;

    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &state,
            AssignmentCreate::user_project(user.id, project.id, role.id, false),
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
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::{MockAssignmentProvider, types::*};
    use crate::identity::{MockIdentityProvider, types::*};

    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Project};

    #[tokio::test]
    #[traced_test]
    async fn test_all_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "user_id".into(),
                    ..Default::default()
                }))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "new_role".into(),
                    ..Default::default()
                }))
            });
        assignment_mock
            .expect_create_grant()
            .withf(|_, params: &AssignmentCreate| {
                params.role_id == "role_id"
                    && params.actor_id == "user_id"
                    && params.target_id == "project_id"
                    && params.r#type == AssignmentType::UserProject
                    && !params.inherited
            })
            .returning(|_, _| {
                Ok(Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "project_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                })
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
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
    async fn test_all_found_not_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "user_id".into(),
                    ..Default::default()
                }))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
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
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, false);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
    async fn test_user_not_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None));
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
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
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
    async fn test_check_project_not_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "user_id".into(),
                    ..Default::default()
                }))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
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
            .returning(|_, _| Ok(None));
        let provider_builder = Provider::mocked_builder()
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
    async fn test_role_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "user_id".into(),
                    ..Default::default()
                }))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
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
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
