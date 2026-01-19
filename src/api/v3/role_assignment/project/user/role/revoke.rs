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

//! Project user role: delete

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
    assignment::{AssignmentApi, types::AssignmentRevoke},
    identity::IdentityApi,
    resource::ResourceApi,
};

/// Revoke role from user on project
///
/// Remove a role assignment for a user on a specific project.
#[utoipa::path(
    delete,
    path = "/projects/{project_id}/users/{user_id}/roles/{role_id}",
    operation_id = "/project/user/role:delete",
    params(
        ("role_id" = String, Path, description = "The role ID."),
        ("project_id" = String, Path, description = "The project ID."),
        ("user_id" = String, Path, description = "The user ID."),
    ),
    responses(
        (status = 204, description = "Role revoked successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(
        ("X-Auth-Token" = [])),
    tag="Role Assignment"
)]
#[tracing::instrument(
    name = "api::v3:project_user_role_revoke",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]

pub(super) async fn revoke(
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
            .get_project(&state, &project_id)
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

    state
        .provider
        .get_assignment_provider()
        .revoke_grant(
            &state,
            AssignmentRevoke::user_project(user.id, project.id, role.id, false),
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

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::{MockAssignmentProvider, types::*};
    use crate::identity::{MockIdentityProvider, types::*};
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Project};

    #[tokio::test]
    #[traced_test]
    async fn test_revoke_success() {
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
                    name: "test_role".into(),
                    ..Default::default()
                }))
            });
        assignment_mock
            .expect_revoke_grant()
            .withf(|_, grant: &AssignmentRevoke| {
                grant.role_id == "role_id"
                    && grant.actor_id == "user_id"
                    && grant.target_id == "project_id"
                    && grant.r#type == AssignmentType::UserProject
                    && !grant.inherited
            })
            .returning(|_, _| Ok(()));

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
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
    async fn test_revoke_forbidden() {
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
                    name: "test_role".into(),
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
        let state = get_mocked_state(provider_builder, false); // Policy NOT allowed
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
    async fn test_revoke_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None)); // User not found

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "role_id".into(),
                    name: "test_role".into(),
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
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
    async fn test_revoke_project_not_found() {
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
                    name: "test_role".into(),
                    ..Default::default()
                }))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, _| Ok(None)); // Project not found

        let provider_builder = Provider::mocked_builder()
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
    async fn test_revoke_role_not_found() {
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
            .returning(|_, _| Ok(None)); // Role not found

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
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
