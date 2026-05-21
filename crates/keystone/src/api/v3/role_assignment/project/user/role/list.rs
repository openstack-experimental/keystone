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

use openstack_keystone_api_types::v3::role_assignment::{Role, RoleAssignmentRoleList};
use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::{
    api::auth::Auth, assignment::AssignmentApi, identity::IdentityApi, resource::ResourceApi,
};

/// List the roles that a user has on a project.
///
/// List the roles that a user has on a project.
#[utoipa::path(
    get,
    path = "/projects/{project_id}/users/{user_id}/roles",
    operation_id = "/project/user/role:list",
    params(
      ("project_id" = String, Path, description = "The project ID."),
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = OK, description = "List of roles", example = json!([])),
        (status = 404, description = "User or project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
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
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        project_id: Some(project_id.clone()),
        effective: Some(true),
        include_names: Some(false),
        ..Default::default()
    };
    // Use join instead of try_join to have more constant latency preventing timing
    // attacks.
    let (user, project, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
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
    state
        .policy_enforcer
        .enforce(
            "identity/project/user/role/list",
            &user_auth,
            json!({"user": user,  "project": project}),
            None,
        )
        .await?;

    // let grants: Vec<Assignment> = assignments?.into_iter().collect();

    let roles: Vec<Role> = assignments?
        .into_iter()
        .map(|a| a.try_into())
        .collect::<Result<Vec<_>, _>>()?;

    Ok((StatusCode::OK, Json(RoleAssignmentRoleList { roles })).into_response())
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

    use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;
    use openstack_keystone_core_types::identity::*;
    use openstack_keystone_core_types::resource::*;

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn user_mock(mock: &mut MockIdentityProvider) {
        mock.expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("domain_id")
                        .enabled(true)
                        .name("uname")
                        .build()
                        .unwrap(),
                ))
            });
    }

    fn project_mock(mock: &mut MockResourceProvider) {
        mock.expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "domain_id".into(),
                    ..Default::default()
                }))
            });
    }

    fn assignment_mock_empty(mock: &mut MockAssignmentProvider) {
        mock.expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_deref() == Some("user_id")
                    && params.project_id.as_deref() == Some("project_id")
                    && params.effective == Some(true)
                    && params.include_names == Some(false)
            })
            .returning(|_, _| Ok(vec![]));
    }

    #[tokio::test]
    async fn test_list_success() {
        let mut identity_mock = MockIdentityProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        let mut assignment_mock = MockAssignmentProvider::default();

        user_mock(&mut identity_mock);
        project_mock(&mut resource_mock);
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_resource(resource_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
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
    async fn test_list_forbidden() {
        let mut identity_mock = MockIdentityProvider::default();
        let mut resource_mock = MockResourceProvider::default();
        let mut assignment_mock = MockAssignmentProvider::default();

        user_mock(&mut identity_mock);
        project_mock(&mut resource_mock);
        // join! fetches assignments before policy enforcement — mock is required
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_resource(resource_mock)
                .mock_assignment(assignment_mock),
            false, // policy denies
            None,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
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
    async fn test_list_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    // no x-auth-token header
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| Ok(None)); // user not found

        let mut resource_mock = MockResourceProvider::default();
        project_mock(&mut resource_mock);

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_resource(resource_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
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
        user_mock(&mut identity_mock);

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, _| Ok(None)); // project not found

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_resource(resource_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
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
