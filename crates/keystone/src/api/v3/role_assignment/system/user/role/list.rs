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

//! System user role: list.
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

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// List the roles that a user has on the system.
#[utoipa::path(
    get,
    path = "/system/users/{user_id}/roles",
    operation_id = "/system/user/role:list",
    params(
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = OK, description = "List of roles", example = json!([])),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::system_user_role_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        system_id: Some("system".into()),
        effective: Some(false),
        include_names: Some(false),
        resolve_implied_roles: false,
        ..Default::default()
    };

    let (user, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
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

    state
        .policy_enforcer
        .enforce(
            "identity/system/user/role/list",
            &user_auth,
            json!({"user": user}),
            None,
        )
        .await?;

    let assignments = assignments?;
    // Collect to HashSet<Role> to deduplicate, then convert to Vec for API response
    let roles: Vec<Role> = assignments
        .into_iter()
        .map(|a| a.try_into())
        .collect::<Result<std::collections::HashSet<_>, _>>()?
        .into_iter()
        .collect();

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

    use openstack_keystone_api_types::v3::role_assignment::RoleAssignmentRoleList;
    use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;
    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::identity::*;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

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

    fn assignment_mock_empty(mock: &mut MockAssignmentProvider) {
        mock.expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_deref() == Some("user_id")
                    && params.system_id.as_deref() == Some("system")
                    && params.effective == Some(false)
                    && params.include_names == Some(false)
            })
            .returning(|_, _| Ok(vec![]));
    }

    #[tokio::test]
    async fn test_list_success() {
        let mut identity_mock = MockIdentityProvider::default();
        let mut assignment_mock = MockAssignmentProvider::default();

        user_mock(&mut identity_mock);
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
        )
        .await;

        let vsc = test_fixture_scoped();

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/system/users/user_id/roles")
                    .extension(vsc)
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
        let mut assignment_mock = MockAssignmentProvider::default();

        user_mock(&mut identity_mock);
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_assignment(assignment_mock),
            false,
            None,
        )
        .await;

        let vsc = test_fixture_scoped();

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/system/users/user_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/system/users/user_id/roles")
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
            .returning(|_, _| Ok(None));

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock_empty(&mut assignment_mock);

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
        )
        .await;

        let vsc = test_fixture_scoped();

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/system/users/user_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_deduplicates_roles() {
        let mut identity_mock = MockIdentityProvider::default();
        let mut assignment_mock = MockAssignmentProvider::default();

        user_mock(&mut identity_mock);
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_deref() == Some("user_id")
                    && params.system_id.as_deref() == Some("system")
                    && params.effective == Some(false)
                    && params.include_names == Some(false)
            })
            .returning(|_, _| {
                Ok(vec![
                    Assignment {
                        role_id: "role1".into(),
                        role_name: Some("Role1".into()),
                        actor_id: "user_id".into(),
                        target_id: "system".into(),
                        r#type: AssignmentType::UserSystem,
                        inherited: false,
                        implied_via: None,
                    },
                    Assignment {
                        role_id: "role1".into(),
                        role_name: Some("Role1".into()),
                        actor_id: "user_id".into(),
                        target_id: "system".into(),
                        r#type: AssignmentType::UserSystem,
                        inherited: false,
                        implied_via: Some("imply_rule_1".into()),
                    },
                    Assignment {
                        role_id: "role1".into(),
                        role_name: Some("Role1".into()),
                        actor_id: "user_id".into(),
                        target_id: "system".into(),
                        r#type: AssignmentType::UserSystem,
                        inherited: false,
                        implied_via: Some("imply_rule_2".into()),
                    },
                    Assignment {
                        role_id: "role2".into(),
                        role_name: Some("Role2".into()),
                        actor_id: "user_id".into(),
                        target_id: "system".into(),
                        r#type: AssignmentType::UserSystem,
                        inherited: false,
                        implied_via: None,
                    },
                ])
            });

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
        )
        .await;

        let vsc = test_fixture_scoped();

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/system/users/user_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let res: RoleAssignmentRoleList = serde_json::from_slice(&bytes).unwrap();

        // 4 assignments but only 2 unique roles
        assert_eq!(res.roles.len(), 2);
        let role_ids: Vec<_> = res.roles.iter().map(|r| &r.id).collect();
        assert!(role_ids.contains(&&"role1".to_string()));
        assert!(role_ids.contains(&&"role2".to_string()));
    }
}
