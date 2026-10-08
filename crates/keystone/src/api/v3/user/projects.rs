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
use serde_json::json;
use std::collections::HashSet;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::assignment::{AssignmentType, RoleAssignmentListParameters};
use openstack_keystone_core_types::resource::ProjectListParameters;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::project::types::{ProjectShort, ProjectShortList};
use crate::keystone::ServiceState;
use crate::policy::PolicyError;

/// List projects a user has a role assignment on
///
/// Returns the projects on which the user has an effective role assignment,
/// either directly or through a group membership (inherited assignments
/// included). Protected by the dedicated `identity/user/project/list` policy
/// (admin, system reader, domain reader or the user itself).
///
/// # Parameters
/// - `user_auth`: The authentication context of the requester.
/// - `user_id`: The ID of the user whose projects are being listed.
/// - `state`: The shared service state.
///
/// # Returns
/// - `Ok` with a JSON list of projects if successful.
/// - `Err` with a `KeystoneApiError` if the user is not found or an error
///   occurs.
#[utoipa::path(
    get,
    path = "/{user_id}/projects",
    description = "List projects a user has a role assignment on",
    responses(
        (status = OK, description = "List of user projects", body = ProjectShortList),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(
    name = "api::v3::user::projects",
    level = "debug",
    skip(state, user_auth)
)]
pub(super) async fn projects(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let is_self = *user_auth.principal().get_user_id() == user_id;
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/project/list",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"user": current})),
        )
        .await?;
    if current.is_none() {
        return Err(KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id,
        });
    }

    let project_ids: HashSet<String> = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &exec,
            &RoleAssignmentListParameters {
                user_id: Some(user_id),
                effective: Some(true),
                include_names: Some(false),
                resolve_implied_roles: false,
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .filter(|assignment| {
            assignment.r#type == AssignmentType::UserProject
                || assignment.r#type == AssignmentType::GroupProject
        })
        .map(|assignment| assignment.target_id)
        .collect();

    let mut projects: Vec<ProjectShort> = Vec::new();
    if !project_ids.is_empty() {
        let raw_projects = state
            .provider
            .get_resource_provider()
            .list_projects(
                &exec,
                &ProjectListParameters {
                    ids: Some(project_ids),
                    ..Default::default()
                },
            )
            .await?;
        // CVE-2019-19687 / security-model I8: an assignment on a readable
        // user must not reveal a project the caller cannot itself read.
        // A caller listing their own projects is not re-checked: that is the
        // same disclosure as `GET /v3/auth/projects`, and the list policy
        // already refuses delegated callers that are not otherwise allowed.
        for project in raw_projects {
            if is_self {
                projects.push(ProjectShort::from(project));
                continue;
            }
            match state
                .policy_enforcer
                .enforce(
                    "identity/resource/project/show",
                    &user_auth,
                    serde_json::Value::Null,
                    Some(json!({"project": &project})),
                )
                .await
            {
                Ok(_) => projects.push(ProjectShort::from(project)),
                Err(PolicyError::Forbidden(_)) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    Ok((
        StatusCode::OK,
        Json(ProjectShortList {
            projects,
            links: None,
        }),
    )
        .into_response())
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

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::{UserResponse, UserResponseBuilder};
    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_mock_policy, policy_contract,
        test_fixture_scoped,
    };
    use crate::api::v3::project::types::ProjectShortList;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn user() -> UserResponse {
        UserResponseBuilder::default()
            .id("foo")
            .domain_id("user_domain_id")
            .enabled(false)
            .name("name")
            .build()
            .unwrap()
    }

    fn project(id: &str, domain_id: &str) -> ProviderProject {
        ProviderProject {
            domain_id: domain_id.into(),
            enabled: true,
            id: id.into(),
            name: format!("{id}_name"),
            ..Default::default()
        }
    }

    fn assignment(target_id: &str, r#type: AssignmentType) -> Assignment {
        Assignment {
            role_id: "role_id".into(),
            role_name: None,
            actor_id: "foo".into(),
            target_id: target_id.into(),
            r#type,
            inherited: false,
            implied_via: None,
        }
    }

    fn mocked_providers() -> crate::provider::ProviderBuilder {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(Some(user())));
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_deref() == Some("foo") && params.effective == Some(true)
            })
            .returning(|_, _| {
                Ok(vec![
                    assignment("p1", AssignmentType::UserProject),
                    assignment("p2", AssignmentType::GroupProject),
                    assignment("d1", AssignmentType::UserDomain),
                ])
            });
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, params| {
                params
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.len() == 2 && ids.contains("p1") && ids.contains("p2"))
            })
            .returning(|_, _| Ok(vec![project("p1", "did"), project("p2", "other")]));
        Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_assignment(assignment_mock)
            .mock_resource(resource_mock)
    }

    #[tokio::test]
    async fn test_projects() {
        let state = get_mocked_state(mocked_providers(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        let mut ids: Vec<_> = res.projects.into_iter().map(|p| p.id).collect();
        ids.sort();
        assert_eq!(ids, vec!["p1", "p2"], "domain assignments are excluded");
    }

    #[tokio::test]
    async fn test_projects_rechecks_each_project_policy() {
        let (state, policy) = get_capturing_state(mocked_providers()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let calls = policy.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].policy_name, "identity/user/project/list");
        for call in &calls {
            // Both policies are show-shaped: no `target`, stored object under
            // `existing`, and nothing secret-shaped in either document.
            assert_eq!(call.target, serde_json::Value::Null);
            policy_contract::assert_existing_presence(&call.existing, true);
            policy_contract::assert_no_secrets(&call.target);
            policy_contract::assert_no_secrets(call.existing.as_ref().unwrap());
        }
        policy_contract::assert_object_keys(calls[0].existing.as_ref().unwrap(), &["user"]);
        for call in calls.iter().skip(1) {
            assert_eq!(call.policy_name, "identity/resource/project/show");
            policy_contract::assert_object_keys(call.existing.as_ref().unwrap(), &["project"]);
        }
    }

    #[tokio::test]
    async fn test_projects_drops_items_denied_by_show_policy() {
        let mut policy = MockPolicy::default();
        policy
            .expect_enforce()
            .returning(|policy_name, _, _, existing| {
                let hidden = policy_name == "identity/resource/project/show"
                    && existing
                        .as_ref()
                        .and_then(|value| value.pointer("/project/id"))
                        .and_then(serde_json::Value::as_str)
                        == Some("p2");
                if hidden {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                } else {
                    Ok(PolicyEvaluationResult::allowed_admin())
                }
            });
        let state = get_state_with_mock_policy(mocked_providers(), policy).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res.projects.into_iter().map(|p| p.id).collect::<Vec<_>>(),
            vec!["p1"]
        );
    }

    #[tokio::test]
    async fn test_projects_self_skips_per_item_policy() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .domain_id("domain_id")
                    .enabled(true)
                    .name("testuser")
                    .build()
                    .unwrap(),
            ))
        });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![assignment("p1", AssignmentType::UserProject)]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .returning(|_, _| Ok(vec![project("p1", "other")]));
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_assignment(assignment_mock)
                .mock_resource(resource_mock),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/uid/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1, "only the list policy is evaluated");
        assert_eq!(calls[0].policy_name, "identity/user/project/list");
    }

    #[tokio::test]
    async fn test_projects_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// I10: a missing user must go through policy before the 404, so a
    /// caller that is not allowed to read it gets a 403 and can not probe
    /// for user existence.
    #[tokio::test]
    async fn test_projects_missing_user_forbidden_for_unprivileged_caller() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));

        let mut policy = MockPolicy::default();
        policy
            .expect_enforce()
            .returning(|policy_name, _, _, existing| {
                // Mirrors `identity.user.project.list`: with no stored user
                // only an admin passes.
                let user_missing = existing
                    .as_ref()
                    .and_then(|value| value.get("user"))
                    .is_some_and(serde_json::Value::is_null);
                assert_eq!(policy_name, "identity/user/project/list");
                if user_missing {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                } else {
                    Ok(PolicyEvaluationResult::allowed_admin())
                }
            });
        let state = get_state_with_mock_policy(
            Provider::mocked_builder().mock_identity(identity_mock),
            policy,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/missing/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_projects_policy_denied() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user())));
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_projects_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/projects")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
