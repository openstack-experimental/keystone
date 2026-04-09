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
//! Get available project scopes.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::Value;
use std::collections::HashSet;

use openstack_keystone_core_types::assignment::{AssignmentType, RoleAssignmentListParameters};
use openstack_keystone_core_types::resource::ProjectListParameters;

use crate::api::v3::project::types::ProjectShortList;
use crate::api::{auth::Auth, error::KeystoneApiError};
use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;

/// Get available project scopes.
///
/// This call returns the list of projects that are available to be scoped to
/// based on the X-Auth-Token provided in the request.
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = OK, description = "Project list", body = ProjectShortList),
    ),
    tag="auth"
)]
#[tracing::instrument(
    name = "api::v3::auth::project::list",
    level = "debug",
    skip(state, user_auth)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce("identity/auth/project/list", &user_auth, Value::Null, None)
        .await?;

    let project_ids: HashSet<String> = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some(user_auth.user_id().clone()),
                effective: Some(true),
                include_names: Some(false),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .filter(|assignment| {
            assignment.r#type == AssignmentType::UserProject
                || assignment.r#type == AssignmentType::GroupProject
        })
        .map(|assignment| assignment.target_id.clone())
        .collect();

    Ok((
        StatusCode::OK,
        Json(ProjectShortList {
            projects: if !project_ids.is_empty() {
                state
                    .provider
                    .get_resource_provider()
                    .list_projects(
                        &state,
                        &ProjectListParameters {
                            ids: Some(project_ids),
                            ..Default::default()
                        },
                    )
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect()
            } else {
                vec![]
            },
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
    use std::collections::HashSet;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::resource::{
        Project as ProviderProject, ProjectListParameters,
    };

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::project::types::ProjectShort;
    use crate::assignment::MockAssignmentProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    use super::super::openapi_router;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_ref().is_some_and(|x| x == "bar")
                    && params.effective.is_some_and(|x| x)
                    && params.include_names.is_some_and(|x| !x)
            })
            .returning(|_, _| {
                Ok(vec![
                    Assignment {
                        role_id: "role_id".into(),
                        role_name: Some("rn".into()),
                        actor_id: "user_id".into(),
                        target_id: "p1".into(),
                        r#type: AssignmentType::UserProject,
                        inherited: false,
                        implied_via: None,
                    },
                    Assignment {
                        role_id: "role_id".into(),
                        role_name: Some("rn".into()),
                        actor_id: "group_id".into(),
                        target_id: "p2".into(),
                        r#type: AssignmentType::GroupProject,
                        inherited: false,
                        implied_via: None,
                    },
                    Assignment {
                        role_id: "role_id".into(),
                        role_name: Some("rn".into()),
                        actor_id: "user_id".into(),
                        target_id: "d1".into(),
                        r#type: AssignmentType::UserDomain,
                        inherited: false,
                        implied_via: None,
                    },
                ])
            });
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, params: &ProjectListParameters| {
                params
                    .ids
                    .as_ref()
                    .is_some_and(|x| *x == HashSet::from(["p1".to_string(), "p2".to_string()]))
            })
            .returning(|_, _| {
                Ok(vec![
                    ProviderProject {
                        description: None,
                        domain_id: "did".into(),
                        enabled: true,
                        extra: std::collections::HashMap::new(),
                        id: "p1".into(),
                        name: "p1_name".into(),
                        parent_id: None,
                        is_domain: false,
                    },
                    ProviderProject {
                        description: None,
                        domain_id: "did".into(),
                        enabled: true,
                        extra: std::collections::HashMap::new(),
                        id: "p2".into(),
                        name: "p2_name".into(),
                        parent_id: None,
                        is_domain: false,
                    },
                ])
            });

        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![
                ProjectShort {
                    domain_id: "did".into(),
                    enabled: true,
                    id: "p1".into(),
                    name: "p1_name".into(),
                },
                ProjectShort {
                    domain_id: "did".into(),
                    enabled: true,
                    id: "p2".into(),
                    name: "p2_name".into(),
                },
            ],
            res.projects
        );
    }
}
