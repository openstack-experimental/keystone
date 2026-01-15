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
//! Get available project scopes

use axum::{extract::State, response::IntoResponse};
use mockall_double::double;
use serde_json::Value;
use std::collections::HashSet;

use crate::api::v3::project::types::ProjectShortList;
use crate::api::{auth::Auth, error::KeystoneApiError};
use crate::assignment::{
    AssignmentApi,
    types::{AssignmentType, RoleAssignmentListParameters},
};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::resource::{ResourceApi, types::ProjectListParameters};

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
    skip(state, user_auth, policy)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
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

    Ok(ProjectShortList {
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
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use crate::api::v3::project::types::ProjectShort;
    use crate::assignment::{MockAssignmentProvider, types::*};
    use crate::config::Config;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyError, PolicyEvaluationResult};
    use crate::provider::{Provider, ProviderBuilder};
    use crate::resource::{
        MockResourceProvider,
        types::{Project as ProviderProject, ProjectListParameters},
    };
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    use super::super::openapi_router;
    use super::*;

    pub(super) fn get_mocked_state(
        provider_builder: ProviderBuilder,
        policy_allowed: bool,
    ) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });

        let provider = provider_builder.token(token_mock).build().unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        if policy_allowed {
            policy_factory_mock.expect_instantiate().returning(move || {
                let mut policy_mock = MockPolicy::default();
                policy_mock
                    .expect_enforce()
                    .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
                Ok(policy_mock)
            });
        } else {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock.expect_enforce().returning(|_, _, _, _| {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                });
                Ok(policy_mock)
            });
        }
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                policy_factory_mock,
            )
            .unwrap(),
        )
    }

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
                        extra: None,
                        id: "p1".into(),
                        name: "p1_name".into(),
                        parent_id: None,
                        is_domain: false,
                    },
                    ProviderProject {
                        description: None,
                        domain_id: "did".into(),
                        enabled: true,
                        extra: None,
                        id: "p2".into(),
                        name: "p2_name".into(),
                        parent_id: None,
                        is_domain: false,
                    },
                ])
            });

        let provider_builder = Provider::mocked_builder()
            .assignment(assignment_mock)
            .resource(resource_mock);
        let state = get_mocked_state(provider_builder, true);

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
