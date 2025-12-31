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

use utoipa_axum::router::OpenApiRouter;

use crate::api::v3::role_assignment::openapi_router as v3_openapi_router;
use crate::keystone::ServiceState;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    v3_openapi_router()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;

    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::role_assignment::types::{
        Assignment as ApiAssignment, AssignmentList as ApiAssignmentList, Project, Role, Scope,
        User,
    };
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Assignment, AssignmentType, RoleAssignmentListParameters},
    };

    use crate::config::Config;

    use crate::keystone::{Service, ServiceState};
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;

    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    fn get_mocked_state(assignment_mock: MockAssignmentProvider) -> ServiceState {
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

        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .token(token_mock)
            .build()
            .unwrap();

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, _: &RoleAssignmentListParameters| true)
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role".into(),
                    role_name: Some("rn".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });

        let state = get_mocked_state(assignment_mock);

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
        let res: ApiAssignmentList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiAssignment {
                role: Role {
                    id: "role".into(),
                    name: Some("rn".into())
                },
                user: Some(User { id: "actor".into() }),
                scope: Scope::Project(Project {
                    id: "target".into()
                }),
                group: None,
            }],
            res.role_assignments
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, qp: &RoleAssignmentListParameters| {
                RoleAssignmentListParameters {
                    role_id: Some("role".into()),
                    user_id: Some("user1".into()),
                    project_id: Some("project1".into()),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });

        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, qp: &RoleAssignmentListParameters| {
                RoleAssignmentListParameters {
                    role_id: Some("role".into()),
                    user_id: Some("user2".into()),
                    domain_id: Some("domain2".into()),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });

        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, qp: &RoleAssignmentListParameters| {
                RoleAssignmentListParameters {
                    group_id: Some("group3".into()),
                    project_id: Some("project3".into()),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?role.id=role&user.id=user1&scope.project.id=project1")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: ApiAssignmentList = serde_json::from_slice(&body).unwrap();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?role.id=role&user.id=user2&scope.domain.id=domain2")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?group.id=group3&scope.project.id=project3")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
