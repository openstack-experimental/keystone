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

//! Domain group role: list.
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
use crate::api::v3::role_assignment::policy_target;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List the roles that a group has on a domain.
#[utoipa::path(
    get,
    path = "/domains/{domain_id}/groups/{group_id}/roles",
    operation_id = "/domain/group/role:list",
    params(
      ("domain_id" = String, Path, description = "The domain ID."),
      ("group_id" = String, Path, description = "The group ID."),
    ),
    responses(
        (status = OK, description = "List of roles", example = json!([])),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Domain or group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::v3::domain_group_role_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path((domain_id, group_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        group_id: Some(group_id.clone()),
        domain_id: Some(domain_id.clone()),
        effective: Some(false),
        include_names: Some(false),
        resolve_implied_roles: false,
        ..Default::default()
    };
    let exec = &ExecutionContext::from_auth(&state, &user_auth);

    let (domain, group) = tokio::join!(
        state
            .provider
            .get_resource_provider()
            .get_domain(exec, &domain_id),
        state
            .provider
            .get_identity_provider()
            .get_group(exec, &group_id),
    );
    let domain = domain?;
    let group = group?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain/group/role/list",
            &user_auth,
            json!({"domain": policy_target(&domain, &domain_id), "group": policy_target(&group, &group_id)}),
            None,
        )
        .await?;

    domain.ok_or_else(|| {
        info!("Domain {} was not found", domain_id);
        KeystoneApiError::NotFound {
            resource: "domain".into(),
            identifier: domain_id.clone(),
        }
    })?;
    group.ok_or_else(|| {
        info!("Group {} was not found", group_id);
        KeystoneApiError::NotFound {
            resource: "group".into(),
            identifier: group_id.clone(),
        }
    })?;

    // Query assignments only once the caller is authorized.
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(exec, &query_params)
        .await?;
    // Collect to HashSet<Role> to deduplicate, then sort by id for a stable
    // response order.
    let mut roles: Vec<Role> = assignments
        .into_iter()
        .map(|a| a.try_into())
        .collect::<Result<std::collections::HashSet<_>, _>>()?
        .into_iter()
        .collect();
    roles.sort_by(|a, b| a.id.cmp(&b.id));

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
    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::GroupBuilder;
    use openstack_keystone_core_types::resource::DomainBuilder;

    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn actor_mock(found: bool) -> MockIdentityProvider {
        let mut m = MockIdentityProvider::default();
        m.expect_get_group()
            .withf(|_, id: &'_ str| id == "group_id")
            .returning(move |_, _| {
                if found {
                    Ok(Some(
                        GroupBuilder::default()
                            .id("group_id")
                            .domain_id("group_domain_id")
                            .name("name")
                            .build()
                            .unwrap(),
                    ))
                } else {
                    Ok(None)
                }
            });
        m
    }

    fn scope_mock(found: bool) -> MockResourceProvider {
        let mut m = MockResourceProvider::default();
        m.expect_get_domain()
            .withf(|_, id: &'_ str| id == "domain_id")
            .returning(move |_, _| {
                if found {
                    Ok(Some(
                        DomainBuilder::default()
                            .id("domain_id")
                            .name("name")
                            .enabled(true)
                            .build()
                            .unwrap(),
                    ))
                } else {
                    Ok(None)
                }
            });
        m
    }

    fn assignment_mock(roles: &[&str]) -> MockAssignmentProvider {
        let roles: Vec<String> = roles.iter().map(|x| x.to_string()).collect();
        let mut m = MockAssignmentProvider::default();
        m.expect_list_role_assignments()
            .withf(|_, p: &RoleAssignmentListParameters| {
                p.group_id.as_deref() == Some("group_id")
                    && p.domain_id.as_deref() == Some("domain_id")
                    && p.effective == Some(false)
            })
            .returning(move |_, _| {
                Ok(roles
                    .iter()
                    .map(|r| Assignment {
                        role_id: r.clone(),
                        role_name: None,
                        actor_id: "group_id".into(),
                        target_id: "domain_id".into(),
                        r#type: AssignmentType::GroupDomain,
                        inherited: false,
                        implied_via: None,
                    })
                    .collect())
            });
        m
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_success() {
        let vsc = test_fixture_scoped();
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(&["b", "a", "b"]))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true)),
        )
        .await;
        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/domains/domain_id/groups/group_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let res: RoleAssignmentRoleList = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<_> = res.roles.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/domain/group/role/list");
        policy_contract::assert_object_keys(&calls[0].target, &["domain", "group"]);
        policy_contract::assert_no_secrets(&calls[0].target);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_forbidden() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(&["a"]))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true)),
            false,
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
                    .uri("/domains/domain_id/groups/group_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_domain_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(&[]))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(false)),
            true,
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
                    .uri("/domains/domain_id/groups/group_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_group_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(&[]))
                .mock_identity(actor_mock(false))
                .mock_resource(scope_mock(true)),
            true,
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
                    .uri("/domains/domain_id/groups/group_id/roles")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
                    .uri("/domains/domain_id/groups/group_id/roles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
