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

//! Domain user role: delete.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;

use openstack_keystone_core_types::assignment::{AssignmentBuilder, AssignmentType};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::role_assignment::policy_target;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Revoke role from user on domain
///
/// Remove a role assignment for a user on a domain.
#[utoipa::path(
    delete,
    path = "/domains/{domain_id}/users/{user_id}/roles/{role_id}",
    operation_id = "/domain/user/role:delete",
    params(
      ("domain_id" = String, Path, description = "The domain ID."),
      ("user_id" = String, Path, description = "The user ID."),
      ("role_id" = String, Path, description = "The role ID."),
    ),
    responses(
        (status = 204, description = "Role revoked successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::v3::domain_user_role_revoke",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn revoke(
    Auth(user_auth): Auth,
    Path((domain_id, user_id, role_id)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = &ExecutionContext::from_auth(&state, &user_auth);
    let (domain, user, role) = tokio::join!(
        state
            .provider
            .get_resource_provider()
            .get_domain(exec, &domain_id),
        state
            .provider
            .get_identity_provider()
            .get_user(exec, &user_id),
        state.provider.get_role_provider().get_role(exec, &role_id),
    );
    let domain = domain?;
    let user = user?;
    let role = role?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain/user/role/revoke",
            &user_auth,
            json!({"domain": policy_target(&domain, &domain_id), "user": policy_target(&user, &user_id), "role": policy_target(&role, &role_id)}),
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
    user.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "user".into(),
            identifier: user_id.clone(),
        }
    })?;
    role.ok_or_else(|| {
        info!("Role {} was not found", role_id);
        KeystoneApiError::NotFound {
            resource: "role".into(),
            identifier: role_id.clone(),
        }
    })?;

    let grant = AssignmentBuilder::default()
        .actor_id(user_id)
        .role_id(role_id)
        .target_id(domain_id)
        .r#type(AssignmentType::UserDomain)
        .inherited(false)
        .build()?;

    // Revoking a grant that does not exist is a 404 (parity with Python).
    if !state
        .provider
        .get_assignment_provider()
        .check_grant(exec, &grant)
        .await?
    {
        return Err(KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        });
    }

    state
        .provider
        .get_assignment_provider()
        .revoke_grant(exec, grant)
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

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::DomainBuilder;
    use openstack_keystone_core_types::role::*;

    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::role::MockRoleProvider;

    fn actor_mock(found: bool) -> MockIdentityProvider {
        let mut m = MockIdentityProvider::default();
        m.expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(move |_, _| {
                if found {
                    Ok(Some(
                        UserResponseBuilder::default()
                            .id("user_id")
                            .domain_id("user_domain_id")
                            .enabled(true)
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

    fn role_mock(found: bool) -> MockRoleProvider {
        let mut m = MockRoleProvider::default();
        m.expect_get_role()
            .withf(|_, rid: &'_ str| rid == "role_id")
            .returning(move |_, _| {
                Ok(found.then(|| {
                    RoleBuilder::default()
                        .id("role_id")
                        .name("new_role")
                        .build()
                        .unwrap()
                }))
            });
        m
    }

    fn assignment_mock(present: bool) -> MockAssignmentProvider {
        let mut m = MockAssignmentProvider::default();
        m.expect_check_grant()
            .withf(|_, g: &Assignment| {
                g.actor_id == "user_id"
                    && g.role_id == "role_id"
                    && g.target_id == "domain_id"
                    && g.r#type == AssignmentType::UserDomain
            })
            .returning(move |_, _| Ok(present));
        m
    }

    fn assignment_mock_revoke() -> MockAssignmentProvider {
        let mut m = assignment_mock(true);
        m.expect_revoke_grant()
            .withf(|_, g: &Assignment| {
                g.actor_id == "user_id"
                    && g.role_id == "role_id"
                    && g.target_id == "domain_id"
                    && g.r#type == AssignmentType::UserDomain
            })
            .returning(|_, _| Ok(()));
        m
    }

    #[tokio::test]
    #[traced_test]
    async fn test_revoke_success() {
        let vsc = test_fixture_scoped();
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock_revoke())
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(true)),
        )
        .await;
        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/domain/user/role/revoke");
        policy_contract::assert_object_keys(&calls[0].target, &["domain", "user", "role"]);
        policy_contract::assert_no_secrets(&calls[0].target);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_revoke_grant_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(false))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(true)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
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
    async fn test_revoke_forbidden() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(true))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(true)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
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
    async fn test_revoke_domain_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(false))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(false))
                .mock_role(role_mock(true)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
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
    async fn test_revoke_user_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(false))
                .mock_identity(actor_mock(false))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(true)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
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
    async fn test_revoke_user_not_found_forbidden_hides_existence() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(false))
                .mock_identity(actor_mock(false))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(true)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
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
    async fn test_revoke_role_not_found() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock(false))
                .mock_identity(actor_mock(true))
                .mock_resource(scope_mock(true))
                .mock_role(role_mock(false)),
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
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_revoke_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domains/domain_id/users/user_id/roles/role_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
