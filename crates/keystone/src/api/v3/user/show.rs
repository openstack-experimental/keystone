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

use super::types::{User, UserResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get single user
#[utoipa::path(
    get,
    path = "/{user_id}",
    params(),
    responses(
        (status = OK, description = "Single user", body = UserResponse),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::from_auth(&state, &user_auth), &user_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/show",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"user": current})),
        )
        .await?;
    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(UserResponse {
                user: User::from(current),
            }),
        )),
        _ => Err(KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id.clone(),
        }),
    }
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

    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::user::types::{UserBuilder as ApiUser, UserResponse as ApiUserResponse};
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .extension(vsc.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiUser::default()
                .id("bar")
                .domain_id("user_domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap(),
            res.user,
        );
    }

    #[tokio::test]
    async fn test_get_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/bar").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/user/show.rego` decision (via
    /// `get_state_with_real_policy`'s real `opa run` subprocess + the
    /// production `HttpPolicyEnforcer`) through the
    /// authorized(admin)/authorized(reader, same domain)/
    /// unauthorized(no roles)/cross-domain(reader, different domain)
    /// matrix -- the domain-scoped counterpart to
    /// `credential::create`'s delegation-scoped Gate B3 matrix. Requires
    /// `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;
        use openstack_keystone_core_types::auth::{
            AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
            SecurityContext, UserIdentityInfoBuilder,
        };
        use openstack_keystone_core_types::resource::Domain;
        use openstack_keystone_core_types::role::RoleRef;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;

        fn domain_scoped_vsc(caller_domain_id: &str, roles: &[&str]) -> ValidatedSecurityContext {
            let authz = AuthzInfoBuilder::default()
                .scope(ScopeInfo::Domain(Domain {
                    id: caller_domain_id.to_string(),
                    name: caller_domain_id.to_string(),
                    enabled: true,
                    ..Default::default()
                }))
                .roles(
                    roles
                        .iter()
                        .enumerate()
                        .map(|(i, name)| RoleRef {
                            domain_id: None,
                            id: format!("role-{i}"),
                            name: Some((*name).to_string()),
                        })
                        .collect::<Vec<_>>(),
                )
                .build()
                .unwrap();

            let sc = SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("caller")
                            .user(
                                UserResponseBuilder::default()
                                    .id("caller")
                                    .domain_id(caller_domain_id)
                                    .enabled(true)
                                    .name("caller")
                                    .build()
                                    .unwrap(),
                            )
                            .user_domain(Domain {
                                id: caller_domain_id.to_string(),
                                name: caller_domain_id.to_string(),
                                enabled: true,
                                ..Default::default()
                            })
                            .build()
                            .unwrap(),
                    ),
                })
                .authorization(authz)
                .build();
            ValidatedSecurityContext::test_new(sc)
        }

        async fn show_request(vsc: ValidatedSecurityContext, target_domain_id: &str) -> StatusCode {
            let mut identity_mock = MockIdentityProvider::default();
            let target_domain_id = target_domain_id.to_string();
            identity_mock.expect_get_user().returning(move |_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("target")
                        .domain_id(target_domain_id.clone())
                        .enabled(true)
                        .name("target")
                        .build()
                        .unwrap(),
                ))
            });

            let (state, _opa_guard) =
                get_state_with_real_policy(Provider::mocked_builder().mock_identity(identity_mock))
                    .await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            api.as_service()
                .oneshot(
                    Request::builder()
                        .uri("/target")
                        .extension(vsc)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn admin_can_show_user_in_any_domain() {
            let status = show_request(domain_scoped_vsc("domain-a", &["admin"]), "domain-b").await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn reader_can_show_user_in_own_domain() {
            let status = show_request(domain_scoped_vsc("domain-a", &["reader"]), "domain-a").await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn caller_with_no_roles_is_denied() {
            let status = show_request(domain_scoped_vsc("domain-a", &[]), "domain-a").await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// Cross-domain: a reader scoped to `domain-a` must not be able to
        /// view a user whose home domain is `domain-b` -- this is
        /// `identity.domain_matches_domain_scope` itself, exercised through
        /// the real handler and the real policy.
        #[tokio::test]
        async fn reader_cannot_show_user_in_different_domain() {
            let status = show_request(domain_scoped_vsc("domain-a", &["reader"]), "domain-b").await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
