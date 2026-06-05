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

//! List role imply rules.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::v3::role::{ImplyGroup, RoleImplyListByPrior};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

/// List role imply rules for a prior role.
#[utoipa::path(
    get,
    path = "/{prior_role_id}/implies",
    operation_id = "/roles/prior_role/implies:list",
    params(
        ("prior_role_id" = String, Path, description = "The prior role ID.")
    ),
    responses(
        (status = OK, description = "List of role imply rules.", body = RoleImplyListByPrior),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "roles"
)]
#[tracing::instrument(
    name = "api::role_imply_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(prior_role_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Policy enforcement first
    state
        .policy_enforcer
        .enforce(
            "identity/role/imply_rule/list",
            &user_auth,
            json!({
                "role_imply_rule": {
                    "prior_role_id": prior_role_id
                }
            }),
            None,
        )
        .await?;

    // Get imply rules for this prior role
    let all_rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&state, &prior_role_id)
        .await?;

    // Get the prior role reference from the first match or resolve via get_role
    let prior_role = if let Some(first) = all_rules.first() {
        first.prior_role.clone().into()
    } else {
        let role = state
            .provider
            .get_role_provider()
            .get_role(&state, &prior_role_id)
            .await?;
        if let Some(role) = role {
            let role_ref: openstack_keystone_core_types::role::RoleRef = role.into();
            role_ref.into()
        } else {
            openstack_keystone_api_types::v3::role::RoleRef {
                id: prior_role_id.clone(),
                name: String::new(),
                domain_id: None,
            }
        }
    };

    // Build the implies list
    let implies: Vec<_> = all_rules
        .into_iter()
        .map(|rule| rule.implied_role.into())
        .collect();

    Ok((
        StatusCode::OK,
        Json(RoleImplyListByPrior {
            role_inference: ImplyGroup {
                prior_role,
                implies,
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
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::role::{RoleImplyBuilder, RoleRefBuilder};

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::openapi_router;
    use crate::api::v3::role::types::RoleImplyListByPrior;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_list_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_role_imply_rules_by_prior()
            .withf(|_, prior: &str| prior == "prior_id")
            .returning(|_, _| {
                Ok(vec![
                    RoleImplyBuilder::default()
                        .prior_role(
                            RoleRefBuilder::default()
                                .id("prior_id")
                                .name("Prior")
                                .build()
                                .unwrap(),
                        )
                        .implied_role(
                            RoleRefBuilder::default()
                                .id("implied_id1")
                                .name("Implied1")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                    RoleImplyBuilder::default()
                        .prior_role(
                            RoleRefBuilder::default()
                                .id("prior_id")
                                .name("Prior")
                                .build()
                                .unwrap(),
                        )
                        .implied_role(
                            RoleRefBuilder::default()
                                .id("implied_id2")
                                .name("Implied2")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/prior_id/implies")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleImplyListByPrior = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role_inference.prior_role.id, "prior_id");
        assert_eq!(res.role_inference.implies.len(), 2);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_role_imply_rules_by_prior()
            .returning(|_, _| Ok(vec![]));
        role_mock
            .expect_get_role()
            .withf(|_, id: &str| id == "prior_id")
            .returning(|_, _| {
                Ok(Some(
                    openstack_keystone_core_types::role::RoleBuilder::default()
                        .id("prior_id")
                        .name("Prior")
                        .build()
                        .unwrap(),
                ))
            });

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/prior_id/implies")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleImplyListByPrior = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role_inference.prior_role.id, "prior_id");
        assert_eq!(res.role_inference.prior_role.name, "Prior");
        assert_eq!(res.role_inference.implies.len(), 0);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_role_imply_rules_by_prior()
            .returning(|_, _| Ok(vec![]));

        let vsc = test_fixture_scoped();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_role(role_mock), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/prior_id/implies")
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

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/prior_id/implies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
