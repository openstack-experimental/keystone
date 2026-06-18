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

//! Role inferences (imply rules) global API.

use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_api_types::v3::role::{ImplyGroup, RoleInferencesList};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

/// List all role inference rules.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/role_inferences:list",
    responses(
        (status = OK, description = "List of all role inference rules.", body = RoleInferencesList),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "roles"
)]
#[tracing::instrument(
    name = "api::role_inferences_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Policy enforcement first
    state
        .policy_enforcer
        .enforce("identity/role/imply_rule/list", &user_auth, json!({}), None)
        .await?;

    // Get all imply rules
    let all_rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    // Group rules by prior role to build ImplyGroup entries
    let mut groups: HashMap<
        String,
        (
            openstack_keystone_api_types::v3::role::RoleRef,
            Vec<openstack_keystone_api_types::v3::role::RoleRef>,
        ),
    > = HashMap::new();
    for rule in all_rules {
        let prior: openstack_keystone_api_types::v3::role::RoleRef = rule.prior_role.into();
        let implied: openstack_keystone_api_types::v3::role::RoleRef = rule.implied_role.into();
        let entry = groups
            .entry(prior.id.clone())
            .or_insert_with(|| (prior.clone(), Vec::new()));
        entry.0 = prior;
        entry.1.push(implied);
    }

    let role_inferences: Vec<ImplyGroup> = groups
        .into_values()
        .map(|(prior_role, implies)| ImplyGroup {
            prior_role,
            implies,
        })
        .collect();

    Ok((StatusCode::OK, Json(RoleInferencesList { role_inferences })).into_response())
}

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(list))
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

    use super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::types::RoleInferencesList;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;

    #[tokio::test]
    async fn test_list_success() {
        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_role_imply_rules().returning(|_| {
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
                            .id("prior_id2")
                            .name("Prior2")
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
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleInferencesList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role_inferences.len(), 2);

        let group1 = res
            .role_inferences
            .iter()
            .find(|g| g.prior_role.id == "prior_id")
            .unwrap();
        assert_eq!(group1.prior_role.name, "Prior");
        assert_eq!(group1.implies.len(), 1);
        assert_eq!(group1.implies[0].id, "implied_id1");
        assert_eq!(group1.implies[0].name, "Implied1");

        let group2 = res
            .role_inferences
            .iter()
            .find(|g| g.prior_role.id == "prior_id2")
            .unwrap();
        assert_eq!(group2.prior_role.name, "Prior2");
        assert_eq!(group2.implies.len(), 1);
        assert_eq!(group2.implies[0].id, "implied_id2");
        assert_eq!(group2.implies[0].name, "Implied2");
    }

    #[tokio::test]
    async fn test_list_empty() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_role_imply_rules()
            .returning(|_| Ok(vec![]));

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
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleInferencesList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role_inferences.len(), 0);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_role_imply_rules()
            .returning(|_| Ok(vec![]));

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
                    .uri("/")
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
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
