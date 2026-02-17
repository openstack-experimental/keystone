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
    extract::{Query, State},
    response::IntoResponse,
};

use super::types::{Role, RoleList, RoleListParameters};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

/// List roles
#[utoipa::path(
    get,
    path = "/",
    params(RoleListParameters),
    description = "List roles",
    responses(
        (status = OK, description = "List of roles", body = RoleList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<RoleListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let roles: Vec<Role> = state
        .provider
        .get_role_provider()
        .list_roles(&state, &query.into())
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(RoleList { roles })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`

    use serde_json::json;

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use super::super::tests::get_mocked_state;
    use crate::api::v3::role::types::{
        Role as ApiRole, //GroupCreate as ApiGroupCreate, GroupCreateRequest,
        RoleList,
    };
    use crate::role::{
        MockRoleProvider,
        types::{Role, RoleListParameters},
    };

    use crate::tests::api::get_mocked_state_unauthed;

    #[tokio::test]
    async fn test_list() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![Role {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(role_mock);

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
        let res: RoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiRole {
                id: "1".into(),
                name: "2".into(),
                // for some reason when deserializing missing value appears still as an empty
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.roles
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(role_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain&name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: RoleList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state_unauthed();

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
