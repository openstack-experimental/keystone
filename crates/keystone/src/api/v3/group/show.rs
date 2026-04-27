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

use super::types::{Group, GroupResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Get a single user group by ID.
#[utoipa::path(
    get,
    path = "/{group_id}",
    params(),
    responses(
        (status = OK, description = "Group object", body = GroupResponse),
        (status = 404, description = "Group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_get", level = "debug", skip(state))]
pub async fn show(
    Auth(user_auth): Auth,
    Path(group_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_group(&state, &group_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "group".into(),
                identifier: group_id,
            })
        })??;
    state
        .policy_enforcer
        .enforce(
            "identity/group/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(GroupResponse {
            group: Group::from(current),
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

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::{
        api::v3::group::types::{GroupBuilder as ApiGroupBuilder, GroupResponse},
        provider::Provider,
    };
    use openstack_keystone_core_types::identity::*;

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(Group {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
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
                    .header("x-auth-token", "foo")
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
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiGroupBuilder::default()
                .id("bar")
                .name("name")
                .domain_id("did")
                .build()
                .unwrap(),
            res.group,
        );
    }

    #[tokio::test]
    async fn test_get_unauth() {
        let state = crate::api::tests::get_mocked_state(
            crate::provider::Provider::mocked_builder(),
            false,
            None,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/foo").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_not_allowed() {
        let mut identity_mock = MockIdentityProvider::default();

        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(Group {
                    id: "foo".into(),
                    name: "name".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            false,
            None,
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
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
