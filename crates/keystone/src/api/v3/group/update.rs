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
use validator::Validate;

use super::types::{Group, GroupResponse, GroupUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing group
#[utoipa::path(
    patch,
    path = "/{group_id}",
    description = "Update group by ID",
    params(),
    responses(
        (status = OK, description = "Updated group", body = GroupResponse),
        (status = 404, description = "Group not found", example = json!(KeystoneApiError::NotFound{resource: "group".into(), identifier: "id = 1".into()}))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::update_group", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(group_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<GroupUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    // Fetch the current group to pass it as existing object into the policy
    // evaluation
    let current = state
        .provider
        .get_identity_provider()
        .get_group(&ExecutionContext::from_auth(&state, &user_auth), &group_id)
        .await?;

    let existing_group = current.as_ref().map(|c| json!({"group": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/group/update",
            &user_auth,
            json!({"group": req.group}),
            existing_group,
        )
        .await?;

    match current {
        Some(_) => {
            let group = state
                .provider
                .get_identity_provider()
                .update_group(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &group_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(GroupResponse {
                    group: Group::from(group),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "group".into(),
            identifier: group_id,
        }),
    }
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

    use openstack_keystone_core_types::identity::*;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::group::types::{GroupResponse, GroupUpdateBuilder as ApiGroupUpdate};
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_update_success() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(Group {
                    id: "foo".into(),
                    name: "old_name".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }))
            });
        identity_mock
            .expect_update_group()
            .withf(|_, id: &'_ str, _: &GroupUpdate| id == "foo")
            .returning(|_, _, _| {
                Ok(Group {
                    id: "foo".into(),
                    name: "new_name".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                })
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
            .with_state(state);

        let req = crate::api::v3::group::types::GroupUpdateRequest {
            group: ApiGroupUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.group.name, "new_name");
        assert_eq!(res.group.id, "foo");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::group::types::GroupUpdateRequest {
            group: ApiGroupUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(Group {
                    id: "foo".into(),
                    name: "old_name".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::group::types::GroupUpdateRequest {
            group: ApiGroupUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::group::types::GroupUpdateRequest {
            group: ApiGroupUpdate::default().name("new_name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_update_rejects_put() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/foo")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"group":{"name":"updated"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
