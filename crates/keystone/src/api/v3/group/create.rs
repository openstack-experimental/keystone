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
use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};

use super::types::{Group, GroupCreateRequest, GroupResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Create new user group.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Group object", body = GroupResponse),
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::create_group", level = "debug", skip(state))]
#[debug_handler]
pub async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<GroupCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let res = state
        .provider
        .get_identity_provider()
        .create_group(&state, req.into())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(GroupResponse {
            group: Group::from(res),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::{
        api::v3::group::types::{
            GroupCreateBuilder as ApiGroupCreateBuilder, GroupCreateRequest, GroupResponse,
        },
        provider::Provider,
    };
    use openstack_keystone_core_types::identity::*;

    #[tokio::test]
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_group()
            .withf(|_, req: &GroupCreate| req.domain_id == "domain" && req.name == "name")
            .returning(|_, req| {
                Ok(Group {
                    id: "bar".into(),
                    domain_id: req.domain_id,
                    name: req.name,
                    ..Default::default()
                })
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

        let req = GroupCreateRequest {
            group: ApiGroupCreateBuilder::default()
                .domain_id("domain")
                .name("name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.group.name, req.group.name);
        assert_eq!(res.group.domain_id, req.group.domain_id);
    }
}
