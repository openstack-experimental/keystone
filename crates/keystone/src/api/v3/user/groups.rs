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

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::group::types::{Group, GroupList};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// List groups a user is member of
#[utoipa::path(
    get,
    path = "/{user_id}/groups",
    description = "List groups a user is member of",
    responses(
        (status = OK, description = "List of user groups", body = GroupList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip(state))]
pub(super) async fn groups(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&state, &user_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    match current {
        Some(_) => {
            let groups: Vec<Group> = state
                .provider
                .get_identity_provider()
                .list_groups_of_user(&state, &user_id)
                .await?
                .into_iter()
                .map(Into::into)
                .collect();
            Ok((StatusCode::OK, Json(GroupList { groups })).into_response())
        }
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

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::{
        api::v3::group::types::{GroupBuilder as ApiGroupBuilder, GroupList},
        provider::Provider,
    };
    use openstack_keystone_core_types::identity::Group;
    use openstack_keystone_core_types::identity::UserResponseBuilder;

    #[tokio::test]
    async fn test_groups() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "foo")
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
        identity_mock
            .expect_list_groups_of_user()
            .withf(|_, uid: &str| uid == "foo")
            .returning(|_, _| {
                Ok(vec![Group {
                    id: "1".into(),
                    name: "2".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }])
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
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/groups")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![
                ApiGroupBuilder::default()
                    .id("1")
                    .name("2")
                    .domain_id("did")
                    .build()
                    .unwrap()
            ],
            res.groups
        );
    }
}
