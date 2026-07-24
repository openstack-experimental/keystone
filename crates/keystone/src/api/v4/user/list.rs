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
//! User: list.

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{User, UserList, UserListParameters};
use crate::api::auth::Auth;
use crate::api::common::paginate_bidirectional;
use crate::api::error::KeystoneApiError;

use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List users
#[utoipa::path(
    get,
    path = "/",
    params(UserListParameters, PaginationQuery),
    description = "List users",
    responses(
        (status = OK, description = "List of users", body = UserList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<UserListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/list",
            &user_auth,
            json!({"user": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_params =
        openstack_keystone_core_types::identity::UserListParameters::from(query);
    provider_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.identity.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: pagination.page_reverse,
    };

    let users: Vec<User> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (users, links) = paginate_bidirectional(&config, users, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(UserList { users, links })).into_response())
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
    use crate::api::v3::user::types::{UserBuilder as ApiUser, UserList};
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_, _: &UserListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    UserResponseBuilder::default()
                        .id("1")
                        .domain_id("did")
                        .enabled(true)
                        .name("2")
                        .build()
                        .unwrap(),
                ])
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
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
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![
                ApiUser::default()
                    .id("1")
                    .domain_id("did")
                    .name("2")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ],
            res.users
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let vsc = test_fixture_scoped();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_, qp: &UserListParameters| {
                qp.domain_id == Some("domain".into()) && qp.name == Some("name".into())
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
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
                    .uri("/?domain_id=domain&name=name")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: UserList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

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

    #[tokio::test]
    async fn test_list_policy_denied() {
        let vsc = test_fixture_scoped();

        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

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

    /// Backend over-fetched (returned `limit + 1 == 2` rows), not the first
    /// page (`marker` set): both `next` and `previous` links are produced,
    /// and the extra row is trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_bidirectional_links() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_, qp: &UserListParameters| {
                qp.pagination.limit == Some(1) && qp.pagination.marker == Some("m".into())
            })
            .returning(|_, _| {
                Ok(vec![
                    UserResponseBuilder::default()
                        .id("1")
                        .domain_id("did")
                        .enabled(true)
                        .name("a")
                        .build()
                        .unwrap(),
                    UserResponseBuilder::default()
                        .id("2")
                        .domain_id("did")
                        .enabled(true)
                        .name("b")
                        .build()
                        .unwrap(),
                ])
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

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=1&marker=m")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.users.len(), 1);
        assert_eq!(res.users[0].id, "1");
        let links = res.links.expect("expected next+previous links");
        assert!(links.iter().any(|l| l.rel == "next"));
        assert!(links.iter().any(|l| l.rel == "previous"));
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced. This is the false-positive the
    /// over-fetch design fixes vs the old `returned_count >= limit`
    /// heuristic.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_, qp: &UserListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    UserResponseBuilder::default()
                        .id("1")
                        .domain_id("did")
                        .enabled(true)
                        .name("a")
                        .build()
                        .unwrap(),
                ])
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

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.users.len(), 1);
        assert_eq!(res.links, None);
    }
}
