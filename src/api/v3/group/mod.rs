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
    Json, debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use types::{Group, GroupCreateRequest, GroupList, GroupListParameters, GroupResponse};

pub mod types;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, remove))
}

/// List groups
#[utoipa::path(
    get,
    path = "/",
    params(GroupListParameters),
    description = "List groups",
    responses(
        (status = OK, description = "List of groups", body = GroupList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_list", level = "debug", skip(state))]
async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<GroupListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let groups: Vec<Group> = state
        .provider
        .get_identity_provider()
        .list_groups(&state, &query.into())
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(GroupList { groups })
}

/// Get single group
#[utoipa::path(
    get,
    path = "/{group_id}",
    description = "Get group by ID",
    params(),
    responses(
        (status = OK, description = "Group object", body = GroupResponse),
        (status = 404, description = "Group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_get", level = "debug", skip(state))]
async fn show(
    Auth(user_auth): Auth,
    Path(group_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_identity_provider()
        .get_group(&state, &group_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "group".into(),
                identifier: group_id,
            })
        })?
}

/// Create group
#[utoipa::path(
    post,
    path = "/",
    description = "Create new Group",
    responses(
        (status = CREATED, description = "Group object", body = GroupResponse),
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::create_group", level = "debug", skip(state))]
#[debug_handler]
async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<GroupCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let res = state
        .provider
        .get_identity_provider()
        .create_group(&state, req.into())
        .await?;
    Ok((StatusCode::CREATED, res).into_response())
}

/// Delete group
#[utoipa::path(
    delete,
    path = "/{group_id}",
    description = "Delete group by ID",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_delete", level = "debug", skip(state))]
async fn remove(
    Auth(user_auth): Auth,
    Path(group_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_identity_provider()
        .delete_group(&state, &group_id)
        .await?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`

    use serde_json::json;

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::group::types::{
        Group as ApiGroup, GroupCreate as ApiGroupCreate, GroupCreateRequest, GroupList,
        GroupResponse,
    };
    use crate::identity::{
        MockIdentityProvider,
        error::IdentityProviderError,
        types::{Group, GroupCreate, GroupListParameters},
    };

    use crate::tests::api::{get_mocked_state, get_mocked_state_unauthed};

    #[tokio::test]
    async fn test_list() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_groups()
            .withf(|_, _: &GroupListParameters| true)
            .returning(|_, _| {
                Ok(vec![Group {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(identity_mock);

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
        let res: GroupList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiGroup {
                id: "1".into(),
                name: "2".into(),
                // for some reason when deserializing missing value appears still as an empty
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.groups
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_groups()
            .withf(|_, qp: &GroupListParameters| {
                GroupListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(identity_mock);

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
        let _res: GroupList = serde_json::from_slice(&body).unwrap();
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
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(identity_mock);

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
            ApiGroup {
                id: "bar".into(),
                extra: Some(json!({})),
                ..Default::default()
            },
            res.group,
        );
    }

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

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = GroupCreateRequest {
            group: ApiGroupCreate {
                domain_id: "domain".into(),
                name: "name".into(),
                ..Default::default()
            },
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

    #[tokio::test]
    async fn test_delete() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Err(IdentityProviderError::GroupNotFound("foo".into())));

        identity_mock
            .expect_delete_group()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
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
                    .method("DELETE")
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
