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

use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

use crate::api::v3::group::openapi_router as v3_openapi_router;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    v3_openapi_router()
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

    use openstack_keystone_core_types::identity::{Group, GroupCreate, GroupListParameters};

    use super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::group::types::{
        GroupBuilder as ApiGroupBuilder, GroupCreateBuilder as ApiGroupCreateBuilder,
        GroupCreateRequest, GroupList, GroupResponse,
    };
    use crate::identity::{MockIdentityProvider, error::IdentityProviderError};
    use crate::provider::Provider;

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
                    domain_id: "did".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
            None,
        );

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

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
            None,
        );

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
        let state = get_mocked_state(Provider::mocked_builder(), false, None, None);

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
        );

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
        );

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

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
            None,
        );

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
