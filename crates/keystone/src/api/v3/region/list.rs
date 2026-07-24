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
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{Region, RegionList, RegionListParameters};
use crate::api::auth::Auth;
use crate::api::common::paginate_forward;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List regions
#[utoipa::path(
    get,
    path = "/",
    params(RegionListParameters, PaginationQuery),
    description = "List regions",
    responses(
        (status = OK, description = "List of regions", body = RegionList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="regions"
)]
#[tracing::instrument(name = "api::region_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<RegionListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/region/list",
            &user_auth,
            json!({"region": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_params =
        openstack_keystone_core_types::catalog::RegionListParameters::from(query);
    provider_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.catalog.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: false,
    };

    let regions: Vec<Region> = state
        .provider
        .get_catalog_provider()
        .list_regions(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (regions, links) = paginate_forward(&config, regions, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(RegionList { regions, links })).into_response())
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

    use openstack_keystone_core_types::catalog::{RegionBuilder, RegionListParameters};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::region::types::{Region as ApiRegion, RegionList};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_regions()
            .withf(|_, _: &RegionListParameters| true)
            .returning(|_, _| Ok(vec![RegionBuilder::default().id("1").build().unwrap()]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
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
        let res: RegionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiRegion {
                id: "1".into(),
                description: None,
                parent_region_id: None,
                extra: std::collections::HashMap::new(),
            }],
            res.regions
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_regions()
            .withf(|_, qp: &RegionListParameters| qp.parent_region_id == Some("parent".into()))
            .returning(|_, _| Ok(Vec::new()));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
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
                    .uri("/?parent_region_id=parent")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: RegionList = serde_json::from_slice(&body).unwrap();
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

    /// Backend over-fetched (returned `limit + 1 == 2` rows): a `next` link
    /// is produced and the extra row trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_regions()
            .withf(|_, qp: &RegionListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    RegionBuilder::default().id("1").build().unwrap(),
                    RegionBuilder::default().id("2").build().unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
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
        let res: RegionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.regions.len(), 1);
        assert_eq!(res.regions[0].id, "1");
        assert!(res.links.is_some());
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_regions()
            .withf(|_, qp: &RegionListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| Ok(vec![RegionBuilder::default().id("1").build().unwrap()]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
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
        let res: RegionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.regions.len(), 1);
        assert_eq!(res.links, None);
    }
}
