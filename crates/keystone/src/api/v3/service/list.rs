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

use super::types::{Service, ServiceList, ServiceListParameters};
use crate::api::auth::Auth;
use crate::api::common::paginate_forward;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List services
#[utoipa::path(
    get,
    path = "/",
    params(ServiceListParameters, PaginationQuery),
    description = "List services",
    responses(
        (status = OK, description = "List of services", body = ServiceList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="services"
)]
#[tracing::instrument(name = "api::service_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<ServiceListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/service/list",
            &user_auth,
            json!({"service": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_params =
        openstack_keystone_core_types::catalog::ServiceListParameters::from(query);
    provider_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.catalog.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: false,
    };

    let services: Vec<Service> = state
        .provider
        .get_catalog_provider()
        .list_services(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (services, links) = paginate_forward(&config, services, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(ServiceList { services, links })).into_response())
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

    use openstack_keystone_core_types::catalog::{ServiceBuilder, ServiceListParameters};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::service::types::{Service as ApiService, ServiceList};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_services()
            .withf(|_, _: &ServiceListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    ServiceBuilder::default()
                        .id("1")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
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
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ServiceList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiService {
                id: "1".into(),
                r#type: Some("identity".into()),
                enabled: true,
                name: None,
                extra: std::collections::HashMap::new(),
            }],
            res.services
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_services()
            .withf(|_, qp: &ServiceListParameters| {
                qp.name == Some("name".into()) && qp.r#type == Some("identity".into())
            })
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
                    .uri("/?name=name&type=identity")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: ServiceList = serde_json::from_slice(&body).unwrap();
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
            .expect_list_services()
            .withf(|_, qp: &ServiceListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    ServiceBuilder::default()
                        .id("1")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
                    ServiceBuilder::default()
                        .id("2")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
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
        let res: ServiceList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.services.len(), 1);
        assert_eq!(res.services[0].id, "1");
        assert!(res.links.is_some());
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_list_services()
            .withf(|_, qp: &ServiceListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    ServiceBuilder::default()
                        .id("1")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
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
        let res: ServiceList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.services.len(), 1);
        assert_eq!(res.links, None);
    }
}
