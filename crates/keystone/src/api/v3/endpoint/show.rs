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

use openstack_keystone_api_types::v3::endpoint::{Endpoint, EndpointResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get single endpoint
#[utoipa::path(
    get,
    path = "/{endpoint_id}",
    description = "Get endpoint by ID",
    params(),
    responses(
        (status = OK, description = "Endpoint object", body = EndpointResponse),
        (status = 404, description = "Endpoint not found", example = json!(KeystoneApiError::NotFound{resource: "endpoint".into(), identifier: "id = 1".into()}))
    ),
    tag="endpoints"
)]
#[tracing::instrument(name = "api::endpoint_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(endpoint_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_catalog_provider()
        .get_endpoint(
            &ExecutionContext::from_auth(&state, &user_auth),
            &endpoint_id,
        )
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/endpoint/show",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"endpoint": current})),
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(EndpointResponse {
                endpoint: Endpoint::from(current),
            }),
        )
            .into_response()),
        _ => Err(KeystoneApiError::NotFound {
            resource: "endpoint".into(),
            identifier: endpoint_id,
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
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::catalog::EndpointBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::endpoint::types::{Endpoint as ApiEndpoint, EndpointResponse};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_show_success() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_endpoint()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    EndpointBuilder::default()
                        .id("foo")
                        .interface("public")
                        .service_id("svc1")
                        .url("https://example.com")
                        .enabled(true)
                        .build()
                        .unwrap(),
                ))
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
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: EndpointResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiEndpoint {
                id: "foo".into(),
                interface: "public".into(),
                region_id: None,
                service_id: "svc1".into(),
                url: "https://example.com".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
            },
            res.endpoint,
        );
    }

    #[tokio::test]
    async fn test_show_not_found_not_allowed() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_endpoint()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
            false,
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
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

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
}
