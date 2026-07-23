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

use super::types::{Endpoint, EndpointResponse, EndpointUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing endpoint
#[utoipa::path(
    patch,
    path = "/{endpoint_id}",
    description = "Update endpoint by ID",
    params(),
    responses(
        (status = OK, description = "Updated endpoint", body = EndpointResponse),
        (status = 404, description = "Endpoint not found", example = json!(KeystoneApiError::NotFound{resource: "endpoint".into(), identifier: "id = 1".into()}))
    ),
    tag="endpoints"
)]
#[tracing::instrument(name = "api::update_endpoint", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(endpoint_id): Path<String>,
    State(state): State<ServiceState>,
    Json(mut req): Json<EndpointUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    req.validate()?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);

    // Fetch the current endpoint to pass it as existing object into the
    // policy evaluation
    let current = state
        .provider
        .get_catalog_provider()
        .get_endpoint(&exec, &endpoint_id)
        .await?;

    let existing_endpoint = current.as_ref().map(|c| json!({"endpoint": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/endpoint/update",
            &user_auth,
            json!({"endpoint": req.endpoint}),
            existing_endpoint,
        )
        .await?;

    match current {
        Some(_) => {
            if let Some(service_id) = &req.endpoint.service_id
                && state
                    .provider
                    .get_catalog_provider()
                    .get_service(&exec, service_id)
                    .await?
                    .is_none()
            {
                return Err(KeystoneApiError::NotFound {
                    resource: "service".into(),
                    identifier: service_id.clone(),
                });
            }

            req.endpoint.region_id = super::resolve_legacy_region(
                &state,
                &exec,
                req.endpoint.region_id.take(),
                &mut req.endpoint.extra,
            )
            .await?;

            let endpoint = state
                .provider
                .get_catalog_provider()
                .update_endpoint(&exec, &endpoint_id, req.into())
                .await?;
            Ok((
                StatusCode::OK,
                Json(EndpointResponse {
                    endpoint: Endpoint::from(endpoint),
                }),
            )
                .into_response())
        }
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
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::catalog::EndpointBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::endpoint::types::{Endpoint as ApiEndpoint, EndpointResponse};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_update_success() {
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
        catalog_mock
            .expect_update_endpoint()
            .withf(|_, id: &'_ str, _| id == "foo")
            .returning(|_, _, _| {
                Ok(EndpointBuilder::default()
                    .id("foo")
                    .interface("public")
                    .service_id("svc1")
                    .url("https://example.com")
                    .enabled(false)
                    .build()
                    .unwrap())
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

        let req = crate::api::v3::endpoint::types::EndpointUpdateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
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
        let res: EndpointResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiEndpoint {
                id: "foo".into(),
                interface: "public".into(),
                region_id: None,
                region: None,
                service_id: "svc1".into(),
                url: "https://example.com".into(),
                enabled: false,
                extra: std::collections::HashMap::new(),
            },
            res.endpoint,
        );
    }

    #[tokio::test]
    async fn test_update_new_service_not_found() {
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
        catalog_mock
            .expect_get_service()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));

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

        let req = crate::api::v3::endpoint::types::EndpointUpdateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointUpdateBuilder::default()
                .service_id("missing")
                .build()
                .unwrap(),
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
    async fn test_update_not_found() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_endpoint()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

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

        let req = crate::api::v3::endpoint::types::EndpointUpdateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
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
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::endpoint::types::EndpointUpdateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
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

        let req = crate::api::v3::endpoint::types::EndpointUpdateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
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
                    .body(Body::from(r#"{"endpoint":{"enabled":false}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
