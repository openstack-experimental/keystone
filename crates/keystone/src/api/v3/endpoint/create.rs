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
//! # Create endpoint API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{EndpointCreateRequest, EndpointResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new Endpoint.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Endpoint created", body = EndpointResponse),
        (status = 400, description = "Invalid input"),
        (status = 404, description = "Service not found"),
        (status = 500, description = "Internal error")
    ),
    tag="endpoints"
)]
#[tracing::instrument(name = "api::v3::endpoint_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(mut payload): Json<EndpointCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/endpoint/create",
            &user_auth,
            json!({"endpoint": payload.endpoint}),
            None,
        )
        .await?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);

    // Ensure the referenced service actually exists before creating the
    // endpoint.
    if state
        .provider
        .get_catalog_provider()
        .get_service(&exec, &payload.endpoint.service_id)
        .await?
        .is_none()
    {
        return Err(KeystoneApiError::NotFound {
            resource: "service".into(),
            identifier: payload.endpoint.service_id.clone(),
        });
    }

    payload.endpoint.region_id = super::resolve_legacy_region(
        &state,
        &exec,
        payload.endpoint.region_id.take(),
        &mut payload.endpoint.extra,
    )
    .await?;

    // Create the endpoint
    let created_endpoint = state
        .provider
        .get_catalog_provider()
        .create_endpoint(&exec, payload.into())
        .await?;

    // Return response with 201 Created status
    Ok((
        StatusCode::CREATED,
        Json(EndpointResponse {
            endpoint: created_endpoint.into(),
        }),
    )
        .into_response())
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

    use openstack_keystone_core_types::catalog::{EndpointBuilder, EndpointCreate, ServiceBuilder};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::endpoint::types::{Endpoint as ApiEndpoint, EndpointResponse};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_create() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_service()
            .withf(|_, id: &'_ str| id == "svc1")
            .returning(|_, _| {
                Ok(Some(
                    ServiceBuilder::default()
                        .id("svc1")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
                ))
            });
        catalog_mock
            .expect_create_endpoint()
            .withf(|_, endpoint_create: &EndpointCreate| {
                endpoint_create.service_id == "svc1"
                    && endpoint_create.interface == "public"
                    && endpoint_create.url == "https://example.com"
                    && endpoint_create.id.is_none()
            })
            .returning(|_, _| {
                Ok(EndpointBuilder::default()
                    .id("new_endpoint_id")
                    .interface("public")
                    .service_id("svc1")
                    .url("https://example.com")
                    .enabled(true)
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
            .with_state(state.clone());

        let req = crate::api::v3::endpoint::types::EndpointCreateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointCreateBuilder::default()
                .interface("public")
                .service_id("svc1")
                .url("https://example.com")
                .enabled(true)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: EndpointResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiEndpoint {
                id: "new_endpoint_id".into(),
                interface: "public".into(),
                region_id: None,
                region: None,
                service_id: "svc1".into(),
                url: "https://example.com".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
            },
            res.endpoint,
        );
    }

    #[tokio::test]
    async fn test_create_service_not_found() {
        let mut catalog_mock = MockCatalogProvider::default();
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

        let req = crate::api::v3::endpoint::types::EndpointCreateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointCreateBuilder::default()
                .interface("public")
                .service_id("missing")
                .url("https://example.com")
                .enabled(true)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let catalog_mock = MockCatalogProvider::default();

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

        let req = crate::api::v3::endpoint::types::EndpointCreateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointCreateBuilder::default()
                .interface("public")
                .service_id("svc1")
                .url("https://example.com")
                .enabled(true)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::endpoint::types::EndpointCreateRequest {
            endpoint: crate::api::v3::endpoint::types::EndpointCreateBuilder::default()
                .interface("public")
                .service_id("svc1")
                .url("https://example.com")
                .enabled(true)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
