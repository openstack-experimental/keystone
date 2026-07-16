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

use super::types::{Service, ServiceResponse, ServiceUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing service
#[utoipa::path(
    put,
    path = "/{service_id}",
    description = "Update service by ID",
    params(),
    responses(
        (status = OK, description = "Updated service", body = ServiceResponse),
        (status = 404, description = "Service not found", example = json!(KeystoneApiError::NotFound{resource: "service".into(), identifier: "id = 1".into()}))
    ),
    tag="services"
)]
#[tracing::instrument(name = "api::update_service", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(service_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<ServiceUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    req.validate()?;

    // Fetch the current service to pass it as existing object into the
    // policy evaluation
    let current = state
        .provider
        .get_catalog_provider()
        .get_service(
            &ExecutionContext::from_auth(&state, &user_auth),
            &service_id,
        )
        .await?;

    let existing_service = current.as_ref().map(|c| json!({"service": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/service/update",
            &user_auth,
            json!({"service": req.service}),
            existing_service,
        )
        .await?;

    match current {
        Some(_) => {
            let service = state
                .provider
                .get_catalog_provider()
                .update_service(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &service_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(ServiceResponse {
                    service: Service::from(service),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "service".into(),
            identifier: service_id,
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

    use openstack_keystone_core_types::catalog::ServiceBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::service::types::{Service as ApiService, ServiceResponse};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_update_success() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_service()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    ServiceBuilder::default()
                        .id("foo")
                        .r#type("identity")
                        .enabled(true)
                        .build()
                        .unwrap(),
                ))
            });
        catalog_mock
            .expect_update_service()
            .withf(|_, id: &'_ str, _| id == "foo")
            .returning(|_, _, _| {
                Ok(ServiceBuilder::default()
                    .id("foo")
                    .r#type("identity")
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

        let req = crate::api::v3::service::types::ServiceUpdateRequest {
            service: crate::api::v3::service::types::ServiceUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
        let res: ServiceResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiService {
                id: "foo".into(),
                r#type: Some("identity".into()),
                enabled: false,
                name: None,
                extra: std::collections::HashMap::new(),
            },
            res.service,
        );
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_service()
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

        let req = crate::api::v3::service::types::ServiceUpdateRequest {
            service: crate::api::v3::service::types::ServiceUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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
            .expect_get_service()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    ServiceBuilder::default()
                        .id("foo")
                        .r#type("identity")
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

        let req = crate::api::v3::service::types::ServiceUpdateRequest {
            service: crate::api::v3::service::types::ServiceUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
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

        let req = crate::api::v3::service::types::ServiceUpdateRequest {
            service: crate::api::v3::service::types::ServiceUpdateBuilder::default()
                .enabled(false)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/foo")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
