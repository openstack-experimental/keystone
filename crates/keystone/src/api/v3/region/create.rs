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
//! # Create region API
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{RegionCreateRequest, RegionResponse, RegionUpdate, RegionUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new Region.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Region created", body = RegionResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="regions"
)]
#[tracing::instrument(name = "api::v3::region_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<RegionCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/region/create",
            &user_auth,
            json!({"region": payload.region}),
            None,
        )
        .await?;
    // Create the region
    let created_region = state
        .provider
        .get_catalog_provider()
        .create_region(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    // Return response with 201 Created status
    Ok((
        StatusCode::CREATED,
        Json(RegionResponse {
            region: created_region.into(),
        }),
    )
        .into_response())
}

/// Create (or update) a Region with a caller-supplied ID.
///
/// `PUT /regions/{region_id}` is python keystone's idempotent upsert form
/// (api-ref "Create or update region"): create the region if `region_id`
/// doesn't exist yet, otherwise update it in place. Distinct from `POST
/// /regions`, which always generates a fresh id.
#[utoipa::path(
    put,
    path = "/{region_id}",
    responses(
        (status = CREATED, description = "Region created or updated", body = RegionResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="regions"
)]
#[tracing::instrument(name = "api::v3::region_create_with_id", level = "debug", skip(state))]
pub(super) async fn create_with_id(
    Auth(user_auth): Auth,
    Path(region_id): Path<String>,
    State(state): State<ServiceState>,
    Json(mut payload): Json<RegionCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;
    payload.region.id = Some(region_id.clone());

    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_catalog_provider()
        .get_region(&exec, &region_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            if current.is_some() {
                "identity/region/update"
            } else {
                "identity/region/create"
            },
            &user_auth,
            json!({"region": payload.region}),
            current.as_ref().map(|c| json!({"region": c})),
        )
        .await?;

    let region = match current {
        Some(_) => {
            state
                .provider
                .get_catalog_provider()
                .update_region(
                    &exec,
                    &region_id,
                    RegionUpdateRequest {
                        region: RegionUpdate {
                            description: payload.region.description,
                            parent_region_id: payload.region.parent_region_id,
                            extra: payload.region.extra,
                        },
                    }
                    .into(),
                )
                .await?
        }
        None => {
            state
                .provider
                .get_catalog_provider()
                .create_region(&exec, payload.into())
                .await?
        }
    };

    Ok((
        StatusCode::CREATED,
        Json(RegionResponse {
            region: region.into(),
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

    use openstack_keystone_core_types::catalog::{RegionBuilder, RegionCreate};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::region::types::{Region as ApiRegion, RegionResponse};
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_create() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_create_region()
            .withf(|_, region_create: &RegionCreate| region_create.id.is_none())
            .returning(|_, _| {
                Ok(RegionBuilder::default()
                    .id("new_region_id")
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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
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
        let res: RegionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiRegion {
                id: "new_region_id".into(),
                description: None,
                parent_region_id: None,
                extra: std::collections::HashMap::new(),
            },
            res.region,
        );
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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
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

    #[tokio::test]
    async fn test_create_with_id_creates_when_absent() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_region()
            .withf(|_, id: &'_ str| id == "specific-id")
            .returning(|_, _| Ok(None));
        catalog_mock
            .expect_create_region()
            .withf(|_, region_create: &RegionCreate| {
                region_create.id.as_deref() == Some("specific-id")
            })
            .returning(|_, _| Ok(RegionBuilder::default().id("specific-id").build().unwrap()));

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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/specific-id")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("PUT")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.region.id, "specific-id");
    }

    #[tokio::test]
    async fn test_create_with_id_updates_when_present() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_region()
            .withf(|_, id: &'_ str| id == "specific-id")
            .returning(|_, _| {
                Ok(Some(
                    RegionBuilder::default().id("specific-id").build().unwrap(),
                ))
            });
        catalog_mock
            .expect_update_region()
            .withf(|_, id: &'_ str, _| id == "specific-id")
            .returning(|_, _, _| {
                Ok(RegionBuilder::default()
                    .id("specific-id")
                    .description("updated")
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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
                .description("updated")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/specific-id")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("PUT")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.region.description.as_deref(), Some("updated"));
    }

    #[tokio::test]
    async fn test_create_with_id_forbidden() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_region()
            .withf(|_, id: &'_ str| id == "specific-id")
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

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/specific-id")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("PUT")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_with_id_unauthorized() {
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_region()
            .withf(|_, id: &'_ str| id == "specific-id")
            .returning(|_, _| Ok(None));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_catalog(catalog_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::region::types::RegionCreateRequest {
            region: crate::api::v3::region::types::RegionCreateBuilder::default()
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/specific-id")
                    .header("Content-Type", "application/json")
                    .method("PUT")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
