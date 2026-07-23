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
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{RegionCreateRequest, RegionResponse};
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
}
