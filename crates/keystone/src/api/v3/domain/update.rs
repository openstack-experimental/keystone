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
//! # Update domain API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Domain, DomainResponse, DomainUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing domain
#[utoipa::path(
    patch,
    path = "/{domain_id}",
    description = "Update domain by ID",
    params(),
    responses(
        (status = OK, description = "Updated domain", body = DomainResponse),
        (status = 404, description = "Domain not found", example = json!(KeystoneApiError::NotFound{resource: "domain".into(), identifier: "id = 1".into()}))
    ),
    tag="domains"
)]
#[tracing::instrument(name = "api::v3::domain_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<DomainUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    // Fetch the current domain to pass it as existing object into the
    // policy evaluation
    let current = state
        .provider
        .get_resource_provider()
        .get_domain(&ExecutionContext::from_auth(&state, &user_auth), &domain_id)
        .await?;

    let existing_domain = current.as_ref().map(|c| json!({"domain": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/resource/domain/update",
            &user_auth,
            json!({"domain": req.domain}),
            existing_domain,
        )
        .await?;

    match current {
        Some(_) => {
            let domain = state
                .provider
                .get_resource_provider()
                .update_domain(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &domain_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(DomainResponse {
                    domain: Domain::from(domain),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "domain".into(),
            identifier: domain_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::Domain as ProviderDomain;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::domain::types::*;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_update_success() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderDomain {
                    id: "foo".into(),
                    name: "old_name".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_update_domain()
            .withf(|_, id: &'_ str, _| id == "foo")
            .returning(|_, _, _| {
                Ok(ProviderDomain {
                    id: "foo".into(),
                    name: "new_name".into(),
                    enabled: true,
                    ..Default::default()
                })
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = DomainUpdateRequest {
            domain: DomainUpdateBuilder::default()
                .name("new_name")
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
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: DomainResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.domain.name, "new_name");
        assert_eq!(res.domain.id, "foo");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = DomainUpdateRequest {
            domain: DomainUpdateBuilder::default()
                .name("new_name")
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
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderDomain {
                    id: "foo".into(),
                    name: "old_name".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = DomainUpdateRequest {
            domain: DomainUpdateBuilder::default()
                .name("new_name")
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
                    .header(header::CONTENT_TYPE, "application/json")
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

        let req = DomainUpdateRequest {
            domain: DomainUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .header(header::CONTENT_TYPE, "application/json")
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
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"domain":{"name":"updated"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
