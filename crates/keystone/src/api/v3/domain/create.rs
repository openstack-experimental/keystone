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
//! # Create domain API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{DomainCreateRequest, DomainResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Create domain.
///
/// Creates a domain, which is a container for projects and users.
#[utoipa::path(
    post,
    path = "/",
    request_body = DomainCreateRequest,
    responses(
        (status = CREATED, description = "Domain created", body = DomainResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="domains"
)]
#[tracing::instrument(name = "api::v3::domain_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<DomainCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/resource/domain/create",
            &user_auth,
            json!({"domain": payload.domain}),
            None,
        )
        .await?;

    // Create the domain
    let created_domain = state
        .provider
        .get_resource_provider()
        .create_domain(&state, payload.domain.into())
        .await?;

    // Return response with 201 CREATED status
    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            domain: created_domain.into(),
        }),
    )
        .into_response())
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
    use tracing_test::traced_test;

    use openstack_keystone_core_types::resource::Domain as ProviderDomain;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::domain::types::*;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[traced_test]
    #[tokio::test]
    async fn test_allowed() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock.expect_create_domain().returning(|_, _| {
            Ok(ProviderDomain {
                description: Some("A new domain".into()),
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "did".into(),
                name: "domain_name".into(),
            })
        });

        let provider_builder = Provider::mocked_builder().mock_resource(resource_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider_builder, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = DomainCreateRequest {
            domain: DomainCreateBuilder::default().name("name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let res: DomainResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            Domain {
                description: Some("A new domain".into()),
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "did".into(),
                name: "domain_name".into(),
            },
            res.domain,
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_not_allowed() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = DomainCreateRequest {
            domain: DomainCreateBuilder::default().name("name").build().unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
