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
//! # Create registered limits API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{RegisteredLimit, RegisteredLimitCreateRequest, RegisteredLimitList};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::limit as provider_types;

/// Create registered limits.
///
/// The request carries one or more registered limits and is processed
/// atomically: either all of them are created or none. The policy is enforced
/// for every item of the batch.
#[utoipa::path(
    post,
    path = "/",
    request_body = RegisteredLimitCreateRequest,
    responses(
        (status = CREATED, description = "Registered limits created", body = RegisteredLimitList),
        (status = 400, description = "Invalid input"),
        (status = 409, description = "Registered limit already exists"),
        (status = 500, description = "Internal error")
    ),
    tag="registered_limits"
)]
#[tracing::instrument(
    name = "api::v3::registered_limit_create",
    level = "debug",
    skip(state)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<RegisteredLimitCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    for item in &payload.registered_limits {
        state
            .policy_enforcer
            .enforce(
                "identity/registered_limit/create",
                &user_auth,
                json!({"registered_limit": item}),
                None,
            )
            .await?;
    }

    let created = state
        .provider
        .get_limit_provider()
        .create_registered_limits(
            &ExecutionContext::from_auth(&state, &user_auth),
            Vec::<provider_types::RegisteredLimitCreate>::from(payload),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisteredLimitList {
            registered_limits: created.into_iter().map(RegisteredLimit::from).collect(),
            links: None,
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
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;

    const BODY: &str = r#"{"registered_limits": [
        {"service_id": "srv", "resource_name": "cores", "default_limit": 10},
        {"service_id": "srv", "region_id": "r1", "resource_name": "ram", "default_limit": -1, "description": "d"}
    ]}"#;

    fn stored(id: &str, name: &str) -> provider_types::RegisteredLimit {
        provider_types::RegisteredLimit {
            default_limit: 10,
            description: None,
            id: id.into(),
            region_id: None,
            resource_name: name.into(),
            service_id: "srv".into(),
        }
    }

    async fn post(
        state: crate::keystone::ServiceState,
        body: &'static str,
        auth: bool,
    ) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json");
        if auth {
            request = request.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_create() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_registered_limits()
            .withf(|_, items: &Vec<provider_types::RegisteredLimitCreate>| {
                items.len() == 2
                    && items[0].id.is_none()
                    && items[1].region_id.as_deref() == Some("r1")
                    && items[1].default_limit == -1
            })
            .returning(|_, _| Ok(vec![stored("1", "cores"), stored("2", "ram")]));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;

        let response = post(state, BODY, true).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegisteredLimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.registered_limits.len());
        assert_eq!("1", res.registered_limits[0].id);
    }

    #[tokio::test]
    async fn test_create_enforces_policy_for_every_item() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_registered_limits()
            .returning(|_, _| Ok(vec![stored("1", "cores"), stored("2", "ram")]));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = post(state, BODY, true).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let calls = policy.calls();
        assert_eq!(2, calls.len());
        for call in calls {
            assert_eq!("identity/registered_limit/create", call.policy_name);
            policy_contract::assert_object_keys(&call.target, &["registered_limit"]);
            policy_contract::assert_existing_presence(&call.existing, false);
            policy_contract::assert_no_secrets(&call.target);
        }
    }

    #[tokio::test]
    async fn test_create_empty_batch() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = post(state, r#"{"registered_limits": []}"#, true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_unknown_attribute() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = post(
            state,
            r#"{"registered_limits": [{"service_id": "s", "resource_name": "r", "default_limit": 1, "id": "x"}]}"#,
            true,
        )
        .await;
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_create_invalid_value() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = post(
            state,
            r#"{"registered_limits": [{"service_id": "s", "resource_name": "r", "default_limit": -2}]}"#,
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_conflict() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_registered_limits()
            .returning(|_, _| Err(crate::limit::LimitProviderError::Conflict("dup".into())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        let response = post(state, BODY, true).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let response = post(state, BODY, true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = post(state, BODY, false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
