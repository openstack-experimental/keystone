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
//! # Create limits API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Limit, LimitCreateRequest, LimitList};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::limit as provider_types;

/// Create limits.
///
/// The request carries one or more limits and is processed atomically: either
/// all of them are created or none. Exactly one of `project_id` and
/// `domain_id` must be set on every limit. The policy is enforced for every
/// item of the batch.
#[utoipa::path(
    post,
    path = "/",
    request_body = LimitCreateRequest,
    responses(
        (status = CREATED, description = "Limits created", body = LimitList),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "No registered limit exists or the limit violates the enforcement model"),
        (status = 409, description = "Limit already exists"),
        (status = 500, description = "Internal error")
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::v3::limit_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<LimitCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    for item in &payload.limits {
        state
            .policy_enforcer
            .enforce(
                "identity/limit/create",
                &user_auth,
                json!({"limit": item}),
                None,
            )
            .await?;
    }

    let created = state
        .provider
        .get_limit_provider()
        .create_limits(
            &ExecutionContext::from_auth(&state, &user_auth),
            Vec::<provider_types::LimitCreate>::from(payload),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(LimitList {
            limits: created.into_iter().map(Limit::from).collect(),
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
    use crate::limit::{LimitProviderError, MockLimitProvider};
    use crate::provider::Provider;

    const BODY: &str = r#"{"limits": [
        {"service_id": "srv", "resource_name": "cores", "resource_limit": 10, "project_id": "p1"},
        {"service_id": "srv", "region_id": "r1", "resource_name": "ram", "resource_limit": 0, "domain_id": "d1"}
    ]}"#;

    fn stored(id: &str) -> provider_types::Limit {
        provider_types::Limit {
            description: None,
            domain_id: None,
            id: id.into(),
            project_id: Some("p1".into()),
            region_id: None,
            resource_limit: 10,
            resource_name: "cores".into(),
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
        mock.expect_create_limits()
            .withf(|_, items: &Vec<provider_types::LimitCreate>| {
                items.len() == 2
                    && items[0].project_id.as_deref() == Some("p1")
                    && items[0].domain_id.is_none()
                    && items[1].domain_id.as_deref() == Some("d1")
                    && items[1].resource_limit == 0
            })
            .returning(|_, _| Ok(vec![stored("1"), stored("2")]));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = post(state, BODY, true).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.limits.len());

        let calls = policy.calls();
        assert_eq!(2, calls.len());
        for call in calls {
            assert_eq!("identity/limit/create", call.policy_name);
            policy_contract::assert_object_keys(&call.target, &["limit"]);
            policy_contract::assert_existing_presence(&call.existing, false);
            policy_contract::assert_no_secrets(&call.target);
        }
    }

    #[tokio::test]
    async fn test_create_empty_batch() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(
            post(state, r#"{"limits": []}"#, true).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_create_invalid_target() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_limits().returning(|_, _| {
            Err(LimitProviderError::InvalidReference(
                "exactly one of project_id and domain_id must be provided".into(),
            ))
        });
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        let response = post(
            state,
            r#"{"limits": [{"service_id": "s", "resource_name": "r", "resource_limit": 1}]}"#,
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_no_registered_limit() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_limits()
            .returning(|_, _| Err(LimitProviderError::NoLimitReference("x".into())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(
            post(state, BODY, true).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_invalid_limit() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_limits()
            .returning(|_, _| Err(LimitProviderError::InvalidLimit("x".into())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(
            post(state, BODY, true).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_conflict() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_limits()
            .returning(|_, _| Err(LimitProviderError::Conflict("dup".into())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(post(state, BODY, true).await.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let mut mock = MockLimitProvider::default();
        mock.expect_create_limits().never();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_limit(mock), false, None).await;
        assert_eq!(
            post(state, BODY, true).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(
            post(state, BODY, false).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
