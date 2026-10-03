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
//! # Update limit API
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Limit, LimitResponse, LimitUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update a limit.
///
/// Only the `resource_limit` and the `description` can be changed.
#[utoipa::path(
    patch,
    path = "/{limit_id}",
    description = "Update limit by ID",
    params(),
    request_body = LimitUpdateRequest,
    responses(
        (status = OK, description = "Limit object", body = LimitResponse),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "The limit violates the enforcement model"),
        (status = 404, description = "Limit not found", example = json!(KeystoneApiError::NotFound{resource: "limit".into(), identifier: "id = 1".into()}))
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::limit_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(limit_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<LimitUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_limit_provider()
        .get_limit(&exec, &limit_id)
        .await?
        .map(Limit::from);

    let existing = match &current {
        Some(current) => super::limit_policy_view(&state, &exec, current).await?,
        None => json!({"limit": null}),
    };
    state
        .policy_enforcer
        .enforce(
            "identity/limit/update",
            &user_auth,
            json!({"limit": req.limit}),
            Some(existing),
        )
        .await?;

    if current.is_none() {
        return Err(KeystoneApiError::NotFound {
            resource: "limit".into(),
            identifier: limit_id,
        });
    }

    let updated = state
        .provider
        .get_limit_provider()
        .update_limit(&exec, &limit_id, req.into())
        .await?;

    Ok((
        StatusCode::OK,
        Json(LimitResponse {
            limit: updated.into(),
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

    use openstack_keystone_core_types::limit as provider_types;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::limit::{LimitProviderError, MockLimitProvider};
    use crate::provider::Provider;

    fn stored(resource_limit: i32) -> provider_types::Limit {
        provider_types::Limit {
            description: None,
            domain_id: Some("d1".into()),
            id: "foo".into(),
            project_id: None,
            region_id: None,
            resource_limit,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    async fn patch(
        state: crate::keystone::ServiceState,
        body: &'static str,
        auth: bool,
    ) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder()
            .method("PATCH")
            .uri("/foo")
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
    async fn test_update() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit()
            .returning(|_, _| Ok(Some(stored(10))));
        mock.expect_update_limit()
            .withf(|_, id: &'_ str, data: &provider_types::LimitUpdate| {
                id == "foo"
                    && data.resource_limit == Some(0)
                    && data.description == Some(Some("d".to_string()))
            })
            .returning(|_, _, _| Ok(stored(0)));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = patch(
            state,
            r#"{"limit": {"resource_limit": 0, "description": "d"}}"#,
            true,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(0, res.limit.resource_limit);

        let calls = policy.calls();
        assert_eq!(1, calls.len());
        assert_eq!("identity/limit/update", calls[0].policy_name);
        policy_contract::assert_object_keys(&calls[0].target, &["limit"]);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
    }

    #[tokio::test]
    async fn test_update_only_value_and_description_allowed() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = patch(state, r#"{"limit": {"project_id": "other"}}"#, true).await;
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit().returning(|_, _| Ok(None));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        let response = patch(state, r#"{"limit": {"resource_limit": 1}}"#, true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_model_violation() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit()
            .returning(|_, _| Ok(Some(stored(10))));
        mock.expect_update_limit()
            .returning(|_, _, _| Err(LimitProviderError::InvalidLimit("bigger".into())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        let response = patch(state, r#"{"limit": {"resource_limit": 100}}"#, true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_invalid() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = patch(state, r#"{"limit": {"resource_limit": -5}}"#, true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit()
            .returning(|_, _| Ok(Some(stored(10))));
        mock.expect_update_limit().never();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_limit(mock), false, None).await;
        let response = patch(state, r#"{"limit": {"resource_limit": 1}}"#, true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let response = patch(state, r#"{"limit": {"resource_limit": 1}}"#, false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
