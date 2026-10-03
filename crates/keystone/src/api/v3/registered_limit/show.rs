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
//! # Show registered limit API
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::{RegisteredLimit, RegisteredLimitResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get a single registered limit.
#[utoipa::path(
    get,
    path = "/{registered_limit_id}",
    description = "Get registered limit by ID",
    params(),
    responses(
        (status = OK, description = "Registered limit object", body = RegisteredLimitResponse),
        (status = 404, description = "Registered limit not found", example = json!(KeystoneApiError::NotFound{resource: "registered_limit".into(), identifier: "id = 1".into()}))
    ),
    tag="registered_limits"
)]
#[tracing::instrument(name = "api::registered_limit_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(registered_limit_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_limit_provider()
        .get_registered_limit(
            &ExecutionContext::from_auth(&state, &user_auth),
            &registered_limit_id,
        )
        .await?
        .map(RegisteredLimit::from);

    state
        .policy_enforcer
        .enforce(
            "identity/registered_limit/show",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"registered_limit": current})),
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(RegisteredLimitResponse {
                registered_limit: current,
            }),
        )
            .into_response()),
        None => Err(KeystoneApiError::NotFound {
            resource: "registered_limit".into(),
            identifier: registered_limit_id,
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

    use openstack_keystone_core_types::limit as provider_types;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;

    fn stored() -> provider_types::RegisteredLimit {
        provider_types::RegisteredLimit {
            default_limit: 10,
            description: None,
            id: "foo".into(),
            region_id: None,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    async fn get(state: crate::keystone::ServiceState, auth: bool) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().uri("/foo");
        if auth {
            request = request.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_show() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(Some(stored())));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = get(state, true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegisteredLimitResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!("foo", res.registered_limit.id);
        assert_eq!(10, res.registered_limit.default_limit);
        // Nullable attributes are present in the response.
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(raw["registered_limit"]["region_id"].is_null());
        assert!(raw["registered_limit"].get("description").is_some());

        let calls = policy.calls();
        assert_eq!(1, calls.len());
        assert_eq!("identity/registered_limit/show", calls[0].policy_name);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        policy_contract::assert_object_keys(
            calls[0].existing.as_ref().unwrap(),
            &["registered_limit"],
        );
        assert!(calls[0].target.is_null());
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(None));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(get(state, true).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_show_forbidden() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(Some(stored())));
        let state =
            get_mocked_state(Provider::mocked_builder().mock_limit(mock), false, None).await;
        assert_eq!(get(state, true).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(get(state, false).await.status(), StatusCode::UNAUTHORIZED);
    }
}
