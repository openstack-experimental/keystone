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
//! # Delete registered limit API
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::RegisteredLimit;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Delete a registered limit.
///
/// A registered limit that is referenced by limits can not be deleted.
#[utoipa::path(
    delete,
    path = "/{registered_limit_id}",
    description = "Delete registered limit by ID",
    params(),
    responses(
        (status = NO_CONTENT, description = "Registered limit deleted"),
        (status = 403, description = "Registered limit is referenced by limits"),
        (status = 404, description = "Registered limit not found", example = json!(KeystoneApiError::NotFound{resource: "registered_limit".into(), identifier: "id = 1".into()}))
    ),
    tag="registered_limits"
)]
#[tracing::instrument(name = "api::registered_limit_delete", level = "debug", skip(state))]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path(registered_limit_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_limit_provider()
        .get_registered_limit(&exec, &registered_limit_id)
        .await?
        .map(RegisteredLimit::from);

    state
        .policy_enforcer
        .enforce(
            "identity/registered_limit/delete",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"registered_limit": current})),
        )
        .await?;

    match current {
        Some(_) => {
            state
                .provider
                .get_limit_provider()
                .delete_registered_limit(&exec, &registered_limit_id)
                .await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
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
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::limit as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::limit::{LimitProviderError, MockLimitProvider};
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

    async fn delete(state: crate::keystone::ServiceState, auth: bool) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().method("DELETE").uri("/foo");
        if auth {
            request = request.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_delete() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_delete_registered_limit()
            .withf(|_, id: &'_ str| id == "foo")
            .times(1)
            .returning(|_, _| Ok(()));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        assert_eq!(delete(state, true).await.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(1, calls.len());
        assert_eq!("identity/registered_limit/delete", calls[0].policy_name);
        assert!(calls[0].target.is_null());
        policy_contract::assert_existing_presence(&calls[0].existing, true);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(None));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(delete(state, true).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_referenced() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_delete_registered_limit()
            .returning(|_, id| Err(LimitProviderError::RegisteredLimitInUse(id.to_string())));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(delete(state, true).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_forbidden() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_delete_registered_limit().never();
        let state =
            get_mocked_state(Provider::mocked_builder().mock_limit(mock), false, None).await;
        assert_eq!(delete(state, true).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(
            delete(state, false).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
