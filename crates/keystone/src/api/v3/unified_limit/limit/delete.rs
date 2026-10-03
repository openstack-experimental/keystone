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
//! # Delete limit API
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::Limit;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Delete a limit.
#[utoipa::path(
    delete,
    path = "/{limit_id}",
    description = "Delete limit by ID",
    params(),
    responses(
        (status = NO_CONTENT, description = "Limit deleted"),
        (status = 404, description = "Limit not found", example = json!(KeystoneApiError::NotFound{resource: "limit".into(), identifier: "id = 1".into()}))
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::v3::limit_delete", level = "debug", skip(state))]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path(limit_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
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
            "identity/limit/delete",
            &user_auth,
            serde_json::Value::Null,
            Some(existing),
        )
        .await?;

    match current {
        Some(_) => {
            state
                .provider
                .get_limit_provider()
                .delete_limit(&exec, &limit_id)
                .await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        None => Err(KeystoneApiError::NotFound {
            resource: "limit".into(),
            identifier: limit_id,
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
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn stored() -> provider_types::Limit {
        provider_types::Limit {
            description: None,
            domain_id: Some("d1".into()),
            id: "foo".into(),
            project_id: None,
            region_id: None,
            resource_limit: 10,
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
        mock.expect_get_limit().returning(|_, _| Ok(Some(stored())));
        mock.expect_delete_limit()
            .withf(|_, id: &'_ str| id == "foo")
            .times(1)
            .returning(|_, _| Ok(()));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        assert_eq!(delete(state, true).await.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(1, calls.len());
        assert_eq!("identity/limit/delete", calls[0].policy_name);
        assert!(calls[0].target.is_null());
        policy_contract::assert_existing_presence(&calls[0].existing, true);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit().returning(|_, _| Ok(None));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;
        assert_eq!(delete(state, true).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_forbidden() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit().returning(|_, _| Ok(Some(stored())));
        mock.expect_delete_limit().never();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_limit(mock)
                .mock_resource(MockResourceProvider::default()),
            false,
            None,
        )
        .await;
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
