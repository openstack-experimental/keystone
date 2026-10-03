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
//! # Limit enforcement model API
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use super::types::{LimitModel, LimitModelResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get the limit enforcement model.
#[utoipa::path(
    get,
    path = "/model",
    description = "Get the limit enforcement model",
    responses(
        (status = OK, description = "The enforcement model", body = LimitModelResponse),
        (status = 500, description = "Internal error")
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::v3::limit_model", level = "debug", skip(state))]
pub(super) async fn model(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/limit/model",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let model = state
        .provider
        .get_limit_provider()
        .get_limit_model(&ExecutionContext::from_auth(&state, &user_auth))
        .await?;

    Ok((
        StatusCode::OK,
        Json(LimitModelResponse {
            model: LimitModel::from(model),
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
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;

    async fn get(state: crate::keystone::ServiceState, auth: bool) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().uri("/model");
        if auth {
            request = request.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_model() {
        let mut mock = MockLimitProvider::default();
        mock.expect_get_limit_model().returning(|_| {
            Ok(provider_types::LimitModel {
                name: "flat".into(),
                description: "descr".into(),
            })
        });
        // `get_limit` must not be reached: `/model` is not a limit ID.
        mock.expect_get_limit().never();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = get(state, true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitModelResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!("flat", res.model.name);
        assert_eq!("descr", res.model.description);

        let calls = policy.calls();
        assert_eq!(1, calls.len());
        assert_eq!("identity/limit/model", calls[0].policy_name);
        assert!(calls[0].target.is_null());
        policy_contract::assert_existing_presence(&calls[0].existing, false);
    }

    #[tokio::test]
    async fn test_model_forbidden() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        assert_eq!(get(state, true).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_model_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(get(state, false).await.status(), StatusCode::UNAUTHORIZED);
    }
}
