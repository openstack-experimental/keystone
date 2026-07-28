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
//! # Show policy API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use super::types::{Policy, PolicyResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get a single policy.
#[utoipa::path(
    get,
    path = "/{policy_id}",
    description = "Get policy by ID",
    params(),
    responses(
        (status = OK, description = "Policy object", body = PolicyResponse),
        (status = 404, description = "Policy not found")
    ),
    tag="policies"
)]
#[tracing::instrument(
    name = "api::policy_show",
    level = "debug",
    skip_all,
    fields(policy_id = %policy_id)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(policy_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_policy_store_provider()
        .get_policy(&ExecutionContext::from_auth(&state, &user_auth), &policy_id)
        .await?
        .map(Policy::from);

    state
        .policy_enforcer
        .enforce(
            "identity/policy/show",
            &user_auth,
            serde_json::Value::Null,
            Some(super::policy_input(
                current
                    .as_ref()
                    .map(Policy::to_policy_input)
                    .unwrap_or(serde_json::Value::Null),
            )),
        )
        .await?;

    match current {
        Some(policy) => Ok((StatusCode::OK, Json(PolicyResponse { policy })).into_response()),
        None => Err(KeystoneApiError::NotFound {
            resource: "policy".into(),
            identifier: policy_id,
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

    use openstack_keystone_core_types::policy_store::PolicyBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::policy::types::PolicyResponse;
    use crate::policy_store::MockPolicyStoreProvider;
    use crate::provider::Provider;

    fn stored() -> openstack_keystone_core_types::policy_store::Policy {
        PolicyBuilder::default()
            .id("pid")
            .r#type("application/json")
            .blob(serde_json::Value::String("s3cr3t-doc".into()))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_show() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .withf(|_, id: &str| id == "pid")
            .returning(|_, _| Ok(Some(stored())));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/pid")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policy.id, "pid");
        assert_eq!(res.policy.blob, serde_json::json!("s3cr3t-doc"));
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy().returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_show_forbidden() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/pid")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/pid").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B2 (issue #978): the stored record is keyed under `existing`, the
    /// target is null, and the document never reaches OPA.
    #[tokio::test]
    async fn test_show_policy_input_contract() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy().returning(|_, _| {
            let mut policy = stored();
            policy
                .extra
                .insert("password".into(), serde_json::json!("hunter2"));
            Ok(Some(policy))
        });

        let vsc = test_fixture_scoped();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_policy_store(mock)).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/pid")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/policy/show");
        assert_eq!(calls[0].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["policy"]);
        policy_contract::assert_no_secrets(existing);
        let rendered = existing.to_string();
        assert!(!rendered.contains("s3cr3t-doc"));
        assert!(!rendered.contains("hunter2"));
    }
}
