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
//! # Create policy API

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{Policy, PolicyCreateRequest, PolicyResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new policy.
///
/// Any caller-supplied `id` in the body is discarded and a fresh UUID
/// assigned, matching python keystone's `_assign_unique_id`.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="policies"
)]
// `skip_all`, not `skip(state)`: the request body carries the policy
// document (`blob`) and an open-ended `extra` map of caller-supplied JSON,
// both of which `tracing::instrument` would otherwise render into the span
// via `Debug`. Only the non-sensitive media type is recorded.
#[tracing::instrument(
    name = "api::v3::policy_create",
    level = "debug",
    skip_all,
    fields(policy_type = %payload.policy.r#type)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<PolicyCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/policy/create",
            &user_auth,
            super::policy_input(payload.policy.to_policy_input()),
            None,
        )
        .await?;

    let created = state
        .provider
        .get_policy_store_provider()
        .create_policy(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(PolicyResponse {
            policy: Policy::from(created),
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

    use openstack_keystone_core_types::policy_store::{PolicyBuilder, PolicyCreate};

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::policy::types::PolicyResponse;
    use crate::policy_store::MockPolicyStoreProvider;
    use crate::provider::Provider;

    fn stored(
        id: &str,
        r#type: &str,
        blob: &str,
    ) -> openstack_keystone_core_types::policy_store::Policy {
        PolicyBuilder::default()
            .id(id)
            .r#type(r#type)
            .blob(serde_json::Value::String(blob.into()))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_create() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_create_policy()
            .withf(|_, req: &PolicyCreate| {
                req.r#type == "application/json"
                    && req.blob == serde_json::Value::String("blob text".into())
            })
            .returning(|_, _| Ok(stored("pid", "application/json", "blob text")));

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
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "application/json", "blob": "blob text"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policy.id, "pid");
        assert_eq!(res.policy.blob, serde_json::json!("blob text"));
    }

    /// A caller-supplied `id` must be replaced by a server-generated one and
    /// must not be smuggled into `extra` (python keystone's
    /// `_assign_unique_id` behaviour).
    #[tokio::test]
    async fn test_create_discards_caller_supplied_id() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_create_policy()
            .withf(|_, req: &PolicyCreate| req.id.is_none() && !req.extra.contains_key("id"))
            .returning(|_, _| Ok(stored("server-generated", "t", "b")));

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
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "t", "blob": "b", "id": "caller-supplied"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policy.id, "server-generated");
    }

    /// Unknown properties round-trip through `extra`.
    #[tokio::test]
    async fn test_create_unknown_properties_round_trip() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_create_policy()
            .withf(|_, req: &PolicyCreate| {
                req.extra.get("custom") == Some(&serde_json::json!("value"))
            })
            .returning(|_, _| {
                let mut policy = stored("pid", "t", "b");
                policy
                    .extra
                    .insert("custom".into(), serde_json::json!("value"));
                Ok(policy)
            });

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
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "t", "blob": "b", "custom": "value"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res.policy.extra.get("custom"),
            Some(&serde_json::json!("value"))
        );
    }

    /// The HTTP contract accepts a string `blob` only, mirroring python
    /// keystone's `{'blob': {'type': 'string'}}` jsonschema.
    ///
    /// Mounts the production `normalize_json_rejection` layer (applied on the
    /// real router in `crate::api::openapi_router`), so this asserts the 400
    /// the service actually returns rather than axum's raw 422.
    #[tokio::test]
    async fn test_create_rejects_object_blob() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(axum::middleware::map_response(
                crate::api::json_rejection::normalize_json_rejection,
            ))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "t", "blob": {"foobar_user": ["role:compute-user"]}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(r#"{"policy": {"type": "t", "blob": "b"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"policy": {"type": "t", "blob": "b"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B2 (issue #978): the handler must feed `enforce()` exactly the
    /// contract `identity/policy/create.rego` documents, with no secret or
    /// caller-controlled payload anywhere in it.
    #[tokio::test]
    async fn test_create_policy_input_contract() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_create_policy()
            .returning(|_, _| Ok(stored("pid", "application/json", "b")));

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
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "application/json", "blob": "s3cr3t-doc", "password": "hunter2", "nested": {"totp_seed": "AAAA"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/policy/create");
        policy_contract::assert_object_keys(&calls[0].target, &["policy"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);

        let rendered = calls[0].target.to_string();
        for needle in ["s3cr3t-doc", "hunter2", "AAAA"] {
            assert!(
                !rendered.contains(needle),
                "{needle} leaked into policy input: {rendered}"
            );
        }
    }
}
