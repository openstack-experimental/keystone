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
//! # Update policy API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{Policy, PolicyResponse, PolicyUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update an existing policy.
///
/// Only the supplied fields change; `extra` properties are merged into the
/// stored ones. Two request-shape rules are inherited from python keystone:
///
/// * an empty `{"policy": {}}` document is a 400 (`minProperties: 1` in
///   `keystone/policy/schema.py`), and
/// * an `id` in the body is accepted only when it equals `{policy_id}`, else
///   400 ("Cannot change policy ID" in `Manager.update_policy`). It is never
///   persisted either way.
#[utoipa::path(
    patch,
    path = "/{policy_id}",
    description = "Update policy by ID",
    params(),
    responses(
        (status = OK, description = "Updated policy", body = PolicyResponse),
        (status = 400, description = "Invalid input"),
        (status = 404, description = "Policy not found")
    ),
    tag="policies"
)]
// `skip_all` for the same reason as `create`: the patch body may carry a new
// `blob` and arbitrary `extra` properties.
#[tracing::instrument(
    name = "api::policy_update",
    level = "debug",
    skip_all,
    fields(policy_id = %policy_id)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(policy_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<PolicyUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    if req.policy.is_empty() {
        return Err(KeystoneApiError::BadRequest(
            "at least one policy property must be supplied".into(),
        ));
    }

    if let Some(body_id) = &req.policy.id
        && *body_id != policy_id
    {
        return Err(KeystoneApiError::BadRequest(
            "Cannot change policy ID".into(),
        ));
    }

    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_policy_store_provider()
        .get_policy(&exec, &policy_id)
        .await?
        .map(Policy::from);

    state
        .policy_enforcer
        .enforce(
            "identity/policy/update",
            &user_auth,
            super::policy_input(req.policy.to_policy_input()),
            Some(super::policy_input(
                current
                    .as_ref()
                    .map(Policy::to_policy_input)
                    .unwrap_or(serde_json::Value::Null),
            )),
        )
        .await?;

    match current {
        Some(_) => {
            let updated = state
                .provider
                .get_policy_store_provider()
                .update_policy(&exec, &policy_id, req.into())
                .await?;
            Ok((
                StatusCode::OK,
                Json(PolicyResponse {
                    policy: Policy::from(updated),
                }),
            )
                .into_response())
        }
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

    use openstack_keystone_core_types::policy_store::{PolicyBuilder, PolicyUpdate};

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
            .blob(serde_json::Value::String("original blob".into()))
            .build()
            .unwrap()
    }

    async fn patch(body: &'static str, mock: MockPolicyStoreProvider) -> axum::response::Response {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        // Mount the production `normalize_json_rejection` layer so
        // type-mismatch bodies surface as the 400 the service actually
        // returns rather than axum's raw 422.
        let mut api = openapi_router()
            .layer(axum::middleware::map_response(
                crate::api::json_rejection::normalize_json_rejection,
            ))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        api.as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/pid")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// A type-only PATCH must not touch the blob — the exact assertion in
    /// tempest's `test_create_update_delete_policy`.
    #[tokio::test]
    async fn test_update_type_only() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_update_policy()
            .withf(|_, id: &str, upd: &PolicyUpdate| {
                id == "pid" && upd.r#type == Some("text/plain".into()) && upd.blob.is_none()
            })
            .returning(|_, _, _| {
                let mut policy = stored();
                policy.r#type = "text/plain".into();
                Ok(policy)
            });

        let response = patch(r#"{"policy": {"type": "text/plain"}}"#, mock).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policy.r#type, "text/plain");
        assert_eq!(res.policy.blob, serde_json::json!("original blob"));
    }

    /// An `id` equal to the path is accepted and not persisted.
    #[tokio::test]
    async fn test_update_accepts_matching_id_without_persisting_it() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_update_policy()
            .withf(|_, _: &str, upd: &PolicyUpdate| !upd.extra.contains_key("id"))
            .returning(|_, _, _| Ok(stored()));

        let response = patch(r#"{"policy": {"id": "pid", "type": "text/plain"}}"#, mock).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// An `id` different from the path is a 400, matching python keystone's
    /// "Cannot change policy ID".
    #[tokio::test]
    async fn test_update_rejects_mismatched_id() {
        let response = patch(
            r#"{"policy": {"id": "other", "type": "text/plain"}}"#,
            MockPolicyStoreProvider::default(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// `minProperties: 1`: an empty patch document is a 400.
    #[tokio::test]
    async fn test_update_rejects_empty_document() {
        let response = patch(r#"{"policy": {}}"#, MockPolicyStoreProvider::default()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Requests carry a string blob only.
    #[tokio::test]
    async fn test_update_rejects_object_blob() {
        let response = patch(
            r#"{"policy": {"blob": {"foobar_user": ["role:compute-user"]}}}"#,
            MockPolicyStoreProvider::default(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Supplied extras are forwarded for merging; the driver preserves the
    /// omitted stored ones.
    #[tokio::test]
    async fn test_update_forwards_extra_for_merge() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_update_policy()
            .withf(|_, _: &str, upd: &PolicyUpdate| {
                upd.extra.get("added") == Some(&serde_json::json!("x"))
            })
            .returning(|_, _, _| Ok(stored()));

        let response = patch(r#"{"policy": {"added": "x"}}"#, mock).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy().returning(|_, _| Ok(None));

        let response = patch(r#"{"policy": {"type": "text/plain"}}"#, mock).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
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
                    .method("PATCH")
                    .uri("/pid")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(r#"{"policy": {"type": "text/plain"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/pid")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"policy": {"type": "text/plain"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B2 (issue #978): the requested change goes to `target`, the
    /// stored record to `existing` (not swapped), and neither carries the
    /// document or arbitrary extras.
    #[tokio::test]
    async fn test_update_policy_input_contract() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_update_policy()
            .returning(|_, _, _| Ok(stored()));

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
                    .method("PATCH")
                    .uri("/pid")
                    .header("content-type", "application/json")
                    .extension(vsc)
                    .body(Body::from(
                        r#"{"policy": {"type": "text/plain", "blob": "new-s3cr3t", "totp_seed": "AAAA"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/policy/update");

        policy_contract::assert_object_keys(&calls[0].target, &["policy"]);
        policy_contract::assert_no_secrets(&calls[0].target);
        assert_eq!(calls[0].target["policy"]["type"], "text/plain");

        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["policy"]);
        policy_contract::assert_no_secrets(existing);
        assert_eq!(
            existing["policy"]["type"], "application/json",
            "existing must be the stored record, not the request"
        );

        for value in [&calls[0].target, existing] {
            let rendered = value.to_string();
            for needle in ["new-s3cr3t", "original blob", "AAAA"] {
                assert!(
                    !rendered.contains(needle),
                    "{needle} leaked into policy input: {rendered}"
                );
            }
        }
    }
}
