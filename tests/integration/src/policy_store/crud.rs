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
//! End-to-end policy store CRUD against a real database.

use std::collections::HashMap;

use eyre::Result;
use serde_json::{Value, json};
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::policy_store::*;

use crate::common::get_state;
use crate::policy_store::create_policy;

fn create_params(r#type: &str, blob: &str) -> PolicyCreate {
    PolicyCreate {
        id: None,
        r#type: r#type.to_string(),
        blob: Value::String(blob.to_string()),
        extra: HashMap::new(),
    }
}

/// The service layer assigns the ID, so the created record always carries one.
#[traced_test]
#[tokio::test]
async fn test_create_assigns_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let policy = create_policy(&state, create_params("application/json", "doc")).await?;

    assert!(!policy.id.is_empty(), "service layer must assign an ID");
    assert_eq!(policy.r#type, "application/json");
    assert_eq!(policy.blob, json!("doc"));
    Ok(())
}

/// A string blob survives the JSON encode/decode round-trip through the
/// `JsonBlob`-compatible `blob` column.
#[traced_test]
#[tokio::test]
async fn test_string_blob_round_trip() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let raw = "{'foobar_user': 'role:compute-user'}";
    let policy = create_policy(&state, create_params("application/json", raw)).await?;

    let fetched = state
        .provider
        .get_policy_store_provider()
        .get_policy(&ExecutionContext::internal(&state), &policy.id)
        .await?
        .expect("policy must be readable after creation");

    assert_eq!(fetched.blob, json!(raw));
    Ok(())
}

/// Unknown properties round-trip through the `extra` column.
#[traced_test]
#[tokio::test]
async fn test_extra_round_trip() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let policy = create_policy(
        &state,
        PolicyCreate {
            id: None,
            r#type: "text/plain".into(),
            blob: json!("b"),
            extra: HashMap::from([("custom".into(), json!("value"))]),
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_policy_store_provider()
        .get_policy(&ExecutionContext::internal(&state), &policy.id)
        .await?
        .expect("policy must be readable");

    assert_eq!(fetched.extra.get("custom"), Some(&json!("value")));
    Ok(())
}

/// `?type=` filtering is an exact match applied in SQL.
#[traced_test]
#[tokio::test]
async fn test_list_filters_by_type_exactly() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let json_policy = create_policy(&state, create_params("application/json", "a")).await?;
    let _text_policy = create_policy(&state, create_params("text/plain", "b")).await?;

    let exec = ExecutionContext::internal(&state);
    let provider = state.provider.get_policy_store_provider();

    let all = provider
        .list_policies(&exec, &PolicyListParameters::default())
        .await?;
    assert!(all.len() >= 2);

    let filtered = provider
        .list_policies(
            &exec,
            &PolicyListParameters {
                r#type: Some("application/json".into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(
        filtered.iter().any(|p| p.id == json_policy.id),
        "matching policy must be listed"
    );
    assert!(
        filtered.iter().all(|p| p.r#type == "application/json"),
        "no other media type may appear"
    );

    // A prefix of a stored type must not match.
    let prefix = provider
        .list_policies(
            &exec,
            &PolicyListParameters {
                r#type: Some("application".into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(prefix.is_empty(), "type filtering must be an exact match");
    Ok(())
}

/// A type-only update leaves the blob alone and merges `extra`, matching
/// python keystone's `update_policy`.
#[traced_test]
#[tokio::test]
async fn test_update_preserves_blob_and_merges_extra() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let policy = create_policy(
        &state,
        PolicyCreate {
            id: None,
            r#type: "application/json".into(),
            blob: json!("original"),
            extra: HashMap::from([("keep".into(), json!("me")), ("over".into(), json!("old"))]),
        },
    )
    .await?;

    let exec = ExecutionContext::internal(&state);
    let updated = state
        .provider
        .get_policy_store_provider()
        .update_policy(
            &exec,
            &policy.id,
            PolicyUpdate {
                r#type: Some("text/plain".into()),
                blob: None,
                extra: HashMap::from([("over".into(), json!("new")), ("add".into(), json!(1))]),
            },
        )
        .await?;

    assert_eq!(updated.r#type, "text/plain");
    assert_eq!(updated.blob, json!("original"), "blob must be preserved");
    assert_eq!(updated.extra.get("keep"), Some(&json!("me")), "omitted key");
    assert_eq!(updated.extra.get("over"), Some(&json!("new")), "new wins");
    assert_eq!(updated.extra.get("add"), Some(&json!(1)), "added key");
    Ok(())
}

/// Updating the blob replaces it, and it still decodes as the same JSON value.
#[traced_test]
#[tokio::test]
async fn test_update_blob() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let policy = create_policy(&state, create_params("application/json", "original")).await?;

    let updated = state
        .provider
        .get_policy_store_provider()
        .update_policy(
            &ExecutionContext::internal(&state),
            &policy.id,
            PolicyUpdate {
                r#type: None,
                blob: Some(json!("replaced")),
                extra: HashMap::new(),
            },
        )
        .await?;

    assert_eq!(updated.blob, json!("replaced"));
    assert_eq!(updated.r#type, "application/json");
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_then_get_is_none() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let policy = create_policy(&state, create_params("application/json", "doc")).await?;
    let id = policy.id.clone();

    let exec = ExecutionContext::internal(&state);
    state
        .provider
        .get_policy_store_provider()
        .delete_policy(&exec, &id)
        .await?;

    assert!(
        state
            .provider
            .get_policy_store_provider()
            .get_policy(&exec, &id)
            .await?
            .is_none()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_missing_is_none() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    assert!(
        state
            .provider
            .get_policy_store_provider()
            .get_policy(&ExecutionContext::internal(&state), "does-not-exist")
            .await?
            .is_none()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_missing_is_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_policy_store_provider()
        .update_policy(
            &ExecutionContext::internal(&state),
            "does-not-exist",
            PolicyUpdate {
                r#type: Some("text/plain".into()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(PolicyStoreProviderError::PolicyNotFound(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_missing_is_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_policy_store_provider()
        .delete_policy(&ExecutionContext::internal(&state), "does-not-exist")
        .await;

    assert!(matches!(
        result,
        Err(PolicyStoreProviderError::PolicyNotFound(_))
    ));
    Ok(())
}

/// `type` is capped at 255 characters by the validator, which must reject the
/// request before it reaches the database.
#[traced_test]
#[tokio::test]
async fn test_create_type_too_long_is_rejected() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_policy_store_provider()
        .create_policy(
            &ExecutionContext::internal(&state),
            create_params(&"x".repeat(256), "doc"),
        )
        .await;

    assert!(
        result.is_err(),
        "expected a validation error for a type longer than 255 characters"
    );
    Ok(())
}
