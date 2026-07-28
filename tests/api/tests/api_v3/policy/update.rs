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

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::policy::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::policy::{create_policy, show_policy, update_policy};

/// Mirrors tempest's `test_create_update_delete_policy`: PATCHing only
/// `type` must leave the blob untouched, as observed through a fresh GET.
#[tokio::test]
#[traced_test]
async fn test_update_type_preserves_blob() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!("BlobName-{}", Uuid::new_v4().simple());

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob(blob.clone())
            .r#type(format!("PolicyType-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await?;

    let updated_type = format!("UpdatedPolicyType-{}", Uuid::new_v4().simple());
    let updated = update_policy(
        &tc,
        &guard.id,
        PolicyUpdateBuilder::default()
            .r#type(updated_type.clone())
            .build()?,
    )
    .await?;
    assert_eq!(updated.r#type, updated_type);

    let fetched = show_policy(&tc, &guard.id).await?;
    assert_eq!(fetched.id, guard.id);
    assert_eq!(fetched.r#type, updated_type);
    assert_eq!(
        fetched.blob,
        serde_json::json!(blob),
        "a type-only PATCH must not change the blob"
    );

    guard.delete().await?;
    Ok(())
}

/// Extras supplied on PATCH are merged into the stored ones; omitted stored
/// keys survive (python keystone's `update_policy` semantics).
#[tokio::test]
#[traced_test]
async fn test_update_merges_extra() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .extra(HashMap::from([
                ("keep".to_string(), serde_json::json!("me")),
                ("over".to_string(), serde_json::json!("old")),
            ]))
            .build()?,
    )
    .await?;

    update_policy(
        &tc,
        &guard.id,
        PolicyUpdateBuilder::default()
            .extra(HashMap::from([(
                "over".to_string(),
                serde_json::json!("new"),
            )]))
            .build()?,
    )
    .await?;

    let fetched = show_policy(&tc, &guard.id).await?;
    assert_eq!(
        fetched.extra.get("keep"),
        Some(&serde_json::json!("me")),
        "an omitted stored extra must survive the PATCH"
    );
    assert_eq!(fetched.extra.get("over"), Some(&serde_json::json!("new")));

    guard.delete().await?;
    Ok(())
}

/// An `id` different from the path is rejected ("Cannot change policy ID").
#[tokio::test]
#[traced_test]
async fn test_update_rejects_mismatched_id() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .build()?,
    )
    .await?;

    assert!(
        update_policy(
            &tc,
            &guard.id,
            PolicyUpdateBuilder::default()
                .id(format!("other{}", Uuid::new_v4().simple()))
                .r#type("text/plain")
                .build()?,
        )
        .await
        .is_err(),
        "an id that differs from the path must be refused"
    );

    guard.delete().await?;
    Ok(())
}

/// An empty patch document is refused (`minProperties: 1`).
#[tokio::test]
#[traced_test]
async fn test_update_rejects_empty_document() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .build()?,
    )
    .await?;

    assert!(
        update_policy(&tc, &guard.id, PolicyUpdate::default())
            .await
            .is_err(),
        "an empty patch document must be refused"
    );

    guard.delete().await?;
    Ok(())
}
