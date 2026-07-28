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
use test_api::policy::create_policy;

/// The blob goes in as a string and comes back as the same string — the
/// assertion tempest's `test_create_update_delete_policy` makes.
#[tokio::test]
#[traced_test]
async fn test_create_policy() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!("BlobName-{}", Uuid::new_v4().simple());
    let policy_type = format!("PolicyType-{}", Uuid::new_v4().simple());

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob(blob.clone())
            .r#type(policy_type.clone())
            .build()?,
    )
    .await?;

    assert!(!guard.id.is_empty(), "the server must assign an ID");
    assert_eq!(guard.blob, serde_json::json!(blob));
    assert_eq!(guard.r#type, policy_type);

    guard.delete().await?;
    Ok(())
}

/// A caller-supplied `id` is discarded (python keystone's
/// `_assign_unique_id`) and must not resurface as an extra property.
#[tokio::test]
#[traced_test]
async fn test_create_policy_ignores_caller_supplied_id() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let requested = format!("caller{}", Uuid::new_v4().simple());

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .id(requested.clone())
            .build()?,
    )
    .await?;

    assert_ne!(guard.id, requested, "caller-supplied id must be replaced");
    assert!(!guard.extra.contains_key("id"));

    guard.delete().await?;
    Ok(())
}

/// Unknown properties round-trip through `extra`.
#[tokio::test]
#[traced_test]
async fn test_create_policy_round_trips_extra() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .extra(HashMap::from([(
                "custom".to_string(),
                serde_json::json!("value"),
            )]))
            .build()?,
    )
    .await?;

    assert_eq!(guard.extra.get("custom"), Some(&serde_json::json!("value")));

    guard.delete().await?;
    Ok(())
}
