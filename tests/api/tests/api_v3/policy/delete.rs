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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::policy::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::policy::{create_policy, delete_policy, show_policy};

#[tokio::test]
#[traced_test]
async fn test_delete_policy() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let guard = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("blob")
            .r#type("application/json")
            .build()?,
    )
    .await?;
    let id = guard.id.clone();

    // The guard's consuming `delete()` *is* the call under test, so no second
    // DELETE is issued and the leak detection stays satisfied.
    guard.delete().await?;

    assert!(
        show_policy(&tc, &id).await.is_err(),
        "a deleted policy must no longer be readable"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_missing_policy_is_404() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    assert!(
        delete_policy(&tc, format!("missing{}", Uuid::new_v4().simple()))
            .await
            .is_err()
    );
    Ok(())
}
