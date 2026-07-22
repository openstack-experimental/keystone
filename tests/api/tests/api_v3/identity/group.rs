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

use openstack_keystone_api_types::v3::group::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::identity::group::{create_group, get_group, update_group};

#[tokio::test]
#[traced_test]
async fn test_update() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("grp_{}", Uuid::new_v4().simple());
    let new_name = format!("{name}_updated");

    let guard = create_group(
        &tc,
        GroupCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .build()?,
    )
    .await?;

    let updated = update_group(
        &tc,
        &guard.id,
        GroupUpdateBuilder::default()
            .name(new_name.clone())
            .build()?,
    )
    .await?;

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.id, guard.id);

    let shown = get_group(&tc, &guard.id).await?;
    assert_eq!(shown.name, new_name);

    guard.delete().await?;
    Ok(())
}
