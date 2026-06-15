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

use eyre::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::group::GroupCreateBuilder;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::*;
use crate::guard::*;
use crate::identity::group::*;
use crate::role::list_roles;

#[tokio::test]
#[traced_test]
async fn test_check_system_role_grant() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let group = create_group(
        &test_client,
        GroupCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&test_client)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member_role = roles.get("member").expect("member role must exist");

    assert!(!check_grant(&test_client, &group.id, member_role).await?);

    add_system_grant(&test_client, &group.id, member_role).await?;

    assert!(check_grant(&test_client, &group.id, member_role).await?);

    group.delete().await?;
    Ok(())
}
