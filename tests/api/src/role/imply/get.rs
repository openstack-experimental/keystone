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

use openstack_keystone_api_types::v3::role::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::super::{create_role, delete_role};
use super::*;

#[tokio::test]
#[traced_test]
async fn test_get_implied_role() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let prior_name = format!("prior_{}", Uuid::new_v4().simple());
    let implied_name = format!("implied_{}", Uuid::new_v4().simple());

    let prior_role =
        create_role(&tc, RoleCreateBuilder::default().name(prior_name).build()?).await?;
    let implied_role = create_role(
        &tc,
        RoleCreateBuilder::default().name(implied_name).build()?,
    )
    .await?;

    create_implied_role(&tc, &prior_role.id, &implied_role.id).await?;

    let rule = get_implied_role(&tc, &prior_role.id, &implied_role.id).await?;

    assert_eq!(rule.prior_role.id, prior_role.id);
    assert_eq!(rule.implied_role.id, implied_role.id);
    assert_eq!(rule.prior_role.name, prior_role.name);
    assert_eq!(rule.implied_role.name, implied_role.name);

    delete_implied_role(&tc, &prior_role.id, &implied_role.id).await?;
    delete_role(&tc, &implied_role.id).await?;
    delete_role(&tc, &prior_role.id).await?;
    Ok(())
}
