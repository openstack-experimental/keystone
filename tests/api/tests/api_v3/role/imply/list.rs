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

use test_api::role::imply::*;
use test_api::role::{create_role, delete_role};

#[tokio::test]
#[traced_test]
async fn test_list_implied_role() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let prior_name = format!("prior_{}", Uuid::new_v4().simple());
    let implied1_name = format!("implied1_{}", Uuid::new_v4().simple());
    let implied2_name = format!("implied2_{}", Uuid::new_v4().simple());

    let prior_role =
        create_role(&tc, RoleCreateBuilder::default().name(prior_name).build()?).await?;
    let implied1 = create_role(
        &tc,
        RoleCreateBuilder::default().name(implied1_name).build()?,
    )
    .await?;
    let implied2 = create_role(
        &tc,
        RoleCreateBuilder::default().name(implied2_name).build()?,
    )
    .await?;

    create_implied_role(&tc, &prior_role.id, &implied1.id).await?;
    create_implied_role(&tc, &prior_role.id, &implied2.id).await?;

    let group = list_implied_role(&tc, &prior_role.id).await?;

    assert_eq!(group.role_inference.prior_role.id, prior_role.id);
    assert_eq!(group.role_inference.prior_role.name, prior_role.name);
    assert_eq!(group.role_inference.implies.len(), 2);

    let implied_ids: Vec<_> = group
        .role_inference
        .implies
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(implied_ids.contains(&implied1.id.as_str()));
    assert!(implied_ids.contains(&implied2.id.as_str()));

    delete_implied_role(&tc, &prior_role.id, &implied1.id).await?;
    delete_implied_role(&tc, &prior_role.id, &implied2.id).await?;
    delete_role(&tc, &implied2.id).await?;
    delete_role(&tc, &implied1.id).await?;
    delete_role(&tc, &prior_role.id).await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_implied_role_empty() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let prior_name = format!("prior_{}", Uuid::new_v4().simple());

    let prior_role =
        create_role(&tc, RoleCreateBuilder::default().name(prior_name).build()?).await?;

    let group = list_implied_role(&tc, &prior_role.id).await?;

    assert_eq!(group.role_inference.prior_role.id, prior_role.id);
    assert_eq!(group.role_inference.prior_role.name, prior_role.name);
    assert_eq!(group.role_inference.implies.len(), 0);

    delete_role(&tc, &prior_role.id).await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_implied_role_isolated() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let prior1_name = format!("prior1_{}", Uuid::new_v4().simple());
    let prior2_name = format!("prior2_{}", Uuid::new_v4().simple());
    let implied1_name = format!("implied1_{}", Uuid::new_v4().simple());

    let prior1 = create_role(&tc, RoleCreateBuilder::default().name(prior1_name).build()?).await?;
    let prior2 = create_role(&tc, RoleCreateBuilder::default().name(prior2_name).build()?).await?;
    let implied1 = create_role(
        &tc,
        RoleCreateBuilder::default().name(implied1_name).build()?,
    )
    .await?;

    create_implied_role(&tc, &prior1.id, &implied1.id).await?;

    let group1 = list_implied_role(&tc, &prior1.id).await?;
    let group2 = list_implied_role(&tc, &prior2.id).await?;

    assert_eq!(group1.role_inference.prior_role.id, prior1.id);
    assert_eq!(group1.role_inference.implies.len(), 1);
    assert_eq!(group1.role_inference.implies[0].id, implied1.id);

    assert_eq!(group2.role_inference.prior_role.id, prior2.id);
    assert_eq!(group2.role_inference.implies.len(), 0);

    delete_implied_role(&tc, &prior1.id, &implied1.id).await?;
    delete_role(&tc, &implied1.id).await?;
    delete_role(&tc, &prior2.id).await?;
    delete_role(&tc, &prior1.id).await?;
    Ok(())
}
