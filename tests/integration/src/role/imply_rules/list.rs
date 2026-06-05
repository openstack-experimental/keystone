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
//! Test role imply rule listing.

use eyre::Result;
use std::collections::BTreeSet;
use uuid::Uuid;

use openstack_keystone::role::RoleApi;
use openstack_keystone_core_types::role::*;

use crate::common::get_state;
use crate::create_role;

fn rule_key(rule: &RoleImply) -> (String, String) {
    (rule.prior_role.id.clone(), rule.implied_role.id.clone())
}

#[tokio::test]
async fn test_list_imply_rules_empty() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    assert!(rules.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_single() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].prior_role.id, prior_role.id);
    assert_eq!(rules[0].implied_role.id, implied_role.id);

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_multiple() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role_a = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_b = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_c = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_d = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &role_a.id, &role_b.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &role_a.id, &role_c.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &role_b.id, &role_d.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    assert_eq!(rules.len(), 3);

    let rule_keys: BTreeSet<(String, String)> = rules.iter().map(rule_key).collect();
    assert!(rule_keys.contains(&(role_a.id.clone(), role_b.id.clone())));
    assert!(rule_keys.contains(&(role_a.id.clone(), role_c.id.clone())));
    assert!(rule_keys.contains(&(role_b.id.clone(), role_d.id.clone())));

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_after_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;
    assert_eq!(rules.len(), 1);

    state
        .provider
        .get_role_provider()
        .delete_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;
    assert!(rules.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_with_domain_roles() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(
        state,
        Uuid::new_v4().simple().to_string(),
        "default".to_string()
    )?;
    let implied_role = create_role!(
        state,
        Uuid::new_v4().simple().to_string(),
        "default".to_string()
    )?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].prior_role.id, prior_role.id);
    assert_eq!(rules[0].implied_role.id, implied_role.id);

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_mixed_global_and_domain_roles() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let global_prior = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let global_implied = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let domain_prior = create_role!(
        state,
        Uuid::new_v4().simple().to_string(),
        "default".to_string()
    )?;
    let domain_implied = create_role!(
        state,
        Uuid::new_v4().simple().to_string(),
        "default".to_string()
    )?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &global_prior.id, &global_implied.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &domain_prior.id, &domain_implied.id)
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules(&state)
        .await?;

    assert_eq!(rules.len(), 2);

    let rule_keys: BTreeSet<(String, String)> = rules.iter().map(rule_key).collect();
    assert!(rule_keys.contains(&(global_prior.id.clone(), global_implied.id.clone())));
    assert!(rule_keys.contains(&(domain_prior.id.clone(), domain_implied.id.clone())));

    Ok(())
}
