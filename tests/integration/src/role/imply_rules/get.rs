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
//! Test role imply rule retrieval.

use eyre::Result;
use uuid::Uuid;

use openstack_keystone::role::RoleApi;

use crate::common::get_state;
use crate::create_role;

#[tokio::test]
async fn test_get_imply_rule() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    let rule = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?
        .unwrap();

    assert_eq!(rule.id.as_deref(), Some(prior_role.id.as_str()));
    assert_eq!(
        rule.implies_role_id.as_deref(),
        Some(implied_role.id.as_str())
    );

    Ok(())
}

#[tokio::test]
async fn test_get_nonexistent_imply_rule() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    let rule = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?;

    assert!(rule.is_none());

    Ok(())
}

#[tokio::test]
async fn test_get_imply_rule_with_domain_roles() -> Result<()> {
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

    let rule = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &prior_role.id, &implied_role.id)
        .await?
        .unwrap();

    assert_eq!(rule.id.as_deref(), Some(prior_role.id.as_str()));
    assert_eq!(
        rule.implies_role_id.as_deref(),
        Some(implied_role.id.as_str())
    );

    Ok(())
}

#[tokio::test]
async fn test_get_imply_rule_wrong_pair() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role_a = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_b = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_c = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&state, &role_a.id, &role_b.id)
        .await?;

    let rule_ab = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &role_a.id, &role_b.id)
        .await?;
    assert!(rule_ab.is_some());

    let rule_ac = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &role_a.id, &role_c.id)
        .await?;
    assert!(rule_ac.is_none());

    let rule_ba = state
        .provider
        .get_role_provider()
        .get_role_imply_rule(&state, &role_b.id, &role_a.id)
        .await?;
    assert!(rule_ba.is_none());

    Ok(())
}
