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
//! Test role imply rule listing by prior role.

use eyre::Result;
use uuid::Uuid;

use crate::common::get_state;
use crate::create_role;
use openstack_keystone_core::auth::ExecutionContext;

#[tokio::test]
async fn test_list_imply_rules_by_prior_empty() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &prior_role.id)
        .await?;

    assert!(rules.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_by_prior_single() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(
            &ExecutionContext::internal(&state),
            &prior_role.id,
            &implied_role.id,
        )
        .await?;

    let rules = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &prior_role.id)
        .await?;

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].prior_role.id, prior_role.id);
    assert_eq!(rules[0].implied_role.id, implied_role.id);

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_by_prior_multiple() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role_a = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_b = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_c = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_d = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let role_e = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &role_a.id, &role_b.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &role_a.id, &role_c.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &role_a.id, &role_d.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &role_b.id, &role_e.id)
        .await?;

    let rules_a = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &role_a.id)
        .await?;

    assert_eq!(rules_a.len(), 3);
    for rule in &rules_a {
        assert_eq!(rule.prior_role.id, role_a.id);
    }

    let rules_b = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &role_b.id)
        .await?;

    assert_eq!(rules_b.len(), 1);
    assert_eq!(rules_b[0].prior_role.id, role_b.id);
    assert_eq!(rules_b[0].implied_role.id, role_e.id);

    Ok(())
}

#[tokio::test]
async fn test_list_imply_rules_by_prior_filters_out_other_prior_roles() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior1 = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let prior2 = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied = create_role!(state, Uuid::new_v4().simple().to_string())?;

    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &prior1.id, &implied.id)
        .await?;
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(&state), &prior2.id, &implied.id)
        .await?;

    let rules1 = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &prior1.id)
        .await?;

    assert_eq!(rules1.len(), 1);
    assert_eq!(rules1[0].prior_role.id, prior1.id);

    let rules2 = state
        .provider
        .get_role_provider()
        .list_role_imply_rules_by_prior(&ExecutionContext::internal(&state), &prior2.id)
        .await?;

    assert_eq!(rules2.len(), 1);
    assert_eq!(rules2[0].prior_role.id, prior2.id);

    Ok(())
}
