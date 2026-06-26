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
//! Test role imply rule creation.

use eyre::Result;
use uuid::Uuid;

use crate::common::get_state;
use crate::create_role;
use openstack_keystone_core::auth::ExecutionContext;

#[tokio::test]
async fn test_create_imply_rule() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    let rule = state
        .provider
        .get_role_provider()
        .create_role_imply_rule(
            &ExecutionContext::internal(&state),
            &prior_role.id,
            &implied_role.id,
        )
        .await?;

    assert_eq!(rule.prior_role.id, prior_role.id);
    assert_eq!(rule.prior_role.name, Some(prior_role.name.clone()));
    assert_eq!(rule.prior_role.domain_id, prior_role.domain_id.clone());
    assert_eq!(rule.implied_role.id, implied_role.id);
    assert_eq!(rule.implied_role.name, Some(implied_role.name.clone()));
    assert_eq!(rule.implied_role.domain_id, implied_role.domain_id.clone());

    Ok(())
}

#[tokio::test]
async fn test_create_imply_rule_with_domain_roles() -> Result<()> {
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

    let rule = state
        .provider
        .get_role_provider()
        .create_role_imply_rule(
            &ExecutionContext::internal(&state),
            &prior_role.id,
            &implied_role.id,
        )
        .await?;

    assert_eq!(rule.prior_role.id, prior_role.id);
    assert_eq!(rule.prior_role.name, Some(prior_role.name.clone()));
    assert_eq!(rule.prior_role.domain_id, prior_role.domain_id.clone());
    assert_eq!(rule.implied_role.id, implied_role.id);
    assert_eq!(rule.implied_role.name, Some(implied_role.name.clone()));
    assert_eq!(rule.implied_role.domain_id, implied_role.domain_id.clone());

    Ok(())
}

#[tokio::test]
async fn test_create_imply_rule_global_roles() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let prior_role = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let implied_role = create_role!(state, Uuid::new_v4().simple().to_string())?;

    assert!(prior_role.domain_id.is_none());
    assert!(implied_role.domain_id.is_none());

    let rule = state
        .provider
        .get_role_provider()
        .create_role_imply_rule(
            &ExecutionContext::internal(&state),
            &prior_role.id,
            &implied_role.id,
        )
        .await?;

    assert_eq!(rule.prior_role.id, prior_role.id);
    assert_eq!(rule.prior_role.name, Some(prior_role.name.clone()));
    assert_eq!(rule.prior_role.domain_id, prior_role.domain_id.clone());
    assert_eq!(rule.implied_role.id, implied_role.id);
    assert_eq!(rule.implied_role.name, Some(implied_role.name.clone()));
    assert_eq!(rule.implied_role.domain_id, implied_role.domain_id.clone());

    Ok(())
}
