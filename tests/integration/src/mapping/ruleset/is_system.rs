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

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::mapping::error::MappingProviderError;
use openstack_keystone_core_types::mapping::*;

use super::{create_ruleset, sample_ruleset_create};

use crate::common::get_state;
use crate::create_domain;

#[tokio::test]
async fn test_system_ruleset_immutable() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let system_rule = MappingRule {
        name: "system-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "${name}".into(),
            user_id: None,
            user_domain_id: None,
            is_system: true,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    };

    let mut create = sample_ruleset_create(Some(domain.id.clone()));
    create.rules = vec![system_rule];
    let ruleset_guard = create_ruleset(&state, create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    // 1. Test update rejection
    let update_result = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &mapping_id,
            MappingRuleSetUpdate {
                enabled: Some(false),
                allowed_domains: None,
                rules: None,
            },
        )
        .await;

    assert!(update_result.is_err());
    assert!(matches!(
        update_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    // 2. Test mutate rejection
    let mutate_result = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Delete {
                    rule_name: "system-rule".into(),
                }],
            },
        )
        .await;

    assert!(mutate_result.is_err());
    assert!(matches!(
        mutate_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    // 3. Test delete rejection
    let delete_result = state
        .provider
        .get_mapping_provider()
        .delete_ruleset(&ExecutionContext::internal(&state), &mapping_id)
        .await;

    assert!(delete_result.is_err());
    assert!(matches!(
        delete_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    Ok(())
}

#[tokio::test]
async fn test_system_global_ruleset_immutable() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let system_rule = MappingRule {
        name: "global-system-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "${name}".into(),
            user_id: None,
            user_domain_id: None,
            is_system: true,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    };

    let mut create = sample_ruleset_create(None::<String>);
    create.rules = vec![system_rule];
    let ruleset_guard = create_ruleset(&state, create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    // 1. Test update rejection
    let update_result = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &mapping_id,
            MappingRuleSetUpdate {
                enabled: Some(false),
                allowed_domains: None,
                rules: None,
            },
        )
        .await;

    assert!(update_result.is_err());
    assert!(matches!(
        update_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    // 2. Test mutate rejection
    let mutate_result = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Delete {
                    rule_name: "global-system-rule".into(),
                }],
            },
        )
        .await;

    assert!(mutate_result.is_err());
    assert!(matches!(
        mutate_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    // 3. Test delete rejection
    let delete_result = state
        .provider
        .get_mapping_provider()
        .delete_ruleset(&ExecutionContext::internal(&state), &mapping_id)
        .await;

    assert!(delete_result.is_err());
    assert!(matches!(
        delete_result.unwrap_err(),
        MappingProviderError::RulesetImmutable(_)
    ));

    Ok(())
}
