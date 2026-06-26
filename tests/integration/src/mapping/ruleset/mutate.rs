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
use openstack_keystone_core_types::mapping::mutation::{RuleMutation, RuleMutations, RulePosition};
use openstack_keystone_core_types::mapping::*;

use super::{create_ruleset, sample_rule, sample_ruleset_create};

use crate::common::get_state;
use crate::create_domain;

#[tokio::test]
async fn test_mutate_rules_insert_before() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    // Create ruleset with two rules: A and B
    let mut create = sample_ruleset_create(Some(domain.id.clone()));
    create.rules = vec![
        MappingRule {
            name: "rule-a".into(),
            ..sample_rule()
        },
        MappingRule {
            name: "rule-b".into(),
            ..sample_rule()
        },
    ];
    let ruleset_guard = create_ruleset(&state, create).await?;

    // Insert rule X before B
    let rule_x = MappingRule {
        name: "rule-x".into(),
        ..sample_rule()
    };
    let updated_ruleset = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &ruleset_guard.mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Insert {
                    rule: rule_x,
                    position: Some(RulePosition::Before {
                        anchor: "rule-b".into(),
                    }),
                }],
            },
        )
        .await?;

    assert_eq!(updated_ruleset.rules[0].name, "rule-a");
    assert_eq!(updated_ruleset.rules[1].name, "rule-x");
    assert_eq!(updated_ruleset.rules[2].name, "rule-b");

    Ok(())
}

#[tokio::test]
async fn test_mutate_rules_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut create = sample_ruleset_create(Some(domain.id.clone()));
    create.rules = vec![MappingRule {
        name: "rule-a".into(),
        ..sample_rule()
    }];
    let ruleset_guard = create_ruleset(&state, create).await?;

    let updated_rule = MappingRule {
        name: "rule-a".into(),
        description: Some("Updated description".into()),
        ..sample_rule()
    };

    let updated_ruleset = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &ruleset_guard.mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Update {
                    rule_name: "rule-a".into(),
                    rule: updated_rule,
                }],
            },
        )
        .await?;

    assert_eq!(
        updated_ruleset.rules[0].description.as_deref(),
        Some("Updated description")
    );

    Ok(())
}

#[tokio::test]
async fn test_mutate_rules_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut create = sample_ruleset_create(Some(domain.id.clone()));
    create.rules = vec![
        MappingRule {
            name: "rule-a".into(),
            ..sample_rule()
        },
        MappingRule {
            name: "rule-b".into(),
            ..sample_rule()
        },
    ];
    let ruleset_guard = create_ruleset(&state, create).await?;

    let updated_ruleset = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &ruleset_guard.mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Delete {
                    rule_name: "rule-a".into(),
                }],
            },
        )
        .await?;

    assert_eq!(updated_ruleset.rules.len(), 1);
    assert_eq!(updated_ruleset.rules[0].name, "rule-b");

    Ok(())
}

#[tokio::test]
async fn test_mutate_rules_global() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    // Create a global ruleset (no domain) with two rules
    let mut create = sample_ruleset_create(None::<String>);
    create.rules = vec![
        MappingRule {
            name: "rule-a".into(),
            ..sample_rule()
        },
        MappingRule {
            name: "rule-b".into(),
            ..sample_rule()
        },
    ];
    let ruleset_guard = create_ruleset(&state, create).await?;

    // Insert rule X before B
    let rule_x = MappingRule {
        name: "rule-x".into(),
        ..sample_rule()
    };
    let updated_ruleset = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &ruleset_guard.mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Insert {
                    rule: rule_x,
                    position: Some(RulePosition::Before {
                        anchor: "rule-b".into(),
                    }),
                }],
            },
        )
        .await?;

    assert!(updated_ruleset.domain_id.is_none());
    assert_eq!(updated_ruleset.rules[0].name, "rule-a");
    assert_eq!(updated_ruleset.rules[1].name, "rule-x");
    assert_eq!(updated_ruleset.rules[2].name, "rule-b");

    Ok(())
}

#[tokio::test]
async fn test_mutate_rules_invalid_anchor() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let create = sample_ruleset_create(Some(domain.id.clone()));
    let ruleset_guard = create_ruleset(&state, create).await?;

    let rule_x = MappingRule {
        name: "rule-x".into(),
        ..sample_rule()
    };
    let result = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::internal(&state),
            &ruleset_guard.mapping_id,
            RuleMutations {
                mutations: vec![RuleMutation::Insert {
                    rule: rule_x,
                    position: Some(RulePosition::Before {
                        anchor: "nonexistent".into(),
                    }),
                }],
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MappingProviderError::Conflict(_)
    ));

    Ok(())
}
