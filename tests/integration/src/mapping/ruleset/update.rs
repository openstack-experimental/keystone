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
//! Test mapping ruleset update.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::mapping::rule::MappingRule;
use openstack_keystone_core_types::mapping::*;

use super::create_ruleset;
use super::sample_ruleset_create;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let ruleset = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;

    let new_rule = MappingRule {
        name: "updated-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "${username}".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    };

    let req = MappingRuleSetUpdate {
        enabled: Some(false),
        allowed_domains: None,
        rules: Some(vec![new_rule.clone()]),
    };

    let res = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &ruleset.mapping_id,
            req,
        )
        .await?;

    assert_eq!(ruleset.mapping_id, res.mapping_id);
    assert!(!res.enabled);
    assert_eq!(res.rules.len(), 1);
    assert_eq!(res.rules[0].name, new_rule.name);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_allowed_domains() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut sot = sample_ruleset_create(Some(domain.id.clone()));
    sot.domain_resolution_mode = DomainResolutionMode::ClaimsOrMapping {
        allowed_domains: vec!["domain-a".into()],
    };
    let ruleset = create_ruleset(&state, sot).await?;

    let req = MappingRuleSetUpdate {
        enabled: None,
        allowed_domains: Some(vec!["domain-b".into(), "domain-c".into()]),
        rules: None,
    };

    let res = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &ruleset.mapping_id,
            req,
        )
        .await?;

    assert_eq!(ruleset.mapping_id, res.mapping_id);
    assert!(matches!(
        res.domain_resolution_mode,
        DomainResolutionMode::ClaimsOrMapping { .. }
    ));
    assert_eq!(
        res.domain_resolution_mode,
        DomainResolutionMode::ClaimsOrMapping {
            allowed_domains: vec!["domain-b".into(), "domain-c".into()]
        }
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_global() -> Result<()> {
    let (state, _) = get_state().await?;
    let ruleset = create_ruleset(&state, sample_ruleset_create(None::<String>)).await?;

    let new_rule = MappingRule {
        name: "updated-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "${username}".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    };

    let req = MappingRuleSetUpdate {
        enabled: Some(false),
        allowed_domains: None,
        rules: Some(vec![new_rule.clone()]),
    };

    let res = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &ruleset.mapping_id,
            req,
        )
        .await?;

    assert_eq!(ruleset.mapping_id, res.mapping_id);
    assert!(res.domain_id.is_none());
    assert!(!res.enabled);
    assert_eq!(res.rules.len(), 1);
    assert_eq!(res.rules[0].name, new_rule.name);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_missing() -> Result<()> {
    let (state, _) = get_state().await?;
    let result = state
        .provider
        .get_mapping_provider()
        .update_ruleset(
            &ExecutionContext::internal(&state),
            &uuid::Uuid::new_v4().simple().to_string(),
            MappingRuleSetUpdate::default(),
        )
        .await;

    assert!(result.is_err());

    Ok(())
}
