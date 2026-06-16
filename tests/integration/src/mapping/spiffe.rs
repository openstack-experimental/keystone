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

use std::collections::HashMap;

use eyre::Result;

use openstack_keystone_core::mapping::MappingApi;
use openstack_keystone_core_types::auth::AuthenticationContext;
use openstack_keystone_core_types::mapping::error::MappingProviderError;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::rule::{ClaimCondition, MatchCondition, MatchCriteria};
use openstack_keystone_core_types::mapping::*;

use crate::common::*;
use crate::create_domain;
use crate::mapping::ruleset::create_ruleset;

/// Construct a SPIFFE ruleset creation payload.
fn spiffe_ruleset_create(domain_id: Option<String>) -> MappingRuleSetCreate {
    MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id,
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: Vec::new(),
    }
}

#[tokio::test]
async fn test_spiffe_happy_path() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = spiffe_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "spiffe.id".into(),
            value: serde_json::Value::String("spiffe://example.org/workload".into()),
        })]),
        identity: IdentityBinding {
            user_name: "spiffe-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/workload".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/workload".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "spiffe-rule");
        assert!(!ctx.virtual_user_id.is_empty());

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.user_id, ctx.virtual_user_id);
        assert_eq!(vuser.mapping_id, mapping_id);
        assert_eq!(vuser.matched_rule_name, "spiffe-rule");
        assert!(vuser.enabled);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_spiffe_no_fallback_when_no_matching_rule() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    // No ruleset is created; authentication MUST fail without fallback to
    // SpiffeBinding
    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/workload".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/workload".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MappingProviderError::NoMatchingRule
    ));

    Ok(())
}

#[tokio::test]
async fn test_spiffe_system_ruleset() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let mut ruleset_create = spiffe_ruleset_create(None::<String>);
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-system-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "spiffe.id".into(),
            value: serde_json::Value::String("spiffe://example.org/system".into()),
        })]),
        identity: IdentityBinding {
            user_name: "spiffe-system-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: true,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/system".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/system".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "spiffe-system-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.user_id, ctx.virtual_user_id);
        assert!(vuser.is_system);
        assert_eq!(vuser.matched_rule_name, "spiffe-system-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_spiffe_claim_condition_any_of() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = spiffe_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-anyof-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::AnyOf {
            claim: "spiffe.id".into(),
            values: vec![
                serde_json::Value::String("spiffe://example.org/workload-a".into()),
                serde_json::Value::String("spiffe://example.org/workload-b".into()),
            ],
        })]),
        identity: IdentityBinding {
            user_name: "spiffe-anyof-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/workload-b".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/workload-b".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "spiffe-anyof-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "spiffe-anyof-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_spiffe_any_of_no_match() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut ruleset_create = spiffe_ruleset_create(Some(domain.id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-anyof-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::AnyOf {
            claim: "spiffe.id".into(),
            values: vec![
                serde_json::Value::String("spiffe://example.org/workload-x".into()),
                serde_json::Value::String("spiffe://example.org/workload-y".into()),
            ],
        })]),
        identity: IdentityBinding {
            user_name: "spiffe-anyof-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let _ruleset_guard = create_ruleset(&state, ruleset_create).await?;

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/workload-z".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/workload-z".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MappingProviderError::NoMatchingRule
    ));

    Ok(())
}

#[tokio::test]
async fn test_spiffe_matches_regex() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = spiffe_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-regex-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
            ClaimCondition::MatchesRegex {
                claim: "spiffe.trust_domain".into(),
                regex: "^example\\.".to_string(),
            },
        )]),
        identity: IdentityBinding {
            user_name: "spiffe-regex-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/workload".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/workload".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "spiffe-regex-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "spiffe-regex-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_spiffe_all_of_strict_with_auth() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = spiffe_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "spiffe-strict-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOfStrict {
            conditions: vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "spiffe.id".into(),
                    value: serde_json::Value::String("spiffe://example.org/strict-workload".into()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "spiffe.trust_domain".into(),
                    value: serde_json::Value::String("example.org".into()),
                }),
            ],
            require_all_keys: true,
        },
        identity: IdentityBinding {
            user_name: "spiffe-strict-user".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: vec![
            openstack_keystone_core_types::mapping::authorization::Authorization::Domain {
                domain_id: domain_id.clone(),
                roles: vec![openstack_keystone_core_types::role::RoleRef {
                    id: "reader-role".into(),
                    name: Some("reader".into()),
                    domain_id: None,
                }],
            },
        ],
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "spiffe.id".to_string(),
        vec!["spiffe://example.org/strict-workload".to_string()],
    );
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec!["example.org".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::Spiffe {
            trust_domain: "example.org".into(),
        },
        unique_workload_id: "spiffe://example.org/strict-workload".into(),
        claims,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "spiffe-strict-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "spiffe-strict-rule");
        assert_eq!(vuser.authorizations.len(), 1);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}
