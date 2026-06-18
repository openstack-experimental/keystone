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

/// Construct a K8s ruleset creation payload.
fn k8s_ruleset_create(domain_id: Option<String>) -> MappingRuleSetCreate {
    MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id,
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: Vec::new(),
    }
}

#[tokio::test]
async fn test_k8s_happy_path() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-ci-pipeline".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.namespace".into(),
                value: serde_json::Value::String("ci-pipeline".into()),
            }),
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.name".into(),
                value: serde_json::Value::String("build-runner".into()),
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-${claims.k8s.serviceaccount.name}".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );
    claims.insert(
        "k8s.aud".to_string(),
        vec!["https://kubernetes.default.svc".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-ci-pipeline");
        assert!(!ctx.virtual_user_id.is_empty());

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.user_id, ctx.virtual_user_id);
        assert_eq!(vuser.mapping_id, mapping_id);
        assert_eq!(vuser.matched_rule_name, "k8s-ci-pipeline");
        assert!(vuser.enabled);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_no_matching_rule() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut ruleset_create = k8s_ruleset_create(Some(domain.id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-specific".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.namespace".into(),
                value: serde_json::Value::String("other-ns".into()),
            }),
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.name".into(),
                value: serde_json::Value::String("other-sa".into()),
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-other".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims,
        rule_name: None,
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
async fn test_k8s_any_of_match() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-ci-anyof".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.namespace".into(),
                value: serde_json::Value::String("ci-pipeline".into()),
            }),
            MatchCondition::Condition(ClaimCondition::AnyOf {
                claim: "k8s.serviceaccount.name".into(),
                values: vec![
                    serde_json::Value::String("build-runner".into()),
                    serde_json::Value::String("deploy-agent".into()),
                ],
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-ci".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["deploy-agent".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "deploy-agent:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-ci-anyof");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "k8s-ci-anyof");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_matches_regex() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-monitoring".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.namespace".into(),
                value: serde_json::Value::String("monitoring".into()),
            }),
            MatchCondition::Condition(ClaimCondition::MatchesRegex {
                claim: "k8s.serviceaccount.name".into(),
                regex: "^prometheus-.*$".to_string(),
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-${claims.k8s.serviceaccount.name}".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["prometheus-node-exporter".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["monitoring".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "prometheus-node-exporter:monitoring".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-monitoring");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "k8s-monitoring");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_all_of_strict() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-strict-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOfStrict {
            conditions: vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.name".into(),
                    value: serde_json::Value::String("build-runner".into()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.namespace".into(),
                    value: serde_json::Value::String("ci-pipeline".into()),
                }),
            ],
            require_all_keys: true,
        },
        identity: IdentityBinding {
            user_name: "svc-k8s-strict".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    // Both keys present — should match
    let mut claims = HashMap::new();
    claims.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-strict-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    // Missing namespace key — should fail due to require_all_keys
    let mut claims_missing = HashMap::new();
    claims_missing.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );

    let request_missing = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims: claims_missing,
        rule_name: None,
    };

    let result_missing = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request_missing)
        .await;

    assert!(result_missing.is_err());
    assert!(matches!(
        result_missing.unwrap_err(),
        MappingProviderError::NoMatchingRule
    ));

    Ok(())
}

#[tokio::test]
async fn test_k8s_with_authorizations() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-auth-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "k8s.serviceaccount.name".into(),
            value: serde_json::Value::String("admin-sa".into()),
        })]),
        identity: IdentityBinding {
            user_name: "svc-k8s-admin".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["admin-sa".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["default".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "admin-sa:default".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-auth-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "k8s-auth-rule");
        // Verify authorizations were snapshotted in the virtual user record
        assert_eq!(vuser.authorizations.len(), 1);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_template_interpolation() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-template-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.namespace".into(),
                value: serde_json::Value::String("ci-pipeline".into()),
            }),
            MatchCondition::Condition(ClaimCondition::AnyOf {
                claim: "k8s.serviceaccount.name".into(),
                values: vec![
                    serde_json::Value::String("build-runner".into()),
                    serde_json::Value::String("deploy-agent".into()),
                ],
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-${claims.k8s.serviceaccount.name}".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["deploy-agent".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "deploy-agent:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-template-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        // Verify the user_name template was interpolated correctly
        assert_eq!(vuser.resolved_user_name, "svc-k8s-deploy-agent");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_disabled_ruleset() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let mut ruleset_create = k8s_ruleset_create(Some(domain.id.clone()));
    ruleset_create.enabled = false;
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-disabled-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "k8s.serviceaccount.name".into(),
            value: serde_json::Value::String("any-sa".into()),
        })]),
        identity: IdentityBinding {
            user_name: "svc-k8s-disabled".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["any-sa".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["default".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "any-sa:default".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MappingProviderError::DisabledRuleset
    ));

    Ok(())
}

#[tokio::test]
async fn test_k8s_unique_workload_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-workload-id-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "k8s.serviceaccount.name".into(),
            value: serde_json::Value::String("unique-sa".into()),
        })]),
        identity: IdentityBinding {
            user_name: "svc-k8s-unique".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;

    let mut claims = HashMap::new();
    claims.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["unique-sa".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["testing".to_string()],
    );

    // Authenticate once
    let request = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "unique-sa:testing".into(),
        claims: claims.clone(),
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    let first_vuser_id = match result.context {
        AuthenticationContext::Mapping(ctx) => ctx.virtual_user_id,
        _ => panic!("Expected Mapping authentication context"),
    };

    // Authenticate again with the same workload_id — should resolve to the same
    // virtual user (deterministic)
    let request2 = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "unique-sa:testing".into(),
        claims,
        rule_name: None,
    };

    let result2 = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request2)
        .await?;

    let second_vuser_id = match result2.context {
        AuthenticationContext::Mapping(ctx) => ctx.virtual_user_id,
        _ => panic!("Expected Mapping authentication context"),
    };

    // Both authentications should resolve to the same virtual user
    assert_eq!(first_vuser_id, second_vuser_id);

    // Verify the virtual user metadata
    let vuser = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&state, &first_vuser_id)
        .await?
        .expect("virtual user should exist");

    assert_eq!(vuser.unique_workload_id, "unique-sa:testing");
    assert_eq!(vuser.mapping_id, ruleset_guard.mapping_id);

    Ok(())
}

#[tokio::test]
async fn test_k8s_aud_claim_passthrough() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-aud-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![
            MatchCondition::Condition(ClaimCondition::Equals {
                claim: "k8s.serviceaccount.name".into(),
                value: serde_json::Value::String("aud-sa".into()),
            }),
            MatchCondition::Condition(ClaimCondition::AnyOf {
                claim: "k8s.aud".into(),
                values: vec![
                    serde_json::Value::String("https://kubernetes.default.svc".into()),
                    serde_json::Value::String("kubernetes".into()),
                ],
            }),
        ]),
        identity: IdentityBinding {
            user_name: "svc-k8s-aud".into(),
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
        "k8s.serviceaccount.name".to_string(),
        vec!["aud-sa".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["default".to_string()],
    );
    claims.insert(
        "k8s.aud".to_string(),
        vec!["https://kubernetes.default.svc".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "aud-sa:default".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-aud-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_rule_priority() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![
        MappingRule {
            name: "k8s-specific-rule".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.name".into(),
                    value: serde_json::Value::String("build-runner".into()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.namespace".into(),
                    value: serde_json::Value::String("ci-pipeline".into()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "svc-k8s-specific".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        },
        MappingRule {
            name: "k8s-catch-all-rule".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "k8s.serviceaccount.name".into(),
                    regex: ".*".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "svc-k8s-catchall".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        },
    ];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    // Claims that match both rules — first rule should win
    let mut claims = HashMap::new();
    claims.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        // First-match-wins: specific rule should be selected, not catch-all
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-specific-rule");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_project_authorization() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "k8s-project-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "k8s.serviceaccount.name".into(),
            value: serde_json::Value::String("pipeline-sa".into()),
        })]),
        identity: IdentityBinding {
            user_name: "svc-k8s-pipeline".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: vec![
            openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                project_id: "test-project-id".into(),
                project_domain_id: domain_id.clone(),
                roles: vec![
                    openstack_keystone_core_types::role::RoleRef {
                        id: "member-role".into(),
                        name: Some("member".into()),
                        domain_id: None,
                    },
                    openstack_keystone_core_types::role::RoleRef {
                        id: "admin-role".into(),
                        name: Some("admin".into()),
                        domain_id: None,
                    },
                ],
            },
        ],
        groups: Vec::new(),
    }];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    let mut claims = HashMap::new();
    claims.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["pipeline-sa".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "pipeline-sa:ci-pipeline".into(),
        claims,
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        assert_eq!(ctx.matched_rule_name, "k8s-project-rule");

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.matched_rule_name, "k8s-project-rule");
        // Verify project authorization was snapshotted with both roles
        assert_eq!(vuser.authorizations.len(), 1);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_k8s_rule_name_hint() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    // Three rules: specific rules first, catch-all last.
    let mut ruleset_create = k8s_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![
        MappingRule {
            name: "k8s-specific-ci".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.namespace".into(),
                    value: serde_json::Value::String("ci-pipeline".into()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.name".into(),
                    value: serde_json::Value::String("build-runner".into()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "svc-k8s-specific-ci".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        },
        MappingRule {
            name: "k8s-specific-monitoring".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.namespace".into(),
                    value: serde_json::Value::String("monitoring".into()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "k8s.serviceaccount.name".into(),
                    value: serde_json::Value::String("grafana".into()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "svc-k8s-specific-monitoring".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        },
        MappingRule {
            name: "k8s-catch-all".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "k8s.serviceaccount.name".into(),
                    regex: ".*".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "svc-k8s-catchall".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        },
    ];

    let ruleset_guard = create_ruleset(&state, ruleset_create).await?;
    let mapping_id = ruleset_guard.mapping_id.clone();

    // --- Case 1: rule_name points to the specific rule that matches. ---
    let mut claims = HashMap::new();
    claims.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["grafana".to_string()],
    );
    claims.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["monitoring".to_string()],
    );

    let request = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "grafana:monitoring".into(),
        claims,
        rule_name: Some("k8s-specific-monitoring".to_string()),
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        // The named rule matches, so it is returned immediately.
        assert_eq!(ctx.matched_rule_name, "k8s-specific-monitoring");
    } else {
        panic!("Expected Mapping authentication context");
    }

    // --- Case 2: rule_name points to a non-matching rule; falls back to
    //   standard iteration which hits the catch-all. ---
    let mut claims_fallback = HashMap::new();
    claims_fallback.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["random-sa".to_string()],
    );
    claims_fallback.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["default".to_string()],
    );

    let request_fallback = MappingAuthRequest {
        domain_id: Some(domain_id.clone()),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "random-sa:default".into(),
        claims: claims_fallback,
        rule_name: Some("k8s-specific-ci".to_string()),
    };

    let result_fallback = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request_fallback)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result_fallback.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        // The named specific-ci rule does NOT match; iteration falls back and
        // catch-all wins.
        assert_eq!(ctx.matched_rule_name, "k8s-catch-all");
    } else {
        panic!("Expected Mapping authentication context");
    }

    // --- Case 3: no rule_name — standard first-match-wins applies. ---
    let mut claims_standard = HashMap::new();
    claims_standard.insert(
        "k8s.serviceaccount.name".to_string(),
        vec!["build-runner".to_string()],
    );
    claims_standard.insert(
        "k8s.serviceaccount.namespace".to_string(),
        vec!["ci-pipeline".to_string()],
    );

    let request_standard = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "build-runner:ci-pipeline".into(),
        claims: claims_standard,
        rule_name: None,
    };

    let result_standard = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request_standard)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result_standard.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        // First rule specific-ci matches, so it wins before catch-all.
        assert_eq!(ctx.matched_rule_name, "k8s-specific-ci");
    } else {
        panic!("Expected Mapping authentication context");
    }

    // --- Case 4: rule_name points to a nonexistent rule → falls back. ---
    let request_missing_hint = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::K8s {
            cluster_id: "eks-prod-cluster-01".into(),
        },
        unique_workload_id: "grafana:monitoring".into(),
        claims: HashMap::from_iter([
            (
                "k8s.serviceaccount.name".to_string(),
                vec!["grafana".to_string()],
            ),
            (
                "k8s.serviceaccount.namespace".to_string(),
                vec!["monitoring".to_string()],
            ),
        ]),
        rule_name: Some("does-not-exist".into()),
    };

    let result_missing_hint = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &request_missing_hint)
        .await?;

    if let AuthenticationContext::Mapping(ctx) = result_missing_hint.context {
        assert_eq!(ctx.mapping_id, mapping_id);
        // Hinted rule not found → falls back to first-match-wins.
        assert_eq!(ctx.matched_rule_name, "k8s-specific-monitoring");
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}
