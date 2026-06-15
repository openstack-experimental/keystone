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
use std::sync::Arc;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::mapping::ruleset::{
    IdentityBinding, MappingRuleSetCreate, MatchCriteria, RuleMutation, RuleMutationsRequest,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::*;

#[tokio::test]
#[traced_test]
async fn test_mutate_mapping_ruleset() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let ruleset = create_ruleset(
        &test_client,
        MappingRuleSetCreate {
            mapping_id: Some(format!("api-test-{}", Uuid::new_v4().simple())),
            domain_id: Some("default".to_string()),
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::Spiffe {
                trust_domain: "example.org".to_string(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "initial-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "initialuser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let mapping_id = &ruleset.mapping_id;

    let mutated = mutate_ruleset(
        &test_client,
        mapping_id,
        RuleMutationsRequest {
            mutations: vec![RuleMutation::Insert {
                rule: openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "second-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "seconduser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
                position: None,
            }],
        },
    )
    .await?;

    assert_eq!(mutated.mapping_id, *mapping_id);
    assert_eq!(mutated.rules.len(), 2);
    assert!(mutated.rules.iter().any(|r| r.name == "initial-rule"));
    assert!(mutated.rules.iter().any(|r| r.name == "second-rule"));

    ruleset.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_mutate_global_mapping_ruleset() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let ruleset = create_ruleset(
        &test_client,
        MappingRuleSetCreate {
            mapping_id: Some(format!("api-test-{}", Uuid::new_v4().simple())),
            domain_id: None,
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::Spiffe {
                trust_domain: "example.org".to_string(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "initial-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "initialuser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let mapping_id = &ruleset.mapping_id;

    let mutated = mutate_ruleset(
        &test_client,
        mapping_id,
        RuleMutationsRequest {
            mutations: vec![RuleMutation::Insert {
                rule: openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "second-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "seconduser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
                position: None,
            }],
        },
    )
    .await?;

    assert_eq!(mutated.mapping_id, *mapping_id);
    assert!(mutated.domain_id.is_none());
    assert_eq!(mutated.rules.len(), 2);
    assert!(mutated.rules.iter().any(|r| r.name == "initial-rule"));
    assert!(mutated.rules.iter().any(|r| r.name == "second-rule"));

    ruleset.delete().await?;
    Ok(())
}
