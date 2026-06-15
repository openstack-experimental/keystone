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
    IdentityBinding, MappingRuleSetCreate, MappingRuleSetUpdate, MatchCriteria, RuleMutation,
    RuleMutationsRequest,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::*;

#[tokio::test]
#[traced_test]
async fn test_system_ruleset_immutable() -> Result<()> {
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
                    name: "system-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "systemuser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: true,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let mapping_id = &ruleset.mapping_id;

    // 1. Test update rejection
    let update_result = update_ruleset(
        &test_client,
        mapping_id,
        MappingRuleSetUpdate {
            enabled: Some(false),
            allowed_domains: None,
            rules: None,
        },
    )
    .await;
    assert!(
        update_result.is_err(),
        "Expected update to fail for system ruleset"
    );

    // 2. Test mutate rejection
    let mutate_result = mutate_ruleset(
        &test_client,
        mapping_id,
        RuleMutationsRequest {
            mutations: vec![RuleMutation::Delete {
                rule_name: "system-rule".to_string(),
            }],
        },
    )
    .await;
    assert!(
        mutate_result.is_err(),
        "Expected mutate to fail for system ruleset"
    );

    // 3. Test delete rejection
    let delete_result = ruleset.delete().await;
    assert!(
        delete_result.is_err(),
        "Expected delete to fail for system ruleset"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_system_global_ruleset_immutable() -> Result<()> {
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
                    name: "global-system-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        user_name: "global-systemuser".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: true,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let mapping_id = &ruleset.mapping_id;

    // 1. Test update rejection
    let update_result = update_ruleset(
        &test_client,
        mapping_id,
        MappingRuleSetUpdate {
            enabled: Some(false),
            allowed_domains: None,
            rules: None,
        },
    )
    .await;
    assert!(
        update_result.is_err(),
        "Expected update to fail for global system ruleset"
    );

    // 2. Test mutate rejection
    let mutate_result = mutate_ruleset(
        &test_client,
        mapping_id,
        RuleMutationsRequest {
            mutations: vec![RuleMutation::Delete {
                rule_name: "global-system-rule".to_string(),
            }],
        },
    )
    .await;
    assert!(
        mutate_result.is_err(),
        "Expected mutate to fail for global system ruleset"
    );

    // 3. Test delete rejection
    let delete_result = ruleset.delete().await;
    assert!(
        delete_result.is_err(),
        "Expected delete to fail for global system ruleset"
    );

    Ok(())
}
