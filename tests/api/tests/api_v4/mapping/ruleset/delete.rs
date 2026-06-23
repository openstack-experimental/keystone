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
    IdentityBinding, MappingRuleSetCreate, MatchCriteria,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::*;
use test_api::mapping::ruleset::*;

#[tokio::test]
#[traced_test]
async fn test_delete_mapping_ruleset() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let mapping_id = format!("api-test-{}", Uuid::new_v4().simple());
    let ruleset = create_ruleset(
        &test_client,
        MappingRuleSetCreate {
            mapping_id: Some(mapping_id.clone()),
            domain_id: Some("default".to_string()),
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::Spiffe {
                trust_domain: "example.org".to_string(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "test-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        identity_mode: None,
                        user_name: "testuser".to_string(),
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

    ruleset.delete().await?;

    let res = show_ruleset(&test_client, &mapping_id).await;
    assert!(res.is_err(), "Expected show to fail after delete");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_global_mapping_ruleset() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let mapping_id = format!("api-test-{}", Uuid::new_v4().simple());
    let ruleset = create_ruleset(
        &test_client,
        MappingRuleSetCreate {
            mapping_id: Some(mapping_id.clone()),
            domain_id: None,
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::Spiffe {
                trust_domain: "example.org".to_string(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "test-rule".to_string(),
                    description: None,
                    r#match: MatchCriteria::default(),
                    identity: IdentityBinding {
                        identity_mode: None,
                        user_name: "testuser".to_string(),
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

    ruleset.delete().await?;

    let res = show_ruleset(&test_client, &mapping_id).await;
    assert!(
        res.is_err(),
        "Expected show to fail after delete for global ruleset"
    );

    Ok(())
}
