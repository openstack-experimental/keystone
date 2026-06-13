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

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::mapping::MappingApi;
use openstack_keystone_core_types::mapping::*;

mod create;
mod delete;
mod get;
mod list;
mod update;

use crate::common::*;

impl ResourceDeleter<MappingRuleSet> for Arc<Service> {
    fn delete(&self, resource: MappingRuleSet) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = self
                .provider
                .get_mapping_provider()
                .delete_ruleset(self, &resource.mapping_id)
                .await;
        })
    }
}

pub async fn create_ruleset(
    state: &ServiceState,
    data: MappingRuleSetCreate,
) -> Result<AsyncResourceGuard<MappingRuleSet, ServiceState>> {
    let res = state
        .provider
        .get_mapping_provider()
        .create_ruleset(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

/// Construct a sample mapping rule for testing.
pub fn sample_rule() -> MappingRule {
    MappingRule {
        name: "test-rule".into(),
        description: Some("A test rule".into()),
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "sub".into(),
            value: serde_json::Value::String("testuser".into()),
        })]),
        identity: IdentityBinding {
            user_name: "${name}".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }
}

/// Construct a sample ruleset creation payload.
pub fn sample_ruleset_create(domain_id: Option<String>) -> MappingRuleSetCreate {
    MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id,
        source: IdentitySource::Federation {
            idp_id: "test-idp".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![sample_rule()],
    }
}
