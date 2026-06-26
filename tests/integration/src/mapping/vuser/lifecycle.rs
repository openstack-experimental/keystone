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

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::AuthenticationContext;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::rule::{ClaimCondition, MatchCondition, MatchCriteria};
use openstack_keystone_core_types::mapping::*;

use crate::common::*;
use crate::create_domain;
use crate::mapping::ruleset::{create_ruleset, sample_ruleset_create};

#[tokio::test]
async fn test_virtual_user_lifecycle() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = sample_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "lifecycle-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "sub".into(),
            value: serde_json::Value::String("user-123".into()),
        })]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "vuser-123".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let _ruleset_guard = create_ruleset(&state, ruleset_create).await?;

    let mut claims = HashMap::new();
    claims.insert("sub".to_string(), vec!["user-123".to_string()]);

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Federation {
            idp_id: "test-idp".into(),
        },
        unique_workload_id: "user-123".to_string(),
        claims,
        rule_name: None,
    };

    let auth_result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&ExecutionContext::internal(&state), &request)
        .await?;

    let virtual_user_id = match auth_result.context {
        AuthenticationContext::Mapping(ctx) => ctx.virtual_user_id,
        _ => panic!("Expected Mapping context"),
    };

    let vu = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should exist");
    assert!(vu.enabled);

    let disabled_vu = state
        .provider
        .get_mapping_provider()
        .disable_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?;
    assert!(!disabled_vu.enabled);

    let vu_check = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should still exist");
    assert!(!vu_check.enabled);

    let enabled_vu = state
        .provider
        .get_mapping_provider()
        .enable_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?;
    assert!(enabled_vu.enabled);

    let vu_final = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should still exist");
    assert!(vu_final.enabled);

    Ok(())
}

#[tokio::test]
async fn test_virtual_user_lifecycle_global() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let mut ruleset_create = sample_ruleset_create(None::<String>);
    ruleset_create.rules = vec![MappingRule {
        name: "global-lifecycle-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "sub".into(),
            value: serde_json::Value::String("global-user-123".into()),
        })]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "global-vuser-123".into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations: Vec::new(),
        groups: Vec::new(),
    }];

    let _ruleset_guard = create_ruleset(&state, ruleset_create).await?;

    let mut claims = HashMap::new();
    claims.insert("sub".to_string(), vec!["global-user-123".to_string()]);

    let request = MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::Federation {
            idp_id: "test-idp".into(),
        },
        unique_workload_id: "global-user-123".to_string(),
        claims,
        rule_name: None,
    };

    let auth_result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&ExecutionContext::internal(&state), &request)
        .await?;

    let virtual_user_id = match auth_result.context {
        AuthenticationContext::Mapping(ctx) => ctx.virtual_user_id,
        _ => panic!("Expected Mapping context"),
    };

    let vu = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should exist");
    assert!(vu.enabled);
    assert!(vu.domain_id.is_none());

    let disabled_vu = state
        .provider
        .get_mapping_provider()
        .disable_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?;
    assert!(!disabled_vu.enabled);

    let vu_check = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should still exist");
    assert!(!vu_check.enabled);

    let enabled_vu = state
        .provider
        .get_mapping_provider()
        .enable_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?;
    assert!(enabled_vu.enabled);

    let vu_final = state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&ExecutionContext::internal(&state), &virtual_user_id)
        .await?
        .expect("virtual user should still exist");
    assert!(vu_final.enabled);

    Ok(())
}
