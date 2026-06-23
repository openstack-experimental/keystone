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
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::rule::{ClaimCondition, MatchCondition, MatchCriteria};
use openstack_keystone_core_types::mapping::*;

use crate::common::*;
use crate::create_domain;
use crate::mapping::ruleset::{create_ruleset, sample_ruleset_create};

#[tokio::test]
async fn test_authenticate_happy_path() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain!(state)?;
    let domain_id = domain.id.clone();

    let mut ruleset_create = sample_ruleset_create(Some(domain_id.clone()));
    ruleset_create.rules = vec![MappingRule {
        name: "matching-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "sub".into(),
            value: serde_json::Value::String("workload-123".into()),
        })]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "mapped-user".into(),
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
    claims.insert("sub".to_string(), vec!["workload-123".to_string()]);

    let request = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Federation {
            idp_id: "test-idp".into(),
        },
        unique_workload_id: "workload-123".into(),
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
        assert_eq!(ctx.matched_rule_name, "matching-rule");
        assert!(!ctx.virtual_user_id.is_empty());

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.user_id, ctx.virtual_user_id);
        assert_eq!(vuser.mapping_id, mapping_id);
        assert_eq!(vuser.matched_rule_name, "matching-rule");
        assert!(vuser.enabled);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}

#[tokio::test]
async fn test_authenticate_global_ruleset() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let mut ruleset_create = sample_ruleset_create(None::<String>);
    ruleset_create.rules = vec![MappingRule {
        name: "global-matching-rule".into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
            claim: "sub".into(),
            value: serde_json::Value::String("global-workload".into()),
        })]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "global-mapped-user".into(),
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
    claims.insert("sub".to_string(), vec!["global-workload".to_string()]);

    let request = MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::Federation {
            idp_id: "test-idp".into(),
        },
        unique_workload_id: "global-workload".into(),
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
        assert_eq!(ctx.matched_rule_name, "global-matching-rule");
        assert!(!ctx.virtual_user_id.is_empty());

        let vuser = state
            .provider
            .get_mapping_provider()
            .get_virtual_user(&state, &ctx.virtual_user_id)
            .await?
            .expect("virtual user should exist");

        assert_eq!(vuser.user_id, ctx.virtual_user_id);
        assert_eq!(vuser.mapping_id, mapping_id);
        assert_eq!(vuser.matched_rule_name, "global-matching-rule");
        assert!(vuser.enabled);
    } else {
        panic!("Expected Mapping authentication context");
    }

    Ok(())
}
