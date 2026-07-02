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
//! Cross-provider integration test: the mapping engine's write-time guard
//! (ADR 0021 §6.C, Invariant 3 defense-in-depth) must reject any
//! `IdentitySource::ApiClient` ruleset that grants system scope, exercised
//! through the real (raft-backed) mapping provider rather than the
//! `crates/core` unit tests.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::error::MappingProviderError;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::*;

use crate::common::get_state;
use crate::create_domain;

fn api_client_rule(name: &str, is_system: bool, authorizations: Vec<Authorization>) -> MappingRule {
    MappingRule {
        name: name.into(),
        description: None,
        r#match: MatchCriteria::AllOf(vec![]),
        identity: IdentityBinding {
            identity_mode: None,
            user_name: "${claims.api_client.client_id}".into(),
            user_id: None,
            user_domain_id: None,
            is_system,
        },
        authorizations,
        groups: Vec::new(),
    }
}

#[traced_test]
#[tokio::test]
async fn test_api_client_ruleset_rejects_is_system() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::ApiClient {
            provider_id: "provider-1".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![api_client_rule("system-rule", true, Vec::new())],
    };

    let result = state
        .provider
        .get_mapping_provider()
        .create_ruleset(&ExecutionContext::internal(&state), ruleset)
        .await;

    assert!(matches!(
        result,
        Err(MappingProviderError::ApiClientSystemScopeForbidden(ref name)) if name == "system-rule"
    ));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_api_client_ruleset_rejects_system_authorization() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::ApiClient {
            provider_id: "provider-1".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![api_client_rule(
            "system-auth-rule",
            false,
            vec![Authorization::System {
                system_id: "all".into(),
                roles: Vec::new(),
            }],
        )],
    };

    let result = state
        .provider
        .get_mapping_provider()
        .create_ruleset(&ExecutionContext::internal(&state), ruleset)
        .await;

    assert!(matches!(
        result,
        Err(MappingProviderError::ApiClientSystemScopeForbidden(ref name)) if name == "system-auth-rule"
    ));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_api_client_ruleset_allows_non_system_scope() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::ApiClient {
            provider_id: "provider-1".into(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![api_client_rule(
            "project-rule",
            false,
            vec![Authorization::Project {
                project_id: "project-1".into(),
                project_domain_id: domain.id.clone(),
                roles: Vec::new(),
            }],
        )],
    };

    let res = state
        .provider
        .get_mapping_provider()
        .create_ruleset(&ExecutionContext::internal(&state), ruleset)
        .await?;

    assert_eq!(res.rules.len(), 1);

    Ok(())
}
