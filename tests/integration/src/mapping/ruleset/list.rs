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
//! Test mapping ruleset listing.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::mapping::MappingRuleSetListParameters;

use super::create_ruleset;
use super::sample_ruleset_create;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let ruleset1 = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;
    let ruleset2 = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::internal(&state),
            &MappingRuleSetListParameters::default(),
        )
        .await?;

    assert!(res.contains(&ruleset1));
    assert!(res.contains(&ruleset2));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_domain() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain2 = create_domain!(state)?;

    let ruleset1 = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;
    let ruleset2 = create_ruleset(&state, sample_ruleset_create(Some(domain2.id.clone()))).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::internal(&state),
            &MappingRuleSetListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert!(res.contains(&ruleset1));
    assert!(!res.contains(&ruleset2));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_global() -> Result<()> {
    let (state, _) = get_state().await?;

    let ruleset1 = create_ruleset(&state, sample_ruleset_create(None::<String>)).await?;
    let ruleset2 = create_ruleset(&state, sample_ruleset_create(None::<String>)).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::internal(&state),
            &MappingRuleSetListParameters::default(),
        )
        .await?;

    assert!(res.contains(&ruleset1));
    assert!(res.contains(&ruleset2));

    // Filter by a non-empty domain_id should exclude global rulesets
    let domain = create_domain!(state)?;
    let res = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::internal(&state),
            &MappingRuleSetListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert!(!res.contains(&ruleset1));
    assert!(!res.contains(&ruleset2));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_enabled() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let ruleset1 = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;

    let mut disabled_sot = sample_ruleset_create(Some(domain.id.clone()));
    disabled_sot.enabled = false;
    let ruleset2 = create_ruleset(&state, disabled_sot).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::internal(&state),
            &MappingRuleSetListParameters {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await?;

    assert!(res.contains(&ruleset1));
    assert!(!res.contains(&ruleset2));

    Ok(())
}
