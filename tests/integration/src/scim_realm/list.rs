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
//! Test SCIM realm listing (ADR 0024 §2.A) against the real
//! `scim-driver-raft` backend.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimRealmResourceListParametersBuilder;

use super::{create_realm, sample_realm_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_list_scopes_to_domain() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;

    create_realm(&state, sample_realm_create(&domain_a.id, "provider-1")).await?;
    create_realm(&state, sample_realm_create(&domain_a.id, "provider-2")).await?;
    create_realm(&state, sample_realm_create(&domain_b.id, "provider-1")).await?;

    let params = ScimRealmResourceListParametersBuilder::default()
        .domain_id(domain_a.id.clone())
        .build()?;
    let realms = state
        .provider
        .get_scim_realm_provider()
        .list_realms(&ExecutionContext::internal(&state), &params)
        .await?;

    assert_eq!(realms.len(), 2);
    assert!(realms.iter().all(|r| r.domain_id == domain_a.id));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filters_by_enabled() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    create_realm(&state, sample_realm_create(&domain.id, "provider-enabled")).await?;
    let disabled =
        create_realm(&state, sample_realm_create(&domain.id, "provider-disabled")).await?;
    state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &disabled.domain_id,
            &disabled.provider_id,
            openstack_keystone_core_types::scim::ScimRealmResourceUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    let params = ScimRealmResourceListParametersBuilder::default()
        .domain_id(domain.id.clone())
        .enabled(true)
        .build()?;
    let realms = state
        .provider
        .get_scim_realm_provider()
        .list_realms(&ExecutionContext::internal(&state), &params)
        .await?;

    assert_eq!(realms.len(), 1);
    assert_eq!(realms[0].provider_id, "provider-enabled");
    Ok(())
}
