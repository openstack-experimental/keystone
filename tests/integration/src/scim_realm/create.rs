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
//! Test SCIM realm registration (ADR 0024 §2.A) against the real
//! `scim-driver-raft` backend.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimRealmProviderError;

use super::{create_realm, sample_realm_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_create_round_trips_through_real_backend() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let data = sample_realm_create(&domain.id, "provider-1");

    let realm = create_realm(&state, data.clone()).await?;

    assert_eq!(realm.domain_id, data.domain_id);
    assert_eq!(realm.provider_id, data.provider_id);
    assert_eq!(realm.idp_id, data.idp_id);
    assert_eq!(realm.display_name, data.display_name);
    assert!(realm.enabled, "a newly registered realm must start enabled");

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_rejects_duplicate_coordinate() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let data = sample_realm_create(&domain.id, "provider-1");

    create_realm(&state, data.clone()).await?;
    // Call the provider directly (not the `eyre`-wrapping `create_realm`
    // helper) so the typed `ScimRealmProviderError` survives for the
    // `matches!` check below.
    let err = state
        .provider
        .get_scim_realm_provider()
        .create_realm(&ExecutionContext::internal(&state), data)
        .await
        .expect_err("a second realm for the same (domain_id, provider_id) must be rejected");

    assert!(
        matches!(err, ScimRealmProviderError::Conflict(_)),
        "expected Conflict, got: {err:?}"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_allows_same_provider_id_in_different_domains() -> Result<()> {
    // The realm coordinate is (domain_id, provider_id), not provider_id
    // alone -- two domains may each register their own realm for the same
    // provider_id without colliding.
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;

    create_realm(&state, sample_realm_create(&domain_a.id, "shared-provider")).await?;
    let realm_b =
        create_realm(&state, sample_realm_create(&domain_b.id, "shared-provider")).await?;

    assert_eq!(realm_b.domain_id, domain_b.id);
    assert_eq!(realm_b.provider_id, "shared-provider");
    Ok(())
}
