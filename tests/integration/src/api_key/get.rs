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
//! Test API Key retrieval by `client_id` and by `lookup_hash`.

use eyre::Result;
use tracing_test::traced_test;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_get_by_client_id() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_client_id(&state, &domain.id, &created.client_id)
        .await?;

    assert_eq!(
        fetched.map(|k| k.client_id),
        Some(created.client_id.clone())
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_by_client_id_missing() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_client_id(&state, &domain.id, "nonexistent-client-id")
        .await?;

    assert!(fetched.is_none());

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_by_lookup_hash() -> Result<()> {
    // The SCIM ingress hot path (ADR 0021 §3 Step 2) resolves solely by
    // lookup_hash, never by client_id.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?;

    assert_eq!(
        fetched.map(|k| k.client_id),
        Some(created.client_id.clone())
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_by_lookup_hash_missing() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, "nonexistent-lookup-hash")
        .await?;

    assert!(fetched.is_none());

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_is_domain_scoped() -> Result<()> {
    // A key created under domain A must not resolve when queried under
    // domain B, even with the correct lookup_hash — the primary storage
    // index partitions strictly by domain_id (ADR 0021 §2.A).
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain_a.id, "provider-1")).await?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain_b.id, &created.lookup_hash)
        .await?;

    assert!(fetched.is_none());

    Ok(())
}
