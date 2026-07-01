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
//! Test `update_last_used` (ADR 0021 §3 Step 3) and `update_secret_hash`
//! (lazy re-hash, ADR 0021 Invariant 8) maintenance operations.

use eyre::Result;
use tracing_test::traced_test;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_update_last_used() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    assert!(created.last_used_at.is_none());

    let now = chrono::Utc::now().timestamp();
    state
        .provider
        .get_api_key_provider()
        .update_last_used(&state, &domain.id, &created.lookup_hash, now)
        .await?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?
        .expect("key must still exist");

    assert_eq!(fetched.last_used_at, Some(now));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_last_used_on_missing_key_is_a_no_op() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    // No key exists for this lookup_hash; must not error (mirrors the
    // dummy-hash timing-parity path, which always runs regardless of
    // whether the key exists).
    let result = state
        .provider
        .get_api_key_provider()
        .update_last_used(&state, &domain.id, "nonexistent-lookup-hash", 12345)
        .await;

    assert!(result.is_ok());

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_secret_hash() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let new_hash = "$argon2id$v=19$m=131072,t=4,p=4$bmV3c2FsdA$bmV3aGFzaA".to_string();
    state
        .provider
        .get_api_key_provider()
        .update_secret_hash(&state, &domain.id, &created.lookup_hash, new_hash.clone())
        .await?;

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?
        .expect("key must still exist");

    assert_eq!(fetched.secret_hash, new_hash);
    // Re-hashing must not disturb unrelated fields.
    assert_eq!(fetched.client_id, created.client_id);
    assert!(fetched.enabled);

    Ok(())
}
