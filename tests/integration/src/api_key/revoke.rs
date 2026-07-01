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
//! Test the API Key emergency revocation path (ADR 0021 §5.C): tombstone,
//! not hard delete.

use eyre::Result;
use tracing_test::traced_test;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_revoke_disables_and_stamps_tombstone() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let revoked = state
        .provider
        .get_api_key_provider()
        .revoke(&state, &domain.id, &created.client_id, "operator-1")
        .await?;

    assert!(!revoked.enabled);
    assert_eq!(revoked.revoked_by, Some("operator-1".to_string()));
    assert!(revoked.revoked_at.is_some());

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_revoke_does_not_hard_delete() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    state
        .provider
        .get_api_key_provider()
        .revoke(&state, &domain.id, &created.client_id, "operator-1")
        .await?;

    // The lookup_hash → resource mapping must still resolve (audit trail /
    // incident response), just with enabled: false.
    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?;

    assert!(fetched.is_some());
    assert!(!fetched.unwrap().enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_revoke_missing_key_fails() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let result = state
        .provider
        .get_api_key_provider()
        .revoke(&state, &domain.id, "nonexistent-client-id", "operator-1")
        .await;

    assert!(result.is_err());

    Ok(())
}
