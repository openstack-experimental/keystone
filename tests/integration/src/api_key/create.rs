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
//! Test API Key creation.

use eyre::Result;
use tracing_test::traced_test;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let sot = sample_api_key_create(&domain.id, "provider-1");

    let res = create_api_key(&state, sot.clone()).await?;

    assert_eq!(sot.domain_id, res.domain_id);
    assert_eq!(sot.provider_id, res.provider_id);
    assert_eq!(sot.client_id, res.client_id);
    assert_eq!(sot.lookup_hash, res.lookup_hash);
    assert_eq!(sot.secret_hash, res.secret_hash);
    assert_eq!(sot.allowed_ips, res.allowed_ips);
    assert_eq!(sot.description, res.description);
    assert_eq!(sot.expires_at, res.expires_at);

    // Server-managed fields.
    assert!(res.enabled);
    assert!(res.last_used_at.is_none());
    assert!(res.revoked_at.is_none());
    assert!(res.revoked_by.is_none());
    assert!(res.created_at > 0);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_with_allowed_ips() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let mut sot = sample_api_key_create(&domain.id, "provider-1");
    sot.allowed_ips = Some(vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]);

    let res = create_api_key(&state, sot.clone()).await?;

    assert_eq!(sot.allowed_ips, res.allowed_ips);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_two_keys_same_provider_rotation() -> Result<()> {
    // Zero-downtime rotation (ADR 0021 §5.D): N:1 keys-to-provider mapping
    // must not collide, since the primary index is keyed by lookup_hash, not
    // provider_id.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let key_a =
        create_api_key(&state, sample_api_key_create(&domain.id, "shared-provider")).await?;
    let key_b =
        create_api_key(&state, sample_api_key_create(&domain.id, "shared-provider")).await?;

    assert_ne!(key_a.client_id, key_b.client_id);
    assert_ne!(key_a.lookup_hash, key_b.lookup_hash);
    assert_eq!(key_a.provider_id, key_b.provider_id);

    Ok(())
}
