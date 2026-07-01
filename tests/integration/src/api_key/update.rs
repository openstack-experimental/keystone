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
//! Test API Key update, including the double-`Option` `allowed_ips` and
//! `description` semantics (ADR 0021 Invariant 5).

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core_types::api_key::ApiClientResourceUpdate;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_update_sets_allowed_ips() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    assert!(created.allowed_ips.is_none());

    let updated = state
        .provider
        .get_api_key_provider()
        .update(
            &state,
            &domain.id,
            &created.client_id,
            ApiClientResourceUpdate {
                allowed_ips: Some(Some(vec!["10.0.0.0/8".to_string()])),
                description: None,
                enabled: None,
            },
        )
        .await?;

    assert_eq!(updated.allowed_ips, Some(vec!["10.0.0.0/8".to_string()]));
    // `None` in the request means "unchanged".
    assert_eq!(updated.description, created.description);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_clears_allowed_ips_to_unrestricted() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let mut sot = sample_api_key_create(&domain.id, "provider-1");
    sot.allowed_ips = Some(vec!["10.0.0.0/8".to_string()]);
    let created = create_api_key(&state, sot).await?;

    let updated = state
        .provider
        .get_api_key_provider()
        .update(
            &state,
            &domain.id,
            &created.client_id,
            ApiClientResourceUpdate {
                // `Some(None)` explicitly clears the restriction.
                allowed_ips: Some(None),
                description: None,
                enabled: None,
            },
        )
        .await?;

    assert_eq!(updated.allowed_ips, None);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_description() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let updated = state
        .provider
        .get_api_key_provider()
        .update(
            &state,
            &domain.id,
            &created.client_id,
            ApiClientResourceUpdate {
                allowed_ips: None,
                description: Some(Some("updated description".to_string())),
                enabled: None,
            },
        )
        .await?;

    assert_eq!(updated.description, Some("updated description".to_string()));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_disable_key() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;

    let updated = state
        .provider
        .get_api_key_provider()
        .update(
            &state,
            &domain.id,
            &created.client_id,
            ApiClientResourceUpdate {
                allowed_ips: None,
                description: None,
                enabled: Some(false),
            },
        )
        .await?;

    assert!(!updated.enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_missing_key_fails() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let result = state
        .provider
        .get_api_key_provider()
        .update(
            &state,
            &domain.id,
            "nonexistent-client-id",
            ApiClientResourceUpdate::default(),
        )
        .await;

    assert!(result.is_err());

    Ok(())
}
