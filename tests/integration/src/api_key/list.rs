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
//! Test API Key listing (domain scoping, provider_id and enabled filters).

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core_types::api_key::ApiClientResourceListParameters;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_list_scoped_to_domain() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;

    let key_a1 = create_api_key(&state, sample_api_key_create(&domain_a.id, "provider-1")).await?;
    let key_a2 = create_api_key(&state, sample_api_key_create(&domain_a.id, "provider-2")).await?;
    let _key_b = create_api_key(&state, sample_api_key_create(&domain_b.id, "provider-1")).await?;

    let listed = state
        .provider
        .get_api_key_provider()
        .list(
            &state,
            &ApiClientResourceListParameters {
                domain_id: domain_a.id.clone(),
                provider_id: None,
                enabled: None,
            },
        )
        .await?;

    let listed_client_ids: Vec<String> = listed.into_iter().map(|k| k.client_id).collect();
    assert!(listed_client_ids.contains(&key_a1.client_id));
    assert!(listed_client_ids.contains(&key_a2.client_id));
    assert_eq!(listed_client_ids.len(), 2);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filters_by_provider_id() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let key_a = create_api_key(&state, sample_api_key_create(&domain.id, "provider-a")).await?;
    let _key_b = create_api_key(&state, sample_api_key_create(&domain.id, "provider-b")).await?;

    let listed = state
        .provider
        .get_api_key_provider()
        .list(
            &state,
            &ApiClientResourceListParameters {
                domain_id: domain.id.clone(),
                provider_id: Some("provider-a".to_string()),
                enabled: None,
            },
        )
        .await?;

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].client_id, key_a.client_id);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filters_by_enabled() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let enabled_key =
        create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    let revoked_key =
        create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    state
        .provider
        .get_api_key_provider()
        .revoke(&state, &domain.id, &revoked_key.client_id, "operator-1")
        .await?;

    let listed_enabled = state
        .provider
        .get_api_key_provider()
        .list(
            &state,
            &ApiClientResourceListParameters {
                domain_id: domain.id.clone(),
                provider_id: None,
                enabled: Some(true),
            },
        )
        .await?;

    assert_eq!(listed_enabled.len(), 1);
    assert_eq!(listed_enabled[0].client_id, enabled_key.client_id);

    Ok(())
}
