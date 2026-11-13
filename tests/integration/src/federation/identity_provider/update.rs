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
//! Test identity provider update.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::federation::FederationProviderError;
use openstack_keystone_core_types::federation::IdentityProviderUpdate;

use super::{idp, unique};
use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

/// Update changes only the supplied fields and can clear optional ones.
#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);

    let created =
        create_identity_provider(&state, idp(Some(&domain.id), Some("https://i"), true)).await?;
    let new_name = unique();

    let updated = fed
        .update_identity_provider(
            &ctx,
            &created.id,
            IdentityProviderUpdate {
                name: Some(new_name.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(new_name, updated.name);
    assert_eq!(Some("https://i".to_string()), updated.bound_issuer);
    assert!(updated.enabled);

    let cleared = fed
        .update_identity_provider(
            &ctx,
            &created.id,
            IdentityProviderUpdate {
                bound_issuer: Some(None),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(None, cleared.bound_issuer);
    let fetched = fed
        .get_identity_provider(&ctx, &created.id)
        .await?
        .ok_or_else(|| eyre::eyre!("idp missing"))?;
    assert_eq!(None, fetched.bound_issuer);

    // Disabling persists.
    let disabled = fed
        .update_identity_provider(
            &ctx,
            &created.id,
            IdentityProviderUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert!(!disabled.enabled);
    let fetched = fed
        .get_identity_provider(&ctx, &created.id)
        .await?
        .ok_or_else(|| eyre::eyre!("idp missing"))?;
    assert!(!fetched.enabled);

    // Other fields can be set and cleared.
    let set = fed
        .update_identity_provider(
            &ctx,
            &created.id,
            IdentityProviderUpdate {
                oidc_client_id: Some(Some("client".into())),
                oidc_scopes: Some(Some(vec!["openid".into()])),
                jwks_url: Some(Some("https://jwks.example.com".into())),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(Some("client".to_string()), set.oidc_client_id);
    assert_eq!(Some(vec!["openid".to_string()]), set.oidc_scopes);
    let cleared = fed
        .update_identity_provider(
            &ctx,
            &created.id,
            IdentityProviderUpdate {
                oidc_client_id: Some(None),
                oidc_scopes: Some(None),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(None, cleared.oidc_client_id);
    assert_eq!(None, cleared.oidc_scopes);
    assert_eq!(
        Some("https://jwks.example.com".to_string()),
        cleared.jwks_url
    );

    let res = fed
        .update_identity_provider(&ctx, "missing", IdentityProviderUpdate::default())
        .await;
    assert!(
        matches!(
            res,
            Err(FederationProviderError::IdentityProviderNotFound(_))
        ),
        "{res:?}"
    );
    Ok(())
}
