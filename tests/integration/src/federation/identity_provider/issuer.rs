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
//! Test identity provider issuer lookup and uniqueness.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::federation::FederationProviderError;
use openstack_keystone_core_types::federation::IdentityProviderUpdate;

use super::{idp, unique};
use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

async fn by_issuer(
    state: &ServiceState,
    domain_id: &str,
    issuer: &str,
) -> Result<Option<String>, FederationProviderError> {
    Ok(state
        .provider
        .get_federation_provider()
        .get_identity_provider_by_issuer(&ExecutionContext::internal(state), domain_id, issuer)
        .await?
        .map(|i| i.id))
}

/// A domain scoped match wins over a global one with the same issuer.
#[traced_test]
#[tokio::test]
async fn test_by_issuer_domain_precedes_global() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let issuer = format!("https://{}.example.com", unique());

    let global = create_identity_provider(&state, idp(None, Some(&issuer), true)).await?;
    // Only the global one exists: it is returned for any domain.
    assert_eq!(
        Some(global.id.clone()),
        by_issuer(&state, &domain.id, &issuer).await?
    );

    let scoped =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), true)).await?;
    assert_eq!(
        Some(scoped.id.clone()),
        by_issuer(&state, &domain.id, &issuer).await?
    );

    // Another domain does not see the scoped one.
    let other = create_domain!(state)?;
    assert_eq!(
        Some(global.id.clone()),
        by_issuer(&state, &other.id, &issuer).await?
    );
    Ok(())
}

/// Unknown issuer and disabled identity provider both resolve to `None`.
#[traced_test]
#[tokio::test]
async fn test_by_issuer_none_for_unknown_and_disabled() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let issuer = format!("https://{}.example.com", unique());

    assert_eq!(None, by_issuer(&state, &domain.id, &issuer).await?);

    let _disabled =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), false)).await?;
    assert_eq!(None, by_issuer(&state, &domain.id, &issuer).await?);

    // IdPs without bound_issuer (global and domain scoped) never match.
    let _no_issuer = create_identity_provider(&state, idp(Some(&domain.id), None, true)).await?;
    let _global_no_issuer = create_identity_provider(&state, idp(None, None, true)).await?;
    assert_eq!(None, by_issuer(&state, &domain.id, &issuer).await?);
    Ok(())
}

/// Two enabled IdPs of the same scope cannot share an issuer; a disabled one
/// can, but cannot be re-enabled while the issuer is taken.
#[traced_test]
#[tokio::test]
async fn test_issuer_conflict() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let issuer = format!("https://{}.example.com", unique());
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);

    let first =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), true)).await?;

    let dup = fed
        .create_identity_provider(&ctx, idp(Some(&domain.id), Some(&issuer), true))
        .await;
    assert!(
        matches!(dup, Err(FederationProviderError::Conflict(_))),
        "{dup:?}"
    );

    // Same issuer in another scope is fine.
    let _global = create_identity_provider(&state, idp(None, Some(&issuer), true)).await?;

    // Disabled duplicate allowed ...
    let retired =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), false)).await?;
    // ... but re-enabling it conflicts.
    let res = fed
        .update_identity_provider(
            &ctx,
            &retired.id,
            IdentityProviderUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(res, Err(FederationProviderError::Conflict(_))),
        "{res:?}"
    );

    // Once the first is disabled, re-enabling succeeds.
    fed.update_identity_provider(
        &ctx,
        &first.id,
        IdentityProviderUpdate {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await?;
    let res = fed
        .update_identity_provider(
            &ctx,
            &retired.id,
            IdentityProviderUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.enabled);
    Ok(())
}

/// A disabled IdP of the domain is not replaced by an enabled global one with
/// the same issuer.
#[traced_test]
#[tokio::test]
async fn test_by_issuer_disabled_domain_idp_blocks_global() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let issuer = format!("https://{}.example.com", unique());

    let _global = create_identity_provider(&state, idp(None, Some(&issuer), true)).await?;
    let _scoped =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), false)).await?;
    assert_eq!(None, by_issuer(&state, &domain.id, &issuer).await?);
    Ok(())
}

/// Changing `bound_issuer` to a value used by an enabled peer conflicts, while
/// unrelated updates on a (disabled) duplicate keep working.
#[traced_test]
#[tokio::test]
async fn test_issuer_conflict_on_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let taken = format!("https://{}.example.com", unique());
    let other = format!("https://{}.example.com", unique());
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);

    let _first =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&taken), true)).await?;
    let second =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&other), true)).await?;

    // Moving onto the taken issuer conflicts ...
    let res = fed
        .update_identity_provider(
            &ctx,
            &second.id,
            IdentityProviderUpdate {
                bound_issuer: Some(Some(taken.clone())),
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(res, Err(FederationProviderError::Conflict(_))),
        "{res:?}"
    );
    // ... and leaves the old issuer in place.
    assert_eq!(
        Some(second.id.clone()),
        by_issuer(&state, &domain.id, &other).await?
    );
    // Re-setting its own issuer is not a conflict with itself.
    fed.update_identity_provider(
        &ctx,
        &second.id,
        IdentityProviderUpdate {
            bound_issuer: Some(Some(other.clone())),
            ..Default::default()
        },
    )
    .await?;

    // A disabled duplicate can be renamed.
    let retired =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&taken), false)).await?;
    let renamed = fed
        .update_identity_provider(
            &ctx,
            &retired.id,
            IdentityProviderUpdate {
                name: Some(unique()),
                ..Default::default()
            },
        )
        .await?;
    assert!(!renamed.enabled);
    Ok(())
}
