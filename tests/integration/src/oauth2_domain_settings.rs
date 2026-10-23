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
//! # OAuth2 per-domain settings and the effective DPoP mode (ADR 0043 §1)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`). Proves against the real Raft-backed
//! store that the settings record round-trips, that a change is visible to
//! the next `effective_dpop_mode` lookup without waiting for the cache to
//! expire, and that the strictest of the global, domain and client levels
//! wins.
use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_config::DpopMode;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::oauth2_client::OAuth2DomainSettingsUpdate;

use crate::common::{get_state, get_state_with_config};
use crate::create_domain;

fn set(dpop: DpopMode) -> OAuth2DomainSettingsUpdate {
    OAuth2DomainSettingsUpdate { dpop: Some(dpop) }
}

#[tokio::test]
#[traced_test]
async fn test_oauth2_domain_settings_default_and_roundtrip() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let exec = ExecutionContext::internal(&state);
    let clients = state.provider.get_oauth2_client_provider();

    // A domain that was never configured reports the defaults.
    let defaults = clients.get_domain_settings(&exec, &domain.id).await?;
    assert_eq!(defaults.domain_id, domain.id);
    assert_eq!(defaults.dpop, DpopMode::Disabled);
    assert_eq!(defaults.updated_at, 0);

    let updated = clients
        .update_domain_settings(&exec, &domain.id, set(DpopMode::Required))
        .await?;
    assert_eq!(updated.dpop, DpopMode::Required);
    assert!(updated.updated_at > 0);
    assert_eq!(
        clients.get_domain_settings(&exec, &domain.id).await?,
        updated
    );

    // A request that changes nothing keeps the time of the last change.
    let unchanged = clients
        .update_domain_settings(&exec, &domain.id, set(DpopMode::Required))
        .await?;
    assert_eq!(unchanged.updated_at, updated.updated_at);
    let kept = clients
        .update_domain_settings(&exec, &domain.id, OAuth2DomainSettingsUpdate::default())
        .await?;
    assert_eq!(kept, updated);

    // Removing the record restores the defaults.
    clients.delete_domain_settings(&exec, &domain.id).await?;
    let restored = clients.get_domain_settings(&exec, &domain.id).await?;
    assert_eq!(restored.dpop, DpopMode::Disabled);
    assert_eq!(restored.updated_at, 0);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_oauth2_domain_settings_are_per_domain() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let strict = create_domain!(state)?;
    let other = create_domain!(state)?;
    let exec = ExecutionContext::internal(&state);
    let clients = state.provider.get_oauth2_client_provider();

    clients
        .update_domain_settings(&exec, &strict.id, set(DpopMode::Required))
        .await?;

    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &strict.id, false)
            .await?,
        DpopMode::Required
    );
    assert_eq!(
        clients.effective_dpop_mode(&exec, &other.id, false).await?,
        DpopMode::Disabled
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_oauth2_effective_dpop_mode_sees_a_change_at_once() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let exec = ExecutionContext::internal(&state);
    let clients = state.provider.get_oauth2_client_provider();

    // The first lookup fills the cache with the default.
    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &domain.id, false)
            .await?,
        DpopMode::Disabled
    );
    for mode in [DpopMode::Optional, DpopMode::Required, DpopMode::Disabled] {
        clients
            .update_domain_settings(&exec, &domain.id, set(mode))
            .await?;
        assert_eq!(
            clients
                .effective_dpop_mode(&exec, &domain.id, false)
                .await?,
            mode
        );
    }
    clients
        .update_domain_settings(&exec, &domain.id, set(DpopMode::Optional))
        .await?;
    clients.delete_domain_settings(&exec, &domain.id).await?;
    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &domain.id, false)
            .await?,
        DpopMode::Disabled
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_oauth2_effective_dpop_mode_is_the_strictest_level() -> Result<()> {
    // A global `optional` is a floor: the domain can raise it, never weaken
    // it, and a client flagged for bound tokens is `required` regardless.
    let (state, _tmp) = get_state_with_config(|cfg| cfg.oauth2.dpop = DpopMode::Optional).await?;
    let domain = create_domain!(state)?;
    let exec = ExecutionContext::internal(&state);
    let clients = state.provider.get_oauth2_client_provider();

    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &domain.id, false)
            .await?,
        DpopMode::Optional
    );
    assert_eq!(
        clients.effective_dpop_mode(&exec, &domain.id, true).await?,
        DpopMode::Required
    );

    clients
        .update_domain_settings(&exec, &domain.id, set(DpopMode::Disabled))
        .await?;
    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &domain.id, false)
            .await?,
        DpopMode::Optional,
        "a domain value below the global one does not weaken it"
    );

    clients
        .update_domain_settings(&exec, &domain.id, set(DpopMode::Required))
        .await?;
    assert_eq!(
        clients
            .effective_dpop_mode(&exec, &domain.id, false)
            .await?,
        DpopMode::Required
    );
    Ok(())
}
