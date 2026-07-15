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
//! # OAuth2 signing-key janitor integration tests (ADR 0026 §3)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`). Complements
//! `crates/core/src/oauth2_key/janitor.rs`'s mocked unit tests (which cover
//! the branching logic in isolation): this confirms `rotate_signing_key`/
//! `list_all_active_keys`/`retire_previous_key`/`prune_expired_jtis`
//! actually round-trip through the real Raft-backed storage layer,
//! mirroring `tests/integration/src/api_key/janitor.rs`'s pattern.

use std::time::Duration;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::oauth2_key::janitor;

use crate::common::get_state_with_config;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_janitor_retires_previous_key_via_real_backend() -> Result<()> {
    // Zero the access-token lifetime so a just-demoted `Previous` key is
    // immediately past retention, without waiting a real access-token
    // lifetime's worth of minutes.
    let (state, _tmp) =
        get_state_with_config(|cfg| cfg.oauth2.access_token_lifetime_minutes = 0).await?;
    let domain = create_domain!(state)?;

    let key_provider = state.provider.get_oauth2_key_provider();
    key_provider.ensure_domain_keys(&state, &domain.id).await?;
    // Normal rotation demotes the current Primary to Previous, stamping
    // `demoted_at = now`.
    key_provider.rotate_signing_key(&state, &domain.id).await?;
    // Guarantee `now - demoted_at > 0` (second-granularity timestamps).
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.retired, 1);
    assert_eq!(report.errors, 0);

    let active = key_provider
        .list_all_active_keys(&state)
        .await?
        .into_iter()
        .find(|(id, _)| id == &domain.id)
        .expect("domain must still be listed");
    assert!(
        active.1.previous.is_none(),
        "the retired Previous key must be gone from the real backend"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_janitor_leaves_recently_rotated_key_alone() -> Result<()> {
    // Default (non-zero) access-token lifetime: a key demoted moments ago
    // must survive this pass.
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let domain = create_domain!(state)?;

    let key_provider = state.provider.get_oauth2_key_provider();
    key_provider.ensure_domain_keys(&state, &domain.id).await?;
    key_provider.rotate_signing_key(&state, &domain.id).await?;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.retired, 0);

    let active = key_provider
        .list_all_active_keys(&state)
        .await?
        .into_iter()
        .find(|(id, _)| id == &domain.id)
        .expect("domain must still be listed");
    assert!(
        active.1.previous.is_some(),
        "a freshly demoted Previous key must not be retired early"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_janitor_sweeps_across_multiple_domains() -> Result<()> {
    let (state, _tmp) =
        get_state_with_config(|cfg| cfg.oauth2.access_token_lifetime_minutes = 0).await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;

    let key_provider = state.provider.get_oauth2_key_provider();
    for domain in [&domain_a, &domain_b] {
        key_provider.ensure_domain_keys(&state, &domain.id).await?;
        key_provider.rotate_signing_key(&state, &domain.id).await?;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.retired, 2, "both domains' Previous keys must retire");
    assert_eq!(report.errors, 0);

    Ok(())
}
