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
//! Janitor sweep (ADR 0021 §6.F) exercised against the real Raft-backed
//! provider, complementing `crates/core/src/api_key/janitor.rs`'s mocked
//! unit tests: those cover the branching logic in isolation, this confirms
//! `list_all`/`update`/`purge` actually round-trip through the real
//! storage/CAS layer end to end.

use std::time::Duration;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::api_key::janitor;

use super::{create_api_key, sample_api_key_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_janitor_disables_inactive_key_via_real_backend() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    // Zero thresholds so a freshly created (never-used) key is immediately
    // past the inactivity threshold, without waiting real days.
    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.api_key.janitor_inactive_days = 0;
        cfg.api_key.janitor_grace_days = 0;
    }

    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    // Guarantee `now - created_at > 0` (second-granularity timestamps).
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.disabled, 1);
    assert_eq!(report.errors, 0);

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?
        .expect("disabled key must still be resolvable, not hard-deleted");
    assert!(!fetched.enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_janitor_purges_old_tombstone_via_real_backend() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    // Zero retention so a just-revoked key's tombstone is immediately
    // eligible for physical purge.
    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.api_key.janitor_tombstone_retention_days = 0;
    }

    let created = create_api_key(&state, sample_api_key_create(&domain.id, "provider-1")).await?;
    state
        .provider
        .get_api_key_provider()
        .revoke(&state, &domain.id, &created.client_id, "operator-1")
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.purged, 1);
    assert_eq!(report.errors, 0);

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain.id, &created.lookup_hash)
        .await?;
    assert!(
        fetched.is_none(),
        "purge must be a hard delete from the real backend"
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_janitor_leaves_active_key_across_domains_alone() -> Result<()> {
    // list_all (§2, §6.F) must sweep across every domain's keyspace
    // partition, but a recently-active key in any domain must survive.
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;

    let key_a = create_api_key(&state, sample_api_key_create(&domain_a.id, "provider-1")).await?;
    let _key_b = create_api_key(&state, sample_api_key_create(&domain_b.id, "provider-1")).await?;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.disabled, 0);
    assert_eq!(report.purged, 0);

    let fetched = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(&state, &domain_a.id, &key_a.lookup_hash)
        .await?
        .expect("key must still exist");
    assert!(fetched.enabled);

    Ok(())
}
