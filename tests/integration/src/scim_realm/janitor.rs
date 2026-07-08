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
//! SCIM resource janitor sweep (ADR 0024 §6.C) exercised against the real
//! Raft-backed provider, complementing
//! `crates/core/src/scim_resource/janitor.rs`'s mocked unit tests: those
//! cover the branching logic in isolation, this confirms
//! `list_all_index`/`update_index`/`purge_index` actually round-trip
//! through the real storage/CAS layer end to end, and that the sweep
//! correctly scopes across multiple realms/domains without cross-purging.

use std::time::Duration;

use chrono::Utc;
use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::scim_resource::janitor;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexCreateBuilder, ScimResourceIndexUpdate, ScimResourceProviderError,
    ScimResourceType,
};

use super::{create_realm, sample_realm_create};

use crate::common::get_state;
use crate::{create_domain, create_user};

#[traced_test]
#[tokio::test]
async fn test_run_once_purges_old_tombstone_via_real_backend() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;
    let user = create_user!(state, domain.id.clone())?;

    // Zero retention so a just-tombstoned resource is immediately eligible.
    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.scim_resource.janitor_deprovisioned_retention_days = 0;
    }

    let exec = ExecutionContext::internal(&state);
    state
        .provider
        .get_scim_resource_provider()
        .create_index(
            &exec,
            ScimResourceIndexCreateBuilder::default()
                .domain_id(domain.id.clone())
                .provider_id("provider-1")
                .resource_type(ScimResourceType::User)
                .keystone_id(user.id.clone())
                .build()?,
        )
        .await?;

    let now = Utc::now().timestamp();
    state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &domain.id,
            "provider-1",
            ScimResourceType::User,
            &user.id,
            ScimResourceIndexUpdate {
                deprovisioned_at: Some(Some(now)),
                ..Default::default()
            },
            None,
        )
        .await?;
    // Guarantee `now - deprovisioned_at > 0` (second-granularity timestamps).
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.purged, 1);
    assert_eq!(report.errors, 0);

    let fetched_user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user.id)
        .await?;
    assert!(
        fetched_user.is_none(),
        "purge must hard-delete the User row"
    );

    let fetched_index = state
        .provider
        .get_scim_resource_provider()
        .get_index(
            &exec,
            &domain.id,
            "provider-1",
            ScimResourceType::User,
            &user.id,
        )
        .await?;
    assert!(
        fetched_index.is_none(),
        "purge must remove the index anchor"
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_purge_now_bypasses_retention_window() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;
    let user = create_user!(state, domain.id.clone())?;

    // Default (365 day) retention -- purge_now must still act immediately.
    let exec = ExecutionContext::internal(&state);
    state
        .provider
        .get_scim_resource_provider()
        .create_index(
            &exec,
            ScimResourceIndexCreateBuilder::default()
                .domain_id(domain.id.clone())
                .provider_id("provider-1")
                .resource_type(ScimResourceType::User)
                .keystone_id(user.id.clone())
                .build()?,
        )
        .await?;
    state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &domain.id,
            "provider-1",
            ScimResourceType::User,
            &user.id,
            ScimResourceIndexUpdate {
                deprovisioned_at: Some(Some(Utc::now().timestamp())),
                ..Default::default()
            },
            None,
        )
        .await?;

    janitor::purge_now(
        &state,
        &domain.id,
        "provider-1",
        ScimResourceType::User,
        &user.id,
    )
    .await?;

    let fetched_user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user.id)
        .await?;
    assert!(fetched_user.is_none());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_purge_now_rejects_live_resource_via_real_backend() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;
    let user = create_user!(state, domain.id.clone())?;

    let exec = ExecutionContext::internal(&state);
    state
        .provider
        .get_scim_resource_provider()
        .create_index(
            &exec,
            ScimResourceIndexCreateBuilder::default()
                .domain_id(domain.id.clone())
                .provider_id("provider-1")
                .resource_type(ScimResourceType::User)
                .keystone_id(user.id.clone())
                .build()?,
        )
        .await?;
    // Never tombstoned -- still live.

    let err = janitor::purge_now(
        &state,
        &domain.id,
        "provider-1",
        ScimResourceType::User,
        &user.id,
    )
    .await
    .expect_err("purge_now must refuse a live (non-deprovisioned) resource");
    assert!(matches!(err, ScimResourceProviderError::Conflict(_)));

    let fetched_user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user.id)
        .await?;
    assert!(
        fetched_user.is_some(),
        "rejected purge must not delete the user"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_run_once_scopes_sweep_across_realms_without_cross_purging() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;
    create_realm(&state, sample_realm_create(&domain_a.id, "provider-1")).await?;
    create_realm(&state, sample_realm_create(&domain_b.id, "provider-1")).await?;
    let user_a = create_user!(state, domain_a.id.clone())?;
    let user_b = create_user!(state, domain_b.id.clone())?;

    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.scim_resource.janitor_deprovisioned_retention_days = 0;
    }

    let exec = ExecutionContext::internal(&state);
    for (domain, user) in [(&domain_a, &user_a), (&domain_b, &user_b)] {
        state
            .provider
            .get_scim_resource_provider()
            .create_index(
                &exec,
                ScimResourceIndexCreateBuilder::default()
                    .domain_id(domain.id.clone())
                    .provider_id("provider-1")
                    .resource_type(ScimResourceType::User)
                    .keystone_id(user.id.clone())
                    .build()?,
            )
            .await?;
    }
    // Only domain_a's resource is tombstoned; domain_b's stays live.
    state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &domain_a.id,
            "provider-1",
            ScimResourceType::User,
            &user_a.id,
            ScimResourceIndexUpdate {
                deprovisioned_at: Some(Some(Utc::now().timestamp())),
                ..Default::default()
            },
            None,
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let report = janitor::run_once(&state).await?;
    assert_eq!(report.purged, 1);
    assert_eq!(report.errors, 0);

    assert!(
        state
            .provider
            .get_identity_provider()
            .get_user(&exec, &user_a.id)
            .await?
            .is_none(),
        "domain_a's tombstoned user must be purged"
    );
    assert!(
        state
            .provider
            .get_identity_provider()
            .get_user(&exec, &user_b.id)
            .await?
            .is_some(),
        "domain_b's live user must survive the same sweep"
    );

    Ok(())
}
