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
//! # Per-domain identity driver dispatch (SQL only)
//!
//! Exercises `[identity] domain_specific_drivers_enabled` end to end through
//! the full `Provider` stack: the `DomainConfigResolver` is consulted for a
//! domain's stored `identity/driver`, and `DomainConfigService` enforces the
//! single-domain SQL identity-driver registration lock on config writes.
//!
//! Both the global and the per-domain driver here are `sql`, so these do not
//! cover cross-backend routing, the `_select_identity_driver` `DomainNotFound`
//! guard, or `CrossBackendNotAllowed` -- those need a second, non-domain-aware
//! backend and are a follow-up (real LDAP harness).

use eyre::Result;
use serde_json::json;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::domain_config::DomainConfigProviderError;
use openstack_keystone_core_types::domain_config::{DomainConfig, DomainConfigCreate};
use openstack_keystone_core_types::identity::*;

use crate::common::get_state_with_config;

/// Turn on per-domain identity drivers with the database as the config source.
fn enable_domain_specific(cfg: &mut Config) {
    cfg.identity.domain_specific_drivers_enabled = true;
    cfg.identity.domain_configurations_from_database = true;
}

/// A stored configuration pinning a domain to the `sql` identity driver.
fn sql_identity_config() -> DomainConfigCreate {
    DomainConfigCreate(
        DomainConfig::from_value(json!({"identity": {"driver": "sql"}}))
            .expect("valid domain configuration"),
    )
}

/// A domain whose stored config names `identity/driver = sql` resolves through
/// `DomainConfigResolver` to the (same) global SQL backend, and ordinary user
/// CRUD scoped to that domain still works.
#[tokio::test]
#[traced_test]
async fn a_domain_pinned_to_the_sql_driver_serves_user_crud() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_domain_specific).await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = crate::create_domain!(state)?;

    // Seed the stored config BEFORE the first identity call for this domain:
    // `driver_for` caches the resolved driver name per domain with no
    // invalidation.
    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &domain.id, sql_identity_config())
        .await?;

    let name = Uuid::new_v4().to_string();
    state
        .provider
        .get_identity_provider()
        .create_user(
            &ctx,
            UserCreateBuilder::default()
                .name(name.clone())
                .domain_id(domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;

    let users: Vec<UserResponse> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ctx,
            &UserListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();

    assert_eq!(users.len(), 1, "the domain-scoped user should be listed");
    assert_eq!(users[0].name, name);
    Ok(())
}

/// At most one domain may hold `identity/driver = sql` while configurations
/// come from the database: the second claim is rejected `Conflict`, and the
/// write does not land.
#[tokio::test]
#[traced_test]
async fn the_sql_identity_driver_registration_is_single_domain() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_domain_specific).await?;
    let first = crate::create_domain!(state)?;
    let second = crate::create_domain!(state)?;
    let dc = state.provider.get_domain_config_provider();

    dc.create_domain_config(&state, &first.id, sql_identity_config())
        .await?;

    let err = dc
        .create_domain_config(&state, &second.id, sql_identity_config())
        .await
        .expect_err("a second domain must not claim the SQL identity driver");
    assert!(
        matches!(err, DomainConfigProviderError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    assert!(
        dc.get_domain_config(&state, &second.id).await?.is_none(),
        "the rejected config must not have been stored"
    );
    Ok(())
}

/// Deleting the owning domain's configuration releases the SQL registration,
/// letting another domain claim it.
#[tokio::test]
#[traced_test]
async fn deleting_a_domain_config_frees_the_sql_registration() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_domain_specific).await?;
    let first = crate::create_domain!(state)?;
    let second = crate::create_domain!(state)?;
    let dc = state.provider.get_domain_config_provider();

    dc.create_domain_config(&state, &first.id, sql_identity_config())
        .await?;
    dc.delete_domain_config(&state, &first.id).await?;

    // Registration is free again.
    dc.create_domain_config(&state, &second.id, sql_identity_config())
        .await?;
    Ok(())
}
