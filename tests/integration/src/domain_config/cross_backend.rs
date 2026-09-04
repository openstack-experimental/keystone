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
//! # Cross-backend (SQL + LDAP) per-domain identity dispatch
//!
//! The parent `domain_config` module only ever has one backend (`sql`)
//! configured both globally and per domain, so it cannot exercise real
//! cross-backend routing or the `driver_for` `DomainNotFound` guard for a
//! non-domain-aware global driver. This module adds a second, non-domain-
//! aware backend by driving a real LDAP directory -- the same fixture
//! harness `identity-driver-ldap`'s own `live_tests` module uses
//! (`tools/start-ldap-test.sh`, seeded from
//! `crates/identity-driver-ldap/tests/fixtures/base.ldif`).
//!
//! Opt-in: every test here skips itself (rather than failing) unless
//! `KEYSTONE_LDAP_TEST_URL` is set. The `ldap`/`ci-ldap` nextest profiles
//! set it; run manually with `tools/start-ldap-test.sh && cargo test -p
//! test_integration domain_config::cross_backend`.
//!
//! Also covers `membership_backend`'s `CrossBackendNotAllowed`: that guard
//! resolves entities via an id-mapping lookup
//! (`crates/core/src/idmapping/`), which regular `create_user` does not
//! populate yet (nothing routes through it outside federated/shadow-user
//! auth) -- so the test seeds the mapping rows directly via `IdMappingApi`
//! rather than relying on `create_user` to do it.

use eyre::Result;
use secrecy::SecretString;
use tracing_test::traced_test;

use openstack_keystone_config::{Config, LdapProvider};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::*;
use openstack_keystone_core_types::idmapping::IdMappingEntityType;
use openstack_keystone_core_types::resource::ResourceProviderError;

use crate::common::get_state_with_config;

use super::{enable_domain_specific, ldap_identity_config, sql_identity_config};

/// Test fixture connection details, or `None` to skip (no live directory
/// configured for this test run).
pub(super) fn test_url() -> Option<String> {
    std::env::var("KEYSTONE_LDAP_TEST_URL").ok()
}

fn base_dn() -> String {
    std::env::var("KEYSTONE_LDAP_TEST_BASE_DN").unwrap_or_else(|_| "dc=example,dc=com".into())
}

fn admin_dn() -> String {
    std::env::var("KEYSTONE_LDAP_TEST_ADMIN_DN")
        .unwrap_or_else(|_| format!("cn=admin,{}", base_dn()))
}

fn admin_pw() -> String {
    std::env::var("KEYSTONE_LDAP_TEST_ADMIN_PW").unwrap_or_else(|_| "adminpw".into())
}

/// An `LdapProvider` pointed at the seeded fixture directory.
pub(super) fn test_ldap_config(url: &str) -> LdapProvider {
    LdapProvider {
        url: url.to_string(),
        user: Some(admin_dn()),
        password: Some(SecretString::from(admin_pw())),
        user_tree_dn: format!("ou=Users,{}", base_dn()),
        group_tree_dn: format!("ou=Groups,{}", base_dn()),
        suffix: base_dn(),
        ..Default::default()
    }
}

/// Skips (returns from the enclosing test with `Ok(())`) rather than failing
/// when no live directory is configured for this run.
macro_rules! skip_unless_configured {
    () => {
        if test_url().is_none() {
            eprintln!(
                "skipping cross-backend domain_config test: KEYSTONE_LDAP_TEST_URL not set \
                 (run tools/start-ldap-test.sh first, or use the `ldap` nextest profile)"
            );
            return Ok(());
        }
    };
}

/// A domain pinned to `sql` and a domain pinned to `ldap` are served by two
/// different, live backend instances: each only ever sees its own domain's
/// data.
///
/// The `ldap` side must use domain id `"default"` (`[identity]
/// default_domain_id`'s value), not a freshly created domain: the LDAP
/// driver is not domain aware (`is_domain_aware() == false`, a single
/// directory maps to one domain) and its own list filter short-circuits to
/// an empty result for any `domain_id` other than the configured default
/// (`crates/identity-driver-ldap/src/filter.rs::domain_matches`) --
/// `driver_for`'s dispatch only decides *which* backend serves a domain, it
/// does not relax that backend's own domain-scoping rules.
#[tokio::test]
#[traced_test]
async fn cross_backend_dispatch_routes_to_correct_backend() -> Result<()> {
    skip_unless_configured!();
    let (state, _tmp) = get_state_with_config(enable_domain_specific).await?;
    let ctx = ExecutionContext::internal(&state);

    let sql_domain = crate::create_domain!(state)?;
    let ldap_domain_id = "default";
    let dc = state.provider.get_domain_config_provider();
    dc.create_domain_config(&state, &sql_domain.id, sql_identity_config())
        .await?;
    dc.create_domain_config(&state, ldap_domain_id, ldap_identity_config())
        .await?;

    let sql_user_name = uuid::Uuid::new_v4().to_string();
    state
        .provider
        .get_identity_provider()
        .create_user(
            &ctx,
            UserCreateBuilder::default()
                .name(sql_user_name.clone())
                .domain_id(sql_domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;

    let sql_users: Vec<UserResponse> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ctx,
            &UserListParameters {
                domain_id: Some(sql_domain.id.clone()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    assert_eq!(sql_users.len(), 1, "the sql domain sees only its own user");
    assert_eq!(sql_users[0].name, sql_user_name);

    let ldap_users: Vec<UserResponse> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ctx,
            &UserListParameters {
                domain_id: Some(ldap_domain_id.to_string()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    let ldap_ids: Vec<&str> = ldap_users.iter().map(|u| u.id.as_str()).collect();
    assert!(
        ldap_ids.contains(&"jdoe") && ldap_ids.contains(&"bsmith"),
        "the ldap domain must see the seeded fixture users, got {ldap_ids:?}"
    );
    assert!(
        !ldap_ids.contains(&sql_user_name.as_str()),
        "the ldap domain must not see the sql domain's user"
    );
    Ok(())
}

/// When the *global* driver is `ldap` (not domain aware) and a domain has no
/// stored config, dispatch must not silently hand that domain's requests to
/// the single shared directory -- it 404s `DomainNotFound` instead. Mirrors
/// python-keystone's `Manager._select_identity_driver`.
#[tokio::test]
#[traced_test]
async fn global_ldap_driver_rejects_unconfigured_domain() -> Result<()> {
    skip_unless_configured!();
    let (state, _tmp) = get_state_with_config(|cfg: &mut Config| {
        enable_domain_specific(cfg);
        cfg.identity.driver = "ldap".to_string();
    })
    .await?;
    let ctx = ExecutionContext::internal(&state);

    // No domain_config row for this domain: resolution falls back to the
    // global `ldap` driver, which is not domain aware.
    let domain = crate::create_domain!(state)?;

    let err = state
        .provider
        .get_identity_provider()
        .list_users(
            &ctx,
            &UserListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await
        .expect_err("a non-domain-aware global driver must reject a non-default domain");
    assert!(
        matches!(
            err,
            IdentityProviderError::ResourceProvider {
                source: ResourceProviderError::DomainNotFound(_)
            }
        ),
        "expected DomainNotFound, got {err:?}"
    );
    Ok(())
}

/// A group membership that spans two live backend instances is rejected
/// `CrossBackendNotAllowed`, once both entities are actually resolvable via
/// the id mapping (`driver_for_user`/`driver_for_group`,
/// `crates/core/src/identity/service.rs`).
///
/// `create_user` does not itself populate the id mapping today, so this
/// seeds it directly through `IdMappingApi::create_id_mapping` -- the public
/// id must be the entity's real id, since that's what
/// `driver_for_public_id` looks up.
#[tokio::test]
#[traced_test]
async fn cross_backend_group_membership_rejected() -> Result<()> {
    skip_unless_configured!();
    let (state, _tmp) = get_state_with_config(enable_domain_specific).await?;
    let ctx = ExecutionContext::internal(&state);

    let sql_domain = crate::create_domain!(state)?;
    let ldap_domain_id = "default";
    let dc = state.provider.get_domain_config_provider();
    dc.create_domain_config(&state, &sql_domain.id, sql_identity_config())
        .await?;
    dc.create_domain_config(&state, ldap_domain_id, ldap_identity_config())
        .await?;

    let sql_user_name = uuid::Uuid::new_v4().to_string();
    let sql_user = state
        .provider
        .get_identity_provider()
        .create_user(
            &ctx,
            UserCreateBuilder::default()
                .name(sql_user_name.clone())
                .domain_id(sql_domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;

    // A seeded fixture group (`base.ldif`) in the ldap-backed `default`
    // domain.
    let ldap_group_id = "admins";

    let idm = state.provider.get_idmapping_provider();
    idm.create_id_mapping(
        &ctx,
        &sql_user.id,
        &sql_domain.id,
        IdMappingEntityType::User,
        Some(sql_user.id.as_str()),
    )
    .await?;
    idm.create_id_mapping(
        &ctx,
        ldap_group_id,
        ldap_domain_id,
        IdMappingEntityType::Group,
        Some(ldap_group_id),
    )
    .await?;

    let err = state
        .provider
        .get_identity_provider()
        .add_user_to_group(&ctx, &sql_user.id, ldap_group_id)
        .await
        .expect_err("a membership spanning two live backends must be rejected");
    assert!(
        matches!(err, IdentityProviderError::CrossBackendNotAllowed { .. }),
        "expected CrossBackendNotAllowed, got {err:?}"
    );
    Ok(())
}
