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
//! # Functional tests against a real OpenLDAP (`slapd`) instance
//!
//! Exercises the LDAP driver's query, ID/DN, filter, and bind-auth logic
//! against an actual directory, seeded from
//! `tests/fixtures/base.ldif` (`tests/fixtures/keystone-test.schema` adds
//! the non-standard `enabled` attribute used by `disableduser`).
//!
//! Opt-in: skipped unless `KEYSTONE_LDAP_TEST_URL` is set. The `ldap`
//! nextest profile (`.config/nextest.toml`) sets it via
//! `tools/start-ldap-test.sh`, which starts and seeds a throwaway local
//! `slapd` (no Docker daemon required). Run manually with:
//! `tools/start-ldap-test.sh && cargo test -p openstack-keystone-identity-driver-ldap --lib live_tests`.
use secrecy::SecretString;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core_types::identity::{
    GroupListParametersBuilder, IdentityProviderError, UserListParametersBuilder,
    UserPasswordAuthRequestBuilder,
};

use crate::{LdapBackend, authenticate, group, user};

const DEFAULT_DOMAIN_ID: &str = "default";

/// Test fixture connection details, or `None` to skip (no live directory
/// configured for this test run).
fn test_url() -> Option<String> {
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

fn test_config(url: &str) -> LdapProvider {
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

/// Skips (returns `Ok(None)`, letting the caller `return Ok(())`) rather
/// than failing when no live directory is configured for this run.
macro_rules! skip_unless_configured {
    () => {
        match test_url() {
            Some(url) => url,
            None => {
                eprintln!(
                    "skipping live LDAP test: KEYSTONE_LDAP_TEST_URL not set \
                     (run tools/start-ldap-test.sh first, or use the `ldap` nextest profile)"
                );
                return Ok(());
            }
        }
    };
}

#[tokio::test]
async fn test_get_user_by_id() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(format!("failed to connect: {e}")))?;
    let found = user::get(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        "jdoe",
    )
    .await?
    .expect("jdoe must exist in the seeded fixture");
    assert_eq!(found.id, "jdoe");
    assert_eq!(found.name, "Doe");
    assert_eq!(found.domain_id, DEFAULT_DOMAIN_ID);
    assert!(
        found.enabled,
        "jdoe has no `enabled` attribute; must default to enabled"
    );
    Ok(())
}

#[tokio::test]
async fn test_get_user_not_found_returns_none() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let found = user::get(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        "nobody-such-user",
    )
    .await?;
    assert!(found.is_none());
    Ok(())
}

#[tokio::test]
async fn test_disabled_user_reports_disabled() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let found = user::get(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        "disableduser",
    )
    .await?
    .expect("disableduser must exist in the seeded fixture");
    assert!(!found.enabled);
    Ok(())
}

#[tokio::test]
async fn test_list_users_by_name() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let params = UserListParametersBuilder::default()
        .name(Some("Doe".to_string()))
        .build()
        .expect("valid params");
    let users = user::list(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &params,
    )
    .await?;
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, "jdoe");
    Ok(())
}

#[tokio::test]
async fn test_list_users_all_finds_seeded_entries() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let params = UserListParametersBuilder::default()
        .build()
        .expect("valid params");
    let users = user::list(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &params,
    )
    .await?;
    let ids: Vec<&str> = users.iter().map(|u| u.id.as_str()).collect();
    assert!(ids.contains(&"jdoe"));
    assert!(ids.contains(&"bsmith"));
    assert!(ids.contains(&"disableduser"));
    Ok(())
}

#[tokio::test]
async fn test_find_user_by_name_ci() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let id = user::find_by_name_ci(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        DEFAULT_DOMAIN_ID,
        "doe",
    )
    .await?;
    assert_eq!(id, Some("jdoe".to_string()));
    Ok(())
}

#[tokio::test]
async fn test_get_group_and_members() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let found = group::get(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        "users",
    )
    .await?
    .expect("`users` group must exist in the seeded fixture");
    assert_eq!(found.id, "users");

    let members =
        group::list_users_of_group(&backend.service_pool, &backend.config, "users").await?;
    let mut members = members;
    members.sort();
    assert_eq!(members, vec!["bsmith".to_string(), "jdoe".to_string()]);
    Ok(())
}

#[tokio::test]
async fn test_list_groups_by_name() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let params = GroupListParametersBuilder::default()
        .name("admins")
        .build()
        .expect("valid params");
    let groups = group::list(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &params,
    )
    .await?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, "admins");
    Ok(())
}

#[tokio::test]
async fn test_list_groups_of_user() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let jdoe_dn = user::resolve_dn(&backend.service_pool, &backend.config, Some("jdoe"), None)
        .await?
        .expect("jdoe must resolve to a DN");
    let groups = group::list_groups_of_user_dn(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &jdoe_dn,
    )
    .await?;
    let mut ids: Vec<&str> = groups.iter().map(|g| g.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["admins", "users"]);
    Ok(())
}

/// `group_members_are_ids` support (`posixGroup`'s `memberUid`): member
/// values are keystone user IDs already, with no DN round trip.
#[tokio::test]
async fn test_list_users_of_group_members_are_ids() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let mut cfg = test_config(&url);
    cfg.group_objectclass = "posixGroup".into();
    cfg.group_member_attribute = "memberUid".into();
    cfg.group_members_are_ids = true;
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let mut members =
        group::list_users_of_group(&backend.service_pool, &backend.config, "posixadmins").await?;
    members.sort();
    assert_eq!(members, vec!["bsmith".to_string(), "jdoe".to_string()]);
    Ok(())
}

#[tokio::test]
async fn test_authenticate_by_password_success() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let auth = UserPasswordAuthRequestBuilder::default()
        .id("jdoe")
        .password(SecretString::from("jdoepass"))
        .build()
        .expect("valid auth request");
    let result = authenticate::authenticate_by_password(
        &backend.service_pool,
        &backend.auth_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &auth,
    )
    .await?;
    match result.principal.identity {
        openstack_keystone_core::auth::IdentityInfo::User(u) => {
            assert_eq!(u.user_id, "jdoe");
        }
        other => panic!("expected IdentityInfo::User, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn test_authenticate_by_password_wrong_password_rejected() -> Result<(), IdentityProviderError>
{
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let auth = UserPasswordAuthRequestBuilder::default()
        .id("jdoe")
        .password(SecretString::from("not-the-password"))
        .build()
        .expect("valid auth request");
    let result = authenticate::authenticate_by_password(
        &backend.service_pool,
        &backend.auth_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &auth,
    )
    .await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_authenticate_by_password_disabled_user_rejected() -> Result<(), IdentityProviderError>
{
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let auth = UserPasswordAuthRequestBuilder::default()
        .id("disableduser")
        .password(SecretString::from("disabledpass"))
        .build()
        .expect("valid auth request");
    let result = authenticate::authenticate_by_password(
        &backend.service_pool,
        &backend.auth_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        &auth,
    )
    .await;
    assert!(
        result.is_err(),
        "a disabled user must be rejected even with the correct password"
    );
    Ok(())
}

#[tokio::test]
async fn test_check_user_exist_rejects_disabled_user() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let cfg = test_config(&url);
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let result = user::check_user_exist(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        Some("disableduser"),
        None,
        None,
    )
    .await;
    assert!(result.is_err());
    Ok(())
}

/// `[ldap] query_scope = "one"` must still find entries directly under the
/// tree DN (a one-level-deep, flat OU, as in the fixture).
#[tokio::test]
async fn test_query_scope_one_still_finds_flat_entries() -> Result<(), IdentityProviderError> {
    let url = skip_unless_configured!();
    let mut cfg = test_config(&url);
    cfg.query_scope = openstack_keystone_config::QueryScope::One;
    let backend = LdapBackend::new(&cfg)
        .await
        .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;
    let found = user::get(
        &backend.service_pool,
        &backend.config,
        DEFAULT_DOMAIN_ID,
        "jdoe",
    )
    .await?;
    assert!(found.is_some());
    Ok(())
}
