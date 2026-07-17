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
//! # LDAP user read operations (ADR-0027 §3)
use ldap3::Scope;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core::auth::AuthenticationError;
use openstack_keystone_core_types::identity::{
    IdentityProviderError, UserListParameters, UserResponse,
};

use crate::connection::ServicePool;
use crate::enabled::enabled_via_group_membership;
use crate::filter::{ListDecision, escape_filter_value, user_list_filter};
use crate::id_dn::{self, ldap_scope};
use crate::models;

const ALL_ATTRS: [&str; 1] = ["*"];

/// Look up a single user entry by `id_attribute` under `user_tree_dn`,
/// scoped by `[ldap] query_scope`, mirroring Python's `_ldap_get` (the read
/// path never constructs a DN directly — that's write-only in Python and
/// this backend is permanently read-only).
async fn get_entry_by_id(
    pool: &ServicePool,
    cfg: &LdapProvider,
    user_id: &str,
) -> Result<Option<ldap3::SearchEntry>, IdentityProviderError> {
    let mut filter = format!(
        "(&({}={})(objectClass={}))",
        cfg.user_id_attribute,
        escape_filter_value(user_id),
        cfg.user_objectclass
    );
    if let Some(extra) = &cfg.user_filter {
        filter = format!("(&{filter}{extra})");
    }
    let entries = pool
        .search(
            &cfg.user_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &ALL_ATTRS,
        )
        .await?;
    Ok(entries.into_iter().next())
}

/// Apply the group-membership enabled-emulation strategy on top of the
/// attribute-derived `enabled` value, when configured (ADR-0027 §7).
async fn apply_enabled_emulation(
    pool: &ServicePool,
    cfg: &LdapProvider,
    base_enabled: bool,
    user_dn: &str,
) -> Result<bool, IdentityProviderError> {
    if !cfg.user_enabled_emulation {
        return Ok(base_enabled);
    }
    let Some(group_dn) = &cfg.user_enabled_emulation_dn else {
        return Ok(base_enabled);
    };
    enabled_via_group_membership(pool, group_dn, &cfg.group_member_attribute, user_dn).await
}

/// Resolve `user_id`/`name` to the entry's DN, without fetching attributes.
/// Used ahead of the second bind step in `authenticate_by_password`.
pub async fn resolve_dn(
    pool: &ServicePool,
    cfg: &LdapProvider,
    id: Option<&str>,
    name: Option<&str>,
) -> Result<Option<String>, IdentityProviderError> {
    if let Some(id) = id {
        return Ok(get_entry_by_id(pool, cfg, id).await?.map(|e| e.dn));
    }
    if let Some(name) = name {
        return find_dn_by_attribute(pool, cfg, &cfg.user_name_attribute, name).await;
    }
    Ok(None)
}

async fn find_dn_by_attribute(
    pool: &ServicePool,
    cfg: &LdapProvider,
    attribute: &str,
    value: &str,
) -> Result<Option<String>, IdentityProviderError> {
    let filter = format!(
        "(&(objectClass={})({attribute}={}))",
        cfg.user_objectclass,
        escape_filter_value(value)
    );
    let entries = pool
        .search(
            &cfg.user_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &[attribute],
        )
        .await?;
    Ok(entries.into_iter().next().map(|e| e.dn))
}

/// Get a single user by ID.
pub async fn get(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    user_id: &str,
) -> Result<Option<UserResponse>, IdentityProviderError> {
    let Some(entry) = get_entry_by_id(pool, cfg, user_id).await? else {
        return Ok(None);
    };
    let mut user = models::to_user_response(cfg, default_domain_id, &entry)?;
    user.enabled = apply_enabled_emulation(pool, cfg, user.enabled, &entry.dn).await?;
    Ok(Some(user))
}

/// Get a single user by DN. Used by the second step of
/// `authenticate_by_password`, after the bind succeeds against the same DN.
pub async fn get_by_dn(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    dn: &str,
) -> Result<Option<UserResponse>, IdentityProviderError> {
    let filter = format!("(objectClass={})", cfg.user_objectclass);
    let entries = pool.search(dn, Scope::Base, &filter, &ALL_ATTRS).await?;
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let mut user = models::to_user_response(cfg, default_domain_id, entry)?;
    user.enabled = apply_enabled_emulation(pool, cfg, user.enabled, &entry.dn).await?;
    Ok(Some(user))
}

/// List users matching the given parameters.
pub async fn list(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    params: &UserListParameters,
) -> Result<Vec<UserResponse>, IdentityProviderError> {
    let filter = match user_list_filter(cfg, default_domain_id, params) {
        ListDecision::Query(f) => f,
        ListDecision::EmptyResult => return Ok(vec![]),
    };
    let entries = pool
        .paged_search(
            &cfg.user_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &ALL_ATTRS,
        )
        .await?;
    let mut users = Vec::with_capacity(entries.len());
    for entry in &entries {
        let mut user = models::to_user_response(cfg, default_domain_id, entry)?;
        user.enabled = apply_enabled_emulation(pool, cfg, user.enabled, &entry.dn).await?;
        users.push(user);
    }
    Ok(users)
}

/// Find the ID of any user in `domain_id` whose name matches `name`
/// case-insensitively. A non-default domain never matches (ADR-0027 §11).
pub async fn find_by_name_ci(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    domain_id: &str,
    name: &str,
) -> Result<Option<String>, IdentityProviderError> {
    if domain_id != default_domain_id {
        return Ok(None);
    }
    let dn = find_dn_by_attribute(pool, cfg, &cfg.user_name_attribute, name).await?;
    match dn {
        Some(dn) => Ok(Some(
            id_dn::dn_to_id(pool, &cfg.user_id_attribute, &dn).await?,
        )),
        None => Ok(None),
    }
}

/// Cheaply resolve a user reference to the canonical user ID, verifying the
/// account exists and is enabled (ADR-0022 Invariant 8 rate-limiting probe).
pub async fn check_user_exist(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    user_id: Option<&str>,
    name: Option<&str>,
    domain_id: Option<&str>,
) -> Result<String, IdentityProviderError> {
    let dn = if let Some(user_id) = user_id {
        resolve_dn(pool, cfg, Some(user_id), None).await?
    } else {
        let name = name.ok_or(IdentityProviderError::UserIdOrNameWithDomain)?;
        let domain_id = domain_id.ok_or(IdentityProviderError::UserIdOrNameWithDomain)?;
        if domain_id != default_domain_id {
            None
        } else {
            find_dn_by_attribute(pool, cfg, &cfg.user_name_attribute, name).await?
        }
    };
    let dn = dn.ok_or_else(|| {
        IdentityProviderError::UserNotFound(user_id.or(name).unwrap_or_default().to_string())
    })?;
    let user = get_by_dn(pool, cfg, default_domain_id, &dn)
        .await?
        .ok_or_else(|| IdentityProviderError::UserNotFound(dn.clone()))?;
    if !user.enabled {
        return Err(AuthenticationError::UserDisabled(user.id).into());
    }
    Ok(user.id)
}
