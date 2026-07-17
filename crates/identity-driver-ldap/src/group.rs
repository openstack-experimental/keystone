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
//! # LDAP group read and membership operations (ADR-0027 §3, §9)
use ldap3::SearchEntry;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core_types::identity::{Group, GroupListParameters, IdentityProviderError};

use crate::connection::ServicePool;
use crate::filter::{ListDecision, escape_filter_value, group_list_filter};
use crate::id_dn::{self, ldap_scope};
use crate::models;

const ALL_ATTRS: [&str; 1] = ["*"];

/// The `LDAP_MATCHING_RULE_IN_CHAIN` OID used to resolve Active Directory
/// nested group membership in a single query (ADR-0027 §9).
const AD_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

fn member_dns(entry: &SearchEntry, member_attribute: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(member_attribute))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Look up a single group entry by `group_id_attribute` under
/// `group_tree_dn`, scoped by `[ldap] query_scope`, mirroring Python's
/// `_ldap_get` (see `user::get_entry_by_id` for why this never constructs a
/// DN directly).
async fn get_entry_by_id(
    pool: &ServicePool,
    cfg: &LdapProvider,
    group_id: &str,
) -> Result<Option<SearchEntry>, IdentityProviderError> {
    let mut filter = format!(
        "(&({}={})(objectClass={}))",
        cfg.group_id_attribute,
        escape_filter_value(group_id),
        cfg.group_objectclass
    );
    if let Some(extra) = &cfg.group_filter {
        filter = format!("(&{filter}{extra})");
    }
    let entries = pool
        .search(
            &cfg.group_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &ALL_ATTRS,
        )
        .await?;
    Ok(entries.into_iter().next())
}

/// Get a single group by ID.
pub async fn get(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    group_id: &str,
) -> Result<Option<Group>, IdentityProviderError> {
    match get_entry_by_id(pool, cfg, group_id).await? {
        Some(entry) => Ok(Some(models::to_group(cfg, default_domain_id, &entry)?)),
        None => Ok(None),
    }
}

/// List groups matching the given parameters.
pub async fn list(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    params: &GroupListParameters,
) -> Result<Vec<Group>, IdentityProviderError> {
    let filter = match group_list_filter(cfg, default_domain_id, params) {
        ListDecision::Query(f) => f,
        ListDecision::EmptyResult => return Ok(vec![]),
    };
    let entries = pool
        .paged_search(
            &cfg.group_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &ALL_ATTRS,
        )
        .await?;
    entries
        .iter()
        .map(|entry| models::to_group(cfg, default_domain_id, entry))
        .collect()
}

/// Find the ID of any group in `domain_id` whose name matches `name`
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
    let filter = format!(
        "(&(objectClass={})({}={}))",
        cfg.group_objectclass,
        cfg.group_name_attribute,
        escape_filter_value(name)
    );
    let entries = pool
        .search(
            &cfg.group_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &[cfg.group_id_attribute.as_str()],
        )
        .await?;
    match entries.into_iter().next() {
        Some(entry) => Ok(Some(
            id_dn::dn_to_id(pool, &cfg.group_id_attribute, &entry.dn).await?,
        )),
        None => Ok(None),
    }
}

/// List the groups a user is a member of, identified by `member_value` — the
/// user's DN, or its `user_id_attribute` value when `group_members_are_ids`
/// is set (mirrors Python's `list_groups_for_user`, which switches between
/// `user_ref['dn']` and `user_ref['id']` the same way).
///
/// When `group_ad_nesting` is set, uses `LDAP_MATCHING_RULE_IN_CHAIN` to
/// resolve nested Active Directory group membership in a single query.
pub async fn list_groups_of_user_dn(
    pool: &ServicePool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    member_value: &str,
) -> Result<Vec<Group>, IdentityProviderError> {
    let member_clause = if cfg.group_ad_nesting {
        format!(
            "({}:{AD_MATCHING_RULE_IN_CHAIN}:={})",
            cfg.group_member_attribute,
            escape_filter_value(member_value)
        )
    } else {
        format!(
            "({}={})",
            cfg.group_member_attribute,
            escape_filter_value(member_value)
        )
    };
    let filter = format!("(&(objectClass={}){member_clause})", cfg.group_objectclass);
    let entries = pool
        .paged_search(
            &cfg.group_tree_dn,
            ldap_scope(cfg.query_scope),
            &filter,
            &ALL_ATTRS,
        )
        .await?;
    entries
        .iter()
        .map(|entry| models::to_group(cfg, default_domain_id, entry))
        .collect()
}

/// List the user IDs that are members of `group_id`, read directly off the
/// group entry's member attribute.
///
/// When `group_members_are_ids` is set, member values are keystone user IDs
/// already and are returned as-is; otherwise they are member DNs and are
/// resolved to IDs via [`id_dn::dn_to_id`] (mirrors Python's
/// `_transform_group_member_ids`).
pub async fn list_users_of_group(
    pool: &ServicePool,
    cfg: &LdapProvider,
    group_id: &str,
) -> Result<Vec<String>, IdentityProviderError> {
    let Some(entry) = get_entry_by_id(pool, cfg, group_id).await? else {
        return Ok(vec![]);
    };
    let members = member_dns(&entry, &cfg.group_member_attribute);
    if cfg.group_members_are_ids {
        return Ok(members);
    }
    let mut ids = Vec::with_capacity(members.len());
    for member_dn in members {
        ids.push(id_dn::dn_to_id(pool, &cfg.user_id_attribute, &member_dn).await?);
    }
    Ok(ids)
}
