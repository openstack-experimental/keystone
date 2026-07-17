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
//! # Query scope and DN-to-ID mapping (ADR-0027 §4)
//!
//! Python's `_id_to_dn` (constructing a DN directly from an ID, without a
//! directory round trip) is only ever used on the LDAP *write* path
//! (`create`/`update`/`delete`, via `_ldap_add`/`_ldap_delete`); every read
//! path (`get`, `get_by_name`, `get_all`) instead runs a single filtered
//! search under `tree_dn`, scoped by `[ldap] query_scope`, and reads the
//! resulting entry's real DN off the search result. Since this backend is
//! permanently read-only, there is no DN-construction path to reproduce here
//! — only [`ldap_scope`], mapping `query_scope` to the ldap3 [`Scope`] used
//! by every read search, and [`dn_to_id`], mirroring `_dn_to_id` for turning
//! a group's raw member DN back into a user ID.
use ldap3::Scope;

use openstack_keystone_config::QueryScope;
use openstack_keystone_core_types::identity::IdentityProviderError;

use crate::connection::ServicePool;

/// Map `[ldap] query_scope` to the ldap3 search scope used for every read
/// operation (`get`, `get_by_name`, `get_all`) — mirrors Python's
/// `LDAP_SCOPES = {'one': ldap.SCOPE_ONELEVEL, 'sub': ldap.SCOPE_SUBTREE}`.
pub fn ldap_scope(query_scope: QueryScope) -> Scope {
    match query_scope {
        QueryScope::One => Scope::OneLevel,
        QueryScope::Sub => Scope::Subtree,
    }
}

/// Extract the value of `id_attribute` from `dn`'s leading RDN, if the RDN's
/// attribute name matches (case-insensitively).
fn rdn_value_if_attribute(dn: &str, id_attribute: &str) -> Option<String> {
    let rdn = dn.split(',').next()?;
    let (attr, value) = rdn.split_once('=')?;
    if attr.trim().eq_ignore_ascii_case(id_attribute) {
        Some(value.trim().to_string())
    } else {
        None
    }
}

/// Resolve `dn` to the value of `id_attribute` on that entry.
///
/// If `id_attribute` matches the DN's leading RDN attribute, the value is
/// parsed out of the DN directly with no directory round trip. Otherwise a
/// BASE-scoped search reads the attribute off the entry (mirrors Python's
/// `_dn_to_id`, which always uses `SCOPE_BASE` for this fallback regardless
/// of `query_scope`).
pub async fn dn_to_id(
    pool: &ServicePool,
    id_attribute: &str,
    dn: &str,
) -> Result<String, IdentityProviderError> {
    if let Some(value) = rdn_value_if_attribute(dn, id_attribute) {
        return Ok(value);
    }
    let entries = pool
        .search(dn, Scope::Base, "(objectClass=*)", &[id_attribute])
        .await?;
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| IdentityProviderError::Driver(format!("no LDAP entry found at dn {dn}")))?;
    entry
        .attrs
        .get(id_attribute)
        .and_then(|values| values.first())
        .cloned()
        .ok_or_else(|| {
            IdentityProviderError::Driver(format!("attribute {id_attribute} missing on dn {dn}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_scope_one_is_onelevel() {
        assert_eq!(ldap_scope(QueryScope::One), Scope::OneLevel);
    }

    #[test]
    fn test_ldap_scope_sub_is_subtree() {
        assert_eq!(ldap_scope(QueryScope::Sub), Scope::Subtree);
    }

    #[test]
    fn test_rdn_value_if_attribute_matches() {
        assert_eq!(
            rdn_value_if_attribute("cn=jdoe,ou=Users,dc=example,dc=com", "cn"),
            Some("jdoe".to_string())
        );
        assert_eq!(
            rdn_value_if_attribute("CN=jdoe,ou=Users,dc=example,dc=com", "cn"),
            Some("jdoe".to_string())
        );
    }

    #[test]
    fn test_rdn_value_if_attribute_mismatch() {
        assert_eq!(
            rdn_value_if_attribute("uid=jdoe,ou=Users,dc=example,dc=com", "cn"),
            None
        );
    }
}
