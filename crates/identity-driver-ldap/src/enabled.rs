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
//! # Enabled-attribute emulation (ADR-0027 §7)
//!
//! Mirrors Python's `EnabledEmuMixIn`. Bitmask and invert/default are pure
//! functions of the raw attribute value; group-membership emulation needs a
//! directory round trip and so is a separate, async entry point.
use ldap3::Scope;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core_types::identity::IdentityProviderError;

use crate::connection::ServicePool;
use crate::filter::escape_filter_value;

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "y")
}

/// Determine whether a user/group is enabled from the raw
/// `user_enabled_attribute` value, applying the bitmask and/or invert
/// strategies, falling back to `user_enabled_default` when the attribute is
/// absent.
///
/// Does not perform the group-membership emulation strategy; call
/// [`enabled_via_group_membership`] separately when
/// `user_enabled_emulation` is set.
///
/// Mirrors Python's `UserApi._ldap_res_to_model`:
/// `enabled = (raw_value & mask) != mask` when `user_enabled_mask` is set —
/// i.e. the account is enabled unless *all* masked bits are set (the
/// Active Directory `userAccountControl` convention, where bit `2` marks
/// `ACCOUNTDISABLE`) — and this ignores `user_enabled_invert` entirely, as
/// documented on `[ldap] user_enabled_mask`.
pub fn enabled_from_attribute(cfg: &LdapProvider, raw_value: Option<&str>) -> bool {
    if let Some(mask) = cfg.user_enabled_mask {
        let value: i32 = raw_value
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| cfg.user_enabled_default.parse().unwrap_or(0));
        return (value & mask) != mask;
    }
    match raw_value {
        Some(v) => {
            let t = truthy(v);
            if cfg.user_enabled_invert { !t } else { t }
        }
        None => truthy(&cfg.user_enabled_default),
    }
}

/// Determine whether `user_dn` is enabled via membership in the
/// enabled-emulation group (`user_enabled_emulation_dn`).
///
/// A BASE-scoped search on the emulation group's DN, filtered by whether
/// its member attribute contains `user_dn`, returns the entry if the user
/// is a member and nothing otherwise.
pub async fn enabled_via_group_membership(
    pool: &ServicePool,
    group_dn: &str,
    member_attribute: &str,
    user_dn: &str,
) -> Result<bool, IdentityProviderError> {
    let filter = format!("({member_attribute}={})", escape_filter_value(user_dn));
    let entries = pool
        .search(group_dn, Scope::Base, &filter, &["objectClass"])
        .await?;
    Ok(!entries.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LdapProvider {
        LdapProvider::default()
    }

    #[test]
    fn test_default_when_attribute_absent() {
        let mut c = cfg();
        c.user_enabled_default = "True".into();
        assert!(enabled_from_attribute(&c, None));
        c.user_enabled_default = "False".into();
        assert!(!enabled_from_attribute(&c, None));
    }

    #[test]
    fn test_truthy_string_values() {
        let c = cfg();
        assert!(enabled_from_attribute(&c, Some("true")));
        assert!(enabled_from_attribute(&c, Some("TRUE")));
        assert!(enabled_from_attribute(&c, Some("1")));
        assert!(!enabled_from_attribute(&c, Some("false")));
        assert!(!enabled_from_attribute(&c, Some("0")));
    }

    #[test]
    fn test_invert_flips_string_interpretation() {
        let mut c = cfg();
        c.user_enabled_invert = true;
        assert!(!enabled_from_attribute(&c, Some("true")));
        assert!(enabled_from_attribute(&c, Some("false")));
    }

    /// `mask = 2` mirrors Active Directory's `userAccountControl` bit 2
    /// (`ACCOUNTDISABLE`): enabled unless that bit is set, i.e.
    /// `(value & mask) != mask` — not `!= 0`.
    #[test]
    fn test_bitmask_strategy() {
        let mut c = cfg();
        c.user_enabled_mask = Some(2);
        assert!(!enabled_from_attribute(&c, Some("2")));
        assert!(!enabled_from_attribute(&c, Some("3")));
        assert!(enabled_from_attribute(&c, Some("1")));
    }

    /// The attribute-absent fallback uses `user_enabled_default` parsed as
    /// an integer (e.g. AD's typical `512` "normal account" value), not a
    /// hardcoded `0`.
    #[test]
    fn test_bitmask_strategy_falls_back_to_enabled_default_when_absent() {
        let mut c = cfg();
        c.user_enabled_mask = Some(2);
        c.user_enabled_default = "512".into();
        assert!(enabled_from_attribute(&c, None));
        c.user_enabled_default = "2".into();
        assert!(!enabled_from_attribute(&c, None));
    }

    /// `user_enabled_invert` has no effect once `user_enabled_mask` is set
    /// (documented on the config option, matches Python).
    #[test]
    fn test_bitmask_strategy_ignores_invert() {
        let mut c = cfg();
        c.user_enabled_mask = Some(2);
        c.user_enabled_invert = true;
        assert!(!enabled_from_attribute(&c, Some("2")));
        assert!(enabled_from_attribute(&c, Some("1")));
    }
}
