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
//! # LDAP entry to core-types conversion (ADR-0027 §6)
use std::collections::HashMap;

use ldap3::SearchEntry;
use serde_json::Value;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core_types::identity::{
    Group, IdentityProviderError, UserOptions, UserResponse,
};

use crate::enabled::enabled_from_attribute;

/// Attributes that must never be surfaced under `extra`, even if an
/// operator misconfigures the additional-attribute mapping to include them
/// (ADR-0027 §6 point 5).
const NEVER_EXPOSED_ATTRIBUTES: &[&str] = &["dn", "userpassword", "unicodepwd", "password"];

/// Case-insensitive view over an entry's attributes (Python's
/// `_ldap_res_to_model` lowercases attribute names before matching
/// `attribute_mapping`).
fn lowercase_attrs(attrs: &HashMap<String, Vec<String>>) -> HashMap<String, &Vec<String>> {
    attrs
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect()
}

fn single_value(lower_attrs: &HashMap<String, &Vec<String>>, attribute: &str) -> Option<String> {
    lower_attrs
        .get(&attribute.to_ascii_lowercase())
        .and_then(|values| values.first())
        .cloned()
}

fn build_extra(
    lower_attrs: &HashMap<String, &Vec<String>>,
    mapping: &HashMap<String, String>,
    extra_disallowed: &str,
) -> HashMap<String, Value> {
    let extra_disallowed = extra_disallowed.to_ascii_lowercase();
    let mut extra = HashMap::new();
    for (ldap_attr, extra_key) in mapping {
        let ldap_attr_lower = ldap_attr.to_ascii_lowercase();
        if NEVER_EXPOSED_ATTRIBUTES.contains(&ldap_attr_lower.as_str())
            || NEVER_EXPOSED_ATTRIBUTES.contains(&extra_key.to_ascii_lowercase().as_str())
            || ldap_attr_lower == extra_disallowed
        {
            continue;
        }
        if let Some(values) = lower_attrs.get(&ldap_attr.to_ascii_lowercase()) {
            let value = if values.len() > 1 {
                Value::Array(values.iter().map(|v| Value::String(v.clone())).collect())
            } else {
                match values.first() {
                    Some(v) => Value::String(v.clone()),
                    None => continue,
                }
            };
            extra.insert(extra_key.clone(), value);
        }
    }
    extra
}

/// Convert an LDAP user entry into a [`UserResponse`].
///
/// `domain_id` is always the configured `default_domain_id`: LDAP is not
/// domain-aware (ADR-0027 §11). `id` falls back to the entry's DN when
/// `user_id_attribute` is absent or multi-valued.
pub fn to_user_response(
    cfg: &LdapProvider,
    default_domain_id: &str,
    entry: &SearchEntry,
) -> Result<UserResponse, IdentityProviderError> {
    let lower_attrs = lowercase_attrs(&entry.attrs);

    let id = match lower_attrs.get(&cfg.user_id_attribute.to_ascii_lowercase()) {
        Some(values) if values.len() == 1 => values[0].clone(),
        _ => {
            tracing::warn!(
                dn = %entry.dn,
                attribute = %cfg.user_id_attribute,
                "user_id_attribute missing or multi-valued; falling back to DN as user id"
            );
            entry.dn.clone()
        }
    };
    let name = single_value(&lower_attrs, &cfg.user_name_attribute).unwrap_or_else(|| id.clone());
    let enabled_raw = single_value(&lower_attrs, &cfg.user_enabled_attribute);
    let enabled = enabled_from_attribute(cfg, enabled_raw.as_deref());
    let extra = build_extra(
        &lower_attrs,
        &cfg.user_additional_attribute_mapping,
        &cfg.user_pass_attribute,
    );

    Ok(UserResponse {
        default_project_id: None,
        domain_id: default_domain_id.to_string(),
        enabled,
        extra,
        federated: None,
        id,
        name,
        options: UserOptions::default(),
        password_expires_at: None,
    })
}

/// Convert an LDAP group entry into a [`Group`].
///
/// `domain_id` is always the configured `default_domain_id`. `id` falls back
/// to the entry's DN when `group_id_attribute` is absent or multi-valued.
pub fn to_group(
    cfg: &LdapProvider,
    default_domain_id: &str,
    entry: &SearchEntry,
) -> Result<Group, IdentityProviderError> {
    let lower_attrs = lowercase_attrs(&entry.attrs);

    let id = match lower_attrs.get(&cfg.group_id_attribute.to_ascii_lowercase()) {
        Some(values) if values.len() == 1 => values[0].clone(),
        _ => {
            tracing::warn!(
                dn = %entry.dn,
                attribute = %cfg.group_id_attribute,
                "group_id_attribute missing or multi-valued; falling back to DN as group id"
            );
            entry.dn.clone()
        }
    };
    let name = single_value(&lower_attrs, &cfg.group_name_attribute).unwrap_or_else(|| id.clone());
    let description = single_value(&lower_attrs, &cfg.group_desc_attribute);
    let extra = build_extra(&lower_attrs, &cfg.group_additional_attribute_mapping, "");

    Ok(Group {
        description,
        domain_id: default_domain_id.to_string(),
        extra,
        id,
        name,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> SearchEntry {
        let mut map = HashMap::new();
        for (k, values) in attrs {
            map.insert(
                k.to_string(),
                values.iter().map(|v| v.to_string()).collect(),
            );
        }
        SearchEntry {
            dn: dn.to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        }
    }

    #[test]
    fn test_to_user_response_basic_mapping() {
        let cfg = LdapProvider::default();
        let e = entry(
            "cn=jdoe,ou=Users,dc=example,dc=com",
            &[("cn", &["jdoe"]), ("sn", &["Doe"]), ("enabled", &["TRUE"])],
        );
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert_eq!(user.id, "jdoe");
        assert_eq!(user.name, "Doe");
        assert_eq!(user.domain_id, "default");
        assert!(user.enabled);
    }

    #[test]
    fn test_to_user_response_case_insensitive_attribute_matching() {
        let cfg = LdapProvider::default();
        let e = entry(
            "cn=jdoe,ou=Users,dc=example,dc=com",
            &[("CN", &["jdoe"]), ("SN", &["Doe"])],
        );
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert_eq!(user.id, "jdoe");
        assert_eq!(user.name, "Doe");
    }

    #[test]
    fn test_to_user_response_falls_back_to_dn_when_id_attribute_missing() {
        let cfg = LdapProvider::default();
        let e = entry("cn=jdoe,ou=Users,dc=example,dc=com", &[("sn", &["Doe"])]);
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert_eq!(user.id, "cn=jdoe,ou=Users,dc=example,dc=com");
    }

    #[test]
    fn test_to_user_response_falls_back_to_dn_when_id_attribute_multivalued() {
        let cfg = LdapProvider::default();
        let e = entry(
            "cn=jdoe,ou=Users,dc=example,dc=com",
            &[("cn", &["jdoe", "john"])],
        );
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert_eq!(user.id, "cn=jdoe,ou=Users,dc=example,dc=com");
    }

    #[test]
    fn test_to_user_response_additional_attribute_mapping() {
        let mut cfg = LdapProvider::default();
        cfg.user_additional_attribute_mapping
            .insert("mail".into(), "email".into());
        let e = entry(
            "cn=jdoe,ou=Users,dc=example,dc=com",
            &[("cn", &["jdoe"]), ("mail", &["jdoe@example.com"])],
        );
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert_eq!(
            user.extra.get("email"),
            Some(&Value::String("jdoe@example.com".into()))
        );
    }

    #[test]
    fn test_to_user_response_never_exposes_dn_or_password_even_if_mapped() {
        let mut cfg = LdapProvider::default();
        cfg.user_additional_attribute_mapping
            .insert("userpassword".into(), "password".into());
        cfg.user_additional_attribute_mapping
            .insert("dn".into(), "distinguished_name".into());
        let e = entry(
            "cn=jdoe,ou=Users,dc=example,dc=com",
            &[("cn", &["jdoe"]), ("userpassword", &["{SSHA}notarealhash"])],
        );
        let user = to_user_response(&cfg, "default", &e).unwrap();
        assert!(!user.extra.contains_key("password"));
        assert!(!user.extra.contains_key("distinguished_name"));
    }

    #[test]
    fn test_to_group_basic_mapping() {
        let cfg = LdapProvider::default();
        let e = entry(
            "cn=admins,ou=Groups,dc=example,dc=com",
            &[
                ("cn", &["admins"]),
                ("ou", &["Admins"]),
                ("description", &["Admin group"]),
            ],
        );
        let group = to_group(&cfg, "default", &e).unwrap();
        assert_eq!(group.id, "admins");
        assert_eq!(group.name, "Admins");
        assert_eq!(group.domain_id, "default");
        assert_eq!(group.description, Some("Admin group".to_string()));
    }
}
