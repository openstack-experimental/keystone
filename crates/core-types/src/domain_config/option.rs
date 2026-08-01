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

//! # Domain configuration groups, options and values

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::DomainConfigProviderError;

/// Name of a domain-configurable option group.
///
/// Only the two groups that influence the per-domain identity backend are
/// configurable, matching the keys of python-keystone's
/// `DomainConfigManager.whitelisted_options`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainConfigGroupName {
    /// The `[identity]` group: which identity driver the domain uses.
    Identity,
    /// The `[ldap]` group: how that domain's LDAP directory is reached.
    Ldap,
}

impl DomainConfigGroupName {
    /// Every configurable group, in a stable order.
    pub const ALL: &'static [Self] = &[Self::Identity, Self::Ldap];

    /// Wire name of the group.
    ///
    /// # Returns
    /// - `&'static str` - The group name as it appears in the API and in the
    ///   persistence layer.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Ldap => "ldap",
        }
    }
}

impl fmt::Display for DomainConfigGroupName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DomainConfigGroupName {
    type Err = DomainConfigProviderError;

    /// Parse a group name coming from the API path or from storage.
    ///
    /// # Parameters
    /// - `s`: The group name.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The parsed group, or
    ///   [`DomainConfigProviderError::UnsupportedGroup`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identity" => Ok(Self::Identity),
            "ldap" => Ok(Self::Ldap),
            other => Err(DomainConfigProviderError::UnsupportedGroup(
                other.to_string(),
            )),
        }
    }
}

/// Whitelisted (readable) options of the `identity` group.
pub const IDENTITY_WHITELISTED_OPTIONS: &[&str] = &["driver", "list_limit"];

/// Sensitive (write-only) options of the `identity` group.
pub const IDENTITY_SENSITIVE_OPTIONS: &[&str] = &[];

/// Whitelisted (readable) options of the `ldap` group.
///
/// Transcribed verbatim from python-keystone's
/// `DomainConfigManager.whitelisted_options['ldap']`. As the upstream comment
/// stresses, the list is explicit rather than derived from the `[ldap]` config
/// section: a newly added `[ldap]` option must never become domain-writable by
/// accident.
pub const LDAP_WHITELISTED_OPTIONS: &[&str] = &[
    "url",
    "user",
    "suffix",
    "query_scope",
    "page_size",
    "alias_dereferencing",
    "debug_level",
    "chase_referrals",
    "user_tree_dn",
    "user_filter",
    "user_objectclass",
    "user_id_attribute",
    "user_name_attribute",
    "user_mail_attribute",
    "user_description_attribute",
    "user_pass_attribute",
    "user_enabled_attribute",
    "user_enabled_invert",
    "user_enabled_mask",
    "user_enabled_default",
    "user_attribute_ignore",
    "user_default_project_id_attribute",
    "user_enabled_emulation",
    "user_enabled_emulation_dn",
    "user_enabled_emulation_use_group_config",
    "user_additional_attribute_mapping",
    "group_tree_dn",
    "group_filter",
    "group_objectclass",
    "group_id_attribute",
    "group_name_attribute",
    "group_members_are_ids",
    "group_member_attribute",
    "group_desc_attribute",
    "group_attribute_ignore",
    "group_additional_attribute_mapping",
    "tls_cacertfile",
    "tls_cacertdir",
    "use_tls",
    "tls_req_cert",
    "use_pool",
    "pool_size",
    "pool_retry_max",
    "pool_retry_delay",
    "pool_connection_timeout",
    "pool_connection_lifetime",
    "use_auth_pool",
    "auth_pool_size",
    "auth_pool_connection_lifetime",
];

/// Sensitive (write-only) options of the `ldap` group.
///
/// Sensitive options can be written through the API but are never returned by
/// it, and are expected to live in separate storage from the whitelisted ones.
pub const LDAP_SENSITIVE_OPTIONS: &[&str] = &["password"];

/// Whitelisted (readable) options of a group.
///
/// # Parameters
/// - `group`: The group to look up.
///
/// # Returns
/// - `&'static [&'static str]` - The readable option names of that group.
pub const fn whitelisted_options(group: DomainConfigGroupName) -> &'static [&'static str] {
    match group {
        DomainConfigGroupName::Identity => IDENTITY_WHITELISTED_OPTIONS,
        DomainConfigGroupName::Ldap => LDAP_WHITELISTED_OPTIONS,
    }
}

/// Sensitive (write-only) options of a group.
///
/// # Parameters
/// - `group`: The group to look up.
///
/// # Returns
/// - `&'static [&'static str]` - The sensitive option names of that group.
pub const fn sensitive_options(group: DomainConfigGroupName) -> &'static [&'static str] {
    match group {
        DomainConfigGroupName::Identity => IDENTITY_SENSITIVE_OPTIONS,
        DomainConfigGroupName::Ldap => LDAP_SENSITIVE_OPTIONS,
    }
}

/// Whether the option is readable through the API.
///
/// # Parameters
/// - `group`: The group the option belongs to.
/// - `option`: The option name.
///
/// # Returns
/// - `bool` - `true` when the option is whitelisted.
pub fn is_whitelisted(group: DomainConfigGroupName, option: &str) -> bool {
    whitelisted_options(group).contains(&option)
}

/// Whether the option holds a secret and must never be returned.
///
/// # Parameters
/// - `group`: The group the option belongs to.
/// - `option`: The option name.
///
/// # Returns
/// - `bool` - `true` when the option is sensitive.
pub fn is_sensitive(group: DomainConfigGroupName, option: &str) -> bool {
    sensitive_options(group).contains(&option)
}

/// Whether the option may be stored at all (whitelisted or sensitive).
///
/// # Parameters
/// - `group`: The group the option belongs to.
/// - `option`: The option name.
///
/// # Returns
/// - `bool` - `true` when the option is supported.
pub fn is_supported(group: DomainConfigGroupName, option: &str) -> bool {
    is_whitelisted(group, option) || is_sensitive(group, option)
}

/// Validate a group/option pair addressed by a request.
///
/// Port of python-keystone's
/// `DomainConfigManager._assert_valid_group_and_option`, including the case
/// where neither is given (the request addresses the whole configuration).
///
/// # Parameters
/// - `group`: The group named in the request path, if any.
/// - `option`: The option named in the request path, if any.
///
/// # Returns
/// - `Result<Option<DomainConfigGroupName>, DomainConfigProviderError>` - The
///   parsed group when one was given, `None` when the request addresses every
///   group, or an error when the pair is not supported.
pub fn assert_valid_group_and_option(
    group: Option<&str>,
    option: Option<&str>,
) -> Result<Option<DomainConfigGroupName>, DomainConfigProviderError> {
    let Some(group) = group else {
        return match option {
            // The API routing should make this unreachable.
            Some(option) => Err(DomainConfigProviderError::OptionWithoutGroup(
                option.to_string(),
            )),
            None => Ok(None),
        };
    };

    let group = DomainConfigGroupName::from_str(group)?;
    if let Some(option) = option
        && !is_supported(group, option)
    {
        return Err(DomainConfigProviderError::UnsupportedOption {
            group: group.to_string(),
            option: option.to_string(),
        });
    }
    Ok(Some(group))
}

/// A single domain configuration option value.
///
/// Values round-trip verbatim as JSON, matching the `JsonBlob` columns
/// python-keystone stores them in: whatever type the client wrote is what a
/// later read returns.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DomainConfigValue(Value);

impl DomainConfigValue {
    /// Wrap a JSON value.
    ///
    /// # Parameters
    /// - `value`: The value to wrap.
    ///
    /// # Returns
    /// - `Self` - The wrapped value.
    pub fn new<V: Into<Value>>(value: V) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying JSON value.
    ///
    /// # Returns
    /// - `&Value` - The wrapped value.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consume the wrapper and yield the JSON value.
    ///
    /// # Returns
    /// - `Value` - The wrapped value.
    pub fn into_value(self) -> Value {
        self.0
    }

    /// Borrow the value as a string, when it is one.
    ///
    /// # Returns
    /// - `Option<&str>` - The string, or `None` for any other JSON type.
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_str()
    }
}

impl From<Value> for DomainConfigValue {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl From<DomainConfigValue> for Value {
    fn from(value: DomainConfigValue) -> Self {
        value.0
    }
}

impl From<&str> for DomainConfigValue {
    fn from(value: &str) -> Self {
        Self(Value::from(value))
    }
}

impl From<String> for DomainConfigValue {
    fn from(value: String) -> Self {
        Self(Value::from(value))
    }
}

impl fmt::Display for DomainConfigValue {
    /// Render the value the way a config consumer expects it: strings bare
    /// (so `%(password)s` substitution does not inject JSON quotes), anything
    /// else as compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.as_str() {
            Some(value) => f.write_str(value),
            None => write!(f, "{}", self.0),
        }
    }
}

/// A single stored configuration option.
///
/// This is the flat shape the persistence layer works with, mirroring
/// python-keystone's option dicts (`{group, option, value, sensitive}`) and
/// the `(domain_id, group, option, value)` primary key of its
/// `whitelisted_config` / `sensitive_config` tables.
#[derive(Clone, PartialEq)]
pub struct DomainConfigOption {
    /// The group the option belongs to.
    pub group: DomainConfigGroupName,
    /// The option name.
    pub option: String,
    /// The option value.
    pub value: DomainConfigValue,
    /// Whether the value is a secret and therefore belongs in the sensitive
    /// storage and must never be returned by the API.
    ///
    /// Private, and derived from the option name by [`Self::new`], so that it
    /// cannot disagree with [`is_sensitive`]: a driver routes an option to the
    /// readable or the sensitive table by this flag, while every read path
    /// decides by name. An option built with the flag cleared would put a bind
    /// password in the table the readable endpoints query.
    sensitive: bool,
}

impl DomainConfigOption {
    /// Build an option, deriving its sensitivity from the option name.
    ///
    /// # Parameters
    /// - `group`: The group the option belongs to.
    /// - `option`: The option name.
    /// - `value`: The option value.
    ///
    /// # Returns
    /// - `Self` - The option with [`Self::sensitive`] set from
    ///   [`is_sensitive`].
    pub fn new<O: Into<String>, V: Into<DomainConfigValue>>(
        group: DomainConfigGroupName,
        option: O,
        value: V,
    ) -> Self {
        let option = option.into();
        let sensitive = is_sensitive(group, &option);
        Self {
            group,
            option,
            value: value.into(),
            sensitive,
        }
    }

    /// Whether the value is a secret.
    ///
    /// # Returns
    /// - `bool` - `true` when the option belongs in the sensitive storage and
    ///   must never be returned by the API.
    pub fn sensitive(&self) -> bool {
        self.sensitive
    }
}

impl fmt::Debug for DomainConfigOption {
    /// Redact the value of sensitive options so they cannot reach logs or
    /// traces through a `{:?}` of the surrounding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("DomainConfigOption");
        out.field("group", &self.group)
            .field("option", &self.option);
        if self.sensitive {
            out.field("value", &"REDACTED");
        } else {
            out.field("value", &self.value);
        }
        out.field("sensitive", &self.sensitive).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_name_round_trips() {
        for group in DomainConfigGroupName::ALL {
            assert_eq!(
                *group,
                DomainConfigGroupName::from_str(group.as_str()).unwrap()
            );
        }
    }

    #[test]
    fn unknown_group_is_rejected() {
        let err = DomainConfigGroupName::from_str("assignment").unwrap_err();
        assert_eq!(
            err.to_string(),
            "group assignment is not supported for domain specific configurations"
        );
    }

    #[test]
    fn whitelist_matches_python_keystone() {
        // The counts are asserted so that an accidental edit of the list is
        // visible in the diff of a failing test, not just in the constant.
        assert_eq!(IDENTITY_WHITELISTED_OPTIONS.len(), 2);
        assert_eq!(LDAP_WHITELISTED_OPTIONS.len(), 49);
        assert!(IDENTITY_SENSITIVE_OPTIONS.is_empty());
        assert_eq!(LDAP_SENSITIVE_OPTIONS, &["password"]);

        // `password` is sensitive, therefore deliberately absent from the
        // readable list.
        assert!(!LDAP_WHITELISTED_OPTIONS.contains(&"password"));
        assert!(is_sensitive(DomainConfigGroupName::Ldap, "password"));
        assert!(!is_whitelisted(DomainConfigGroupName::Ldap, "password"));
        assert!(is_supported(DomainConfigGroupName::Ldap, "password"));
    }

    #[test]
    fn whitelist_has_no_duplicates() {
        for group in DomainConfigGroupName::ALL {
            let options = whitelisted_options(*group);
            let unique: std::collections::HashSet<_> = options.iter().collect();
            assert_eq!(unique.len(), options.len(), "duplicate option in {group}");
        }
    }

    #[test]
    fn assert_valid_group_and_option_accepts_the_whole_config() {
        assert_eq!(assert_valid_group_and_option(None, None).unwrap(), None);
    }

    #[test]
    fn assert_valid_group_and_option_accepts_supported_pairs() {
        assert_eq!(
            assert_valid_group_and_option(Some("ldap"), Some("url")).unwrap(),
            Some(DomainConfigGroupName::Ldap)
        );
        assert_eq!(
            assert_valid_group_and_option(Some("identity"), None).unwrap(),
            Some(DomainConfigGroupName::Identity)
        );
        // Sensitive options are addressable for writes.
        assert_eq!(
            assert_valid_group_and_option(Some("ldap"), Some("password")).unwrap(),
            Some(DomainConfigGroupName::Ldap)
        );
    }

    #[test]
    fn assert_valid_group_and_option_rejects_unknown_option() {
        let err = assert_valid_group_and_option(Some("ldap"), Some("bind_dn")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "option bind_dn in group ldap is not supported for domain specific configurations"
        );
    }

    #[test]
    fn assert_valid_group_and_option_rejects_option_without_group() {
        let err = assert_valid_group_and_option(None, Some("url")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "option url found with no group specified while checking domain configuration request"
        );
    }

    #[test]
    fn assert_valid_group_and_option_rejects_cross_group_option() {
        // `driver` belongs to `identity`, not to `ldap`.
        assert!(assert_valid_group_and_option(Some("ldap"), Some("driver")).is_err());
        assert!(assert_valid_group_and_option(Some("identity"), Some("url")).is_err());
    }

    #[test]
    fn value_display_leaves_strings_bare() {
        assert_eq!(
            DomainConfigValue::from("ldap://host").to_string(),
            "ldap://host"
        );
        assert_eq!(DomainConfigValue::new(10).to_string(), "10");
        assert_eq!(DomainConfigValue::new(true).to_string(), "true");
    }

    #[test]
    fn option_debug_redacts_sensitive_values() {
        let option = DomainConfigOption::new(DomainConfigGroupName::Ldap, "password", "s3cr3t");
        assert!(option.sensitive());
        let rendered = format!("{option:?}");
        assert!(!rendered.contains("s3cr3t"), "Debug leaked the password");
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn option_debug_keeps_non_sensitive_values() {
        let option = DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", "ldap://host");
        assert!(!option.sensitive());
        assert!(format!("{option:?}").contains("ldap://host"));
    }
}
