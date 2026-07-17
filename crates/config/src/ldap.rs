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
//! # LDAP identity backend configuration (ADR-0027)
//!
//! Maps 1:1 with Python Keystone's `[ldap]` config section (`conf.ldap.*`) so
//! a config file written for Python Keystone works unmodified here.
use std::collections::{HashMap, HashSet};

use secrecy::SecretString;
use serde::Deserialize;

/// LDAP identity backend configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct LdapProvider {
    // --- Connection ---
    /// LDAP server URL.
    #[serde(default = "default_url")]
    pub url: String,
    /// Service bind DN used for all directory queries.
    pub user: Option<String>,
    /// Service bind password.
    pub password: Option<SecretString>,
    /// Enable TLS for the connection.
    #[serde(default)]
    pub use_tls: bool,
    /// Path to a CA certificate file used to validate the LDAP server.
    ///
    /// Parsed for config-file compatibility with Python Keystone, but not
    /// currently applied: TLS verification uses the platform/`rustls`
    /// default trust store regardless of this setting (tracked as a
    /// follow-up; see ADR-0027 implementation notes). Set
    /// `tls_req_cert = never` for a self-signed test directory in the
    /// meantime, or install the CA into the system trust store.
    pub tls_cacertfile: Option<String>,
    /// Path to a directory of CA certificates used to validate the LDAP
    /// server. Same not-yet-applied caveat as `tls_cacertfile`.
    pub tls_cacertdir: Option<String>,
    /// Certificate validation strictness for TLS connections.
    #[serde(default)]
    pub tls_req_cert: TlsReqCert,
    /// Connection timeout, in seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: f64,
    /// Randomize the order in which multiple LDAP URLs are tried.
    #[serde(default)]
    pub randomize_urls: bool,
    /// Enable the service connection pool.
    #[serde(default = "default_true_bool")]
    pub pool: bool,
    /// Service connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: i32,
    /// Maximum number of connection retries for the service pool.
    #[serde(default = "default_pool_retry_max")]
    pub pool_retry_max: i32,
    /// Delay, in seconds, between service pool connection retries.
    #[serde(default = "default_pool_retry_delay")]
    pub pool_retry_delay: f64,
    /// Service pool connection acquisition timeout, in seconds.
    #[serde(default = "default_pool_connection_timeout")]
    pub pool_connection_timeout: f64,
    /// Maximum lifetime of a pooled service connection, in seconds.
    #[serde(default = "default_pool_connection_lifetime")]
    pub pool_connection_lifetime: f64,
    /// Enable the dedicated authentication connection pool, isolating
    /// end-user bind storms from the service query pool.
    #[serde(default = "default_true_bool")]
    pub auth_pool: bool,
    /// Authentication connection pool size.
    #[serde(default = "default_auth_pool_size")]
    pub auth_pool_size: i32,
    /// Maximum lifetime of a pooled authentication connection, in seconds.
    #[serde(default = "default_auth_pool_connection_lifetime")]
    pub auth_pool_connection_lifetime: f64,

    // --- Query ---
    /// Default search scope for subtree operations.
    #[serde(default)]
    pub query_scope: QueryScope,
    /// Number of entries requested per page (RFC 2696).
    #[serde(default = "default_page_size")]
    pub page_size: i32,
    /// Alias dereferencing policy applied to searches.
    #[serde(default)]
    pub alias_dereferencing: AliasDereferencing,
    /// Chase LDAP referrals.
    #[serde(default)]
    pub chase_referrals: Option<bool>,
    /// LDAP client library debug level.
    #[serde(default)]
    pub debug_level: i32,

    // --- User mapping ---
    /// Base DN for user entries.
    #[serde(default)]
    pub user_tree_dn: String,
    /// LDAP `objectClass` identifying user entries.
    #[serde(default = "default_user_objectclass")]
    pub user_objectclass: String,
    /// Attribute used as the public user ID.
    #[serde(default = "default_user_id_attribute")]
    pub user_id_attribute: String,
    /// Attribute used as the user name.
    #[serde(default = "default_user_name_attribute")]
    pub user_name_attribute: String,
    /// Attribute used as the user's mail address.
    #[serde(default = "default_user_mail_attribute")]
    pub user_mail_attribute: String,
    /// Attribute used as the user's description.
    #[serde(default = "default_user_description_attribute")]
    pub user_description_attribute: String,
    /// Attribute used as the user's password (read-only backend: only used
    /// to keep the attribute out of `extra` regardless of the
    /// `user_additional_attribute_mapping` configuration).
    #[serde(default = "default_user_pass_attribute")]
    pub user_pass_attribute: String,
    /// Attribute mapped to a user's `default_project_id`. Unused by this
    /// read-only backend (Python only consults it on write), kept for config
    /// parity.
    pub user_default_project_id_attribute: Option<String>,
    /// Attribute used to determine whether a user is enabled.
    #[serde(default = "default_user_enabled_attribute")]
    pub user_enabled_attribute: String,
    /// Bitmask applied to `user_enabled_attribute` to determine enabled
    /// state, when the attribute stores a bitmask rather than a boolean
    /// (e.g. Active Directory's `userAccountControl`). Ignores
    /// `user_enabled_invert` when set, matching Python Keystone.
    pub user_enabled_mask: Option<i32>,
    /// Invert the interpretation of `user_enabled_attribute`. Has no effect
    /// when `user_enabled_mask` or `user_enabled_emulation` is in use.
    #[serde(default)]
    pub user_enabled_invert: bool,
    /// Enabled state to assume when `user_enabled_attribute` is absent.
    /// A free-form string (matching Python's `StrOpt`) since it doubles as
    /// a boolean literal (`"True"`/`"False"`) in the plain-boolean case and
    /// as an integer literal (e.g. `"512"`) in the `user_enabled_mask` case.
    #[serde(default = "default_user_enabled_default")]
    pub user_enabled_default: String,
    /// Extra LDAP attributes exposed under `extra` in the API response,
    /// mapped as `ldap_attribute -> extra_key`.
    #[serde(default)]
    pub user_additional_attribute_mapping: HashMap<String, String>,
    /// Additional LDAP filter clause AND-ed into every user search.
    pub user_filter: Option<String>,
    /// Attributes never surfaced as `extra`, even if mapped.
    #[serde(default = "default_user_attribute_ignore")]
    pub user_attribute_ignore: HashSet<String>,
    /// Emulate the enabled attribute via group membership.
    #[serde(default)]
    pub user_enabled_emulation: bool,
    /// DN of the group used for enabled-emulation membership checks.
    pub user_enabled_emulation_dn: Option<String>,
    /// Use the group configuration options for the enabled-emulation group.
    #[serde(default)]
    pub user_enabled_emulation_use_group_config: bool,

    // --- Group mapping ---
    /// Base DN for group entries.
    #[serde(default)]
    pub group_tree_dn: String,
    /// LDAP `objectClass` identifying group entries.
    #[serde(default = "default_group_objectclass")]
    pub group_objectclass: String,
    /// Attribute used as the public group ID.
    #[serde(default = "default_group_id_attribute")]
    pub group_id_attribute: String,
    /// Attribute used as the group name.
    #[serde(default = "default_group_name_attribute")]
    pub group_name_attribute: String,
    /// Attribute used as the group description.
    #[serde(default = "default_group_desc_attribute")]
    pub group_desc_attribute: String,
    /// Attribute on a group entry listing member DNs (or member IDs, when
    /// `group_members_are_ids` is set).
    #[serde(default = "default_group_member_attribute")]
    pub group_member_attribute: String,
    /// Members of `group_member_attribute` are keystone user IDs rather than
    /// LDAP DNs (e.g. `posixGroup`'s `memberUid`).
    #[serde(default)]
    pub group_members_are_ids: bool,
    /// Attributes never surfaced as `extra`, even if mapped.
    #[serde(default)]
    pub group_attribute_ignore: HashSet<String>,
    /// Extra LDAP attributes exposed under `extra` in the API response,
    /// mapped as `ldap_attribute -> extra_key`.
    #[serde(default)]
    pub group_additional_attribute_mapping: HashMap<String, String>,
    /// Additional LDAP filter clause AND-ed into every group search.
    pub group_filter: Option<String>,
    /// Use `LDAP_MATCHING_RULE_IN_CHAIN` for Active Directory nested group
    /// resolution.
    #[serde(default)]
    pub group_ad_nesting: bool,

    // --- General ---
    /// Base DN suffix of the directory.
    #[serde(default = "default_suffix")]
    pub suffix: String,
}

impl Default for LdapProvider {
    fn default() -> Self {
        Self {
            url: default_url(),
            user: None,
            password: None,
            use_tls: false,
            tls_cacertfile: None,
            tls_cacertdir: None,
            tls_req_cert: TlsReqCert::default(),
            connection_timeout: default_connection_timeout(),
            randomize_urls: false,
            pool: default_true_bool(),
            pool_size: default_pool_size(),
            pool_retry_max: default_pool_retry_max(),
            pool_retry_delay: default_pool_retry_delay(),
            pool_connection_timeout: default_pool_connection_timeout(),
            pool_connection_lifetime: default_pool_connection_lifetime(),
            auth_pool: default_true_bool(),
            auth_pool_size: default_auth_pool_size(),
            auth_pool_connection_lifetime: default_auth_pool_connection_lifetime(),
            query_scope: QueryScope::default(),
            page_size: default_page_size(),
            alias_dereferencing: AliasDereferencing::default(),
            chase_referrals: None,
            debug_level: 0,
            user_tree_dn: String::new(),
            user_objectclass: default_user_objectclass(),
            user_id_attribute: default_user_id_attribute(),
            user_name_attribute: default_user_name_attribute(),
            user_mail_attribute: default_user_mail_attribute(),
            user_description_attribute: default_user_description_attribute(),
            user_pass_attribute: default_user_pass_attribute(),
            user_default_project_id_attribute: None,
            user_enabled_attribute: default_user_enabled_attribute(),
            user_enabled_mask: None,
            user_enabled_invert: false,
            user_enabled_default: default_user_enabled_default(),
            user_additional_attribute_mapping: HashMap::new(),
            user_filter: None,
            user_attribute_ignore: default_user_attribute_ignore(),
            user_enabled_emulation: false,
            user_enabled_emulation_dn: None,
            user_enabled_emulation_use_group_config: false,
            group_tree_dn: String::new(),
            group_objectclass: default_group_objectclass(),
            group_id_attribute: default_group_id_attribute(),
            group_name_attribute: default_group_name_attribute(),
            group_desc_attribute: default_group_desc_attribute(),
            group_member_attribute: default_group_member_attribute(),
            group_members_are_ids: false,
            group_attribute_ignore: HashSet::new(),
            group_additional_attribute_mapping: HashMap::new(),
            group_filter: None,
            group_ad_nesting: false,
            suffix: default_suffix(),
        }
    }
}

/// TLS certificate validation strictness (`[ldap] tls_req_cert`).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum TlsReqCert {
    /// Reject the connection if no certificate is provided or verification
    /// fails.
    #[default]
    #[serde(rename = "demand")]
    Demand,
    /// Accept the connection whether or not a certificate is provided.
    #[serde(rename = "allow")]
    Allow,
    /// Attempt verification, but do not reject the connection on failure.
    #[serde(rename = "try")]
    Try,
    /// Skip certificate verification entirely.
    #[serde(rename = "never")]
    Never,
}

/// Default search scope for subtree LDAP operations (`[ldap] query_scope`).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum QueryScope {
    /// Single-level search relative to the tree DN.
    #[default]
    #[serde(rename = "one")]
    One,
    /// Whole-subtree search relative to the tree DN.
    #[serde(rename = "sub")]
    Sub,
}

/// Alias dereferencing policy (`[ldap] alias_dereferencing`).
///
/// Parsed for config-file compatibility with Python Keystone, but not
/// currently applied to searches: the `ldap3` crate (v0.11) has no
/// per-search or per-connection alias-dereferencing control. Every search
/// therefore uses the `ldap3`/OpenLDAP client library default regardless of
/// this setting (tracked as a follow-up; see ADR-0027 implementation notes).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum AliasDereferencing {
    /// Fall back to the default dereferencing behavior configured by the
    /// underlying LDAP client library.
    #[default]
    #[serde(rename = "default")]
    Default,
    /// Never dereference aliases.
    #[serde(rename = "never")]
    Never,
    /// Dereference aliases only while searching.
    #[serde(rename = "searching")]
    Searching,
    /// Always dereference aliases.
    #[serde(rename = "always")]
    Always,
    /// Dereference aliases only when locating the search base.
    #[serde(rename = "finding")]
    Finding,
}

fn default_url() -> String {
    "ldap://localhost".into()
}

fn default_true_bool() -> bool {
    true
}

fn default_connection_timeout() -> f64 {
    -1.0
}

fn default_pool_size() -> i32 {
    10
}

fn default_pool_retry_max() -> i32 {
    3
}

fn default_pool_retry_delay() -> f64 {
    0.1
}

fn default_pool_connection_timeout() -> f64 {
    -1.0
}

fn default_pool_connection_lifetime() -> f64 {
    600.0
}

fn default_auth_pool_size() -> i32 {
    100
}

fn default_auth_pool_connection_lifetime() -> f64 {
    60.0
}

fn default_page_size() -> i32 {
    0
}

fn default_user_objectclass() -> String {
    "inetOrgPerson".into()
}

fn default_user_id_attribute() -> String {
    "cn".into()
}

fn default_user_name_attribute() -> String {
    "sn".into()
}

fn default_user_mail_attribute() -> String {
    "mail".into()
}

fn default_user_description_attribute() -> String {
    "description".into()
}

fn default_user_pass_attribute() -> String {
    "userPassword".into()
}

fn default_user_enabled_attribute() -> String {
    "enabled".into()
}

fn default_user_enabled_default() -> String {
    "True".into()
}

fn default_user_attribute_ignore() -> HashSet<String> {
    HashSet::from(["default_project_id".into()])
}

fn default_group_objectclass() -> String {
    "groupOfNames".into()
}

fn default_group_id_attribute() -> String {
    "cn".into()
}

fn default_group_name_attribute() -> String {
    "ou".into()
}

fn default_group_desc_attribute() -> String {
    "description".into()
}

fn default_group_member_attribute() -> String {
    "member".into()
}

fn default_suffix() -> String {
    "cn=example,cn=com".into()
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = LdapProvider::default();
        assert_eq!(cfg.url, "ldap://localhost");
        assert_eq!(cfg.query_scope, QueryScope::One);
        assert_eq!(cfg.tls_req_cert, TlsReqCert::Demand);
        assert_eq!(cfg.alias_dereferencing, AliasDereferencing::Default);
        assert_eq!(cfg.user_objectclass, "inetOrgPerson");
        assert_eq!(cfg.user_id_attribute, "cn");
        assert_eq!(cfg.user_name_attribute, "sn");
        assert_eq!(cfg.user_enabled_default, "True");
        assert_eq!(cfg.group_objectclass, "groupOfNames");
        assert!(!cfg.group_members_are_ids);
        assert!(cfg.pool);
        assert!(cfg.auth_pool);
    }

    #[test]
    fn test_parse_minimal_section() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
[ldap]
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let parsed: LdapProvider = c.get("ldap").unwrap();
        assert_eq!(parsed.url, "ldap://localhost");
        assert_eq!(parsed.user_objectclass, "inetOrgPerson");
    }

    #[test]
    fn test_parse_full_section() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
[ldap]
url = ldaps://ldap.example.com
user = cn=service,dc=example,dc=com
password = secret
use_tls = true
tls_req_cert = never
query_scope = one
alias_dereferencing = always
user_tree_dn = ou=Users,dc=example,dc=com
user_objectclass = person
user_id_attribute = uid
group_tree_dn = ou=Groups,dc=example,dc=com
group_ad_nesting = true
suffix = dc=example,dc=com
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let parsed: LdapProvider = c.get("ldap").unwrap();
        assert_eq!(parsed.url, "ldaps://ldap.example.com");
        assert_eq!(parsed.password.unwrap().expose_secret(), "secret");
        assert!(parsed.use_tls);
        assert_eq!(parsed.tls_req_cert, TlsReqCert::Never);
        assert_eq!(parsed.query_scope, QueryScope::One);
        assert_eq!(parsed.alias_dereferencing, AliasDereferencing::Always);
        assert_eq!(parsed.user_id_attribute, "uid");
        assert!(parsed.group_ad_nesting);
        assert_eq!(parsed.suffix, "dc=example,dc=com");
    }

    #[test]
    fn test_env_override() {
        temp_env::with_var("OS_LDAP__PASSWORD", Some("envsecret"), || {
            let c = Config::builder()
                .add_source(File::from_str("[ldap]\n", FileFormat::Ini))
                .add_source(
                    config::Environment::with_prefix("OS")
                        .prefix_separator("_")
                        .separator("__"),
                )
                .build()
                .unwrap();
            let parsed: LdapProvider = c.get("ldap").unwrap();
            assert_eq!(parsed.password.unwrap().expose_secret(), "envsecret");
        });
    }
}
