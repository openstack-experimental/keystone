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

use chrono::TimeDelta;
use config::{File, FileFormat};
use eyre::{Report, WrapErr};
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    /// Global configuration options
    #[serde(rename = "DEFAULT")]
    pub default: Option<DefaultSection>,
    ///
    /// Assignments (roles) related configuration
    #[serde(default)]
    pub assignment: AssignmentSection,

    /// Authentication configuration.
    pub auth: AuthSection,

    /// Catalog
    #[serde(default)]
    pub catalog: CatalogSection,

    #[serde(default)]
    pub federation: FederationSection,

    /// Fernet tokens
    #[serde(default)]
    pub fernet_tokens: FernetTokenSection,

    /// Database configuration
    //#[serde(default)]
    pub database: DatabaseSection,

    /// Identity provider related configuration
    #[serde(default)]
    pub identity: IdentitySection,

    /// API policy enforcement
    #[serde(default)]
    pub api_policy: PolicySection,

    /// Resource provider related configuration.
    #[serde(default)]
    pub resource: ResourceSection,

    /// Revoke provider configuration.
    #[serde(default)]
    pub revoke: RevokeSection,

    /// Security compliance
    #[serde(default)]
    pub security_compliance: SecurityComplianceSection,

    /// Token
    #[serde(default)]
    pub token: TokenSection,

    /// User options id to name mapping
    #[serde(default = "default_user_options_mapping")]
    pub user_options_id_name_mapping: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DefaultSection {
    /// Debug logging
    pub debug: Option<bool>,
    /// Public endpoint
    pub public_endpoint: Option<String>,
}

/// Authentication configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct AuthSection {
    /// Authentication methods to be enabled and used for token validation.
    #[serde(deserialize_with = "csv")]
    pub methods: Vec<String>,
}

pub fn csv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(String::deserialize(deserializer)?
        .split(',')
        .map(Into::into)
        .collect())
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FernetTokenSection {
    pub key_repository: PathBuf,
    pub max_active_keys: usize,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DatabaseSection {
    /// Database URL.
    pub connection: SecretString,
}

impl DatabaseSection {
    pub fn get_connection(&self) -> SecretString {
        let val = self.connection.expose_secret();
        if val.contains("+") {
            return Regex::new(r"(?<type>\w+)\+(\w+)://")
                .map(|re| SecretString::from(re.replace(val, "${type}://").to_string()))
                .unwrap_or(self.connection.clone());
        }
        self.connection.clone()
    }
}

/// The configuration options for the API policy enforcement.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PolicySection {
    /// Whether the policy enforcement should be enforced or not.
    pub enable: bool,

    /// OpenPolicyAgent instance url to use for evaluating the policy.
    pub opa_base_url: Option<Url>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AssignmentSection {
    #[serde(default = "default_sql_driver")]
    pub driver: String,
}

impl Default for AssignmentSection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CatalogSection {
    #[serde(default = "default_sql_driver")]
    pub driver: String,
}

impl Default for CatalogSection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct FederationSection {
    #[serde(default = "default_sql_driver")]
    pub driver: String,
}

impl Default for FederationSection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct IdentitySection {
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    #[serde(default)]
    pub password_hashing_algorithm: PasswordHashingAlgo,
    pub max_password_length: usize,
    pub password_hash_rounds: Option<usize>,
}

impl Default for IdentitySection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            password_hashing_algorithm: PasswordHashingAlgo::Bcrypt,
            max_password_length: 4096,
            password_hash_rounds: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResourceSection {
    #[serde(default = "default_sql_driver")]
    pub driver: String,
}

impl Default for ResourceSection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
        }
    }
}

/// Revoke provider configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct RevokeSection {
    /// Entry point for the token revocation backend driver in the
    /// `keystone.revoke` namespace. Keystone only provides a `sql` driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// The number of seconds after a token has expired before a corresponding
    /// revocation event may be purged from the backend.
    pub expiration_buffer: usize,
}

impl Default for RevokeSection {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            expiration_buffer: 1800,
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub enum PasswordHashingAlgo {
    #[default]
    Bcrypt,
}

/// Security compliance configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityComplianceSection {
    /// The maximum number of days a user can go without authenticating before
    /// being considered "inactive" and automatically disabled (locked).
    /// This feature is disabled by default; set any value to enable
    /// it. This feature depends on the sql backend for the [identity] driver.
    /// When a user exceeds this threshold and is considered "inactive", the
    /// user's enabled attribute in the HTTP API may not match the value of
    /// the user’s enabled column in the user table.
    #[serde(default)]
    pub disable_user_account_days_inactive: Option<u16>,
    /// Enabling this option requires users to change their password when the
    /// user is created, or upon administrative reset. Before accessing any
    /// services, affected users will have to change their password. To ignore
    /// this requirement for specific users, such as service users, set the
    /// options attribute ignore_change_password_upon_first_use to True for the
    /// desired user via the update user API. This feature is disabled by
    /// default. This feature is only applicable with the sql backend for the
    /// [identity] driver.
    #[serde(default)]
    pub change_password_upon_first_use: bool,
    /// If report_invalid_password_hash is configured, defines the hash function
    /// to be used by HMAC. Possible values are names suitable to hashlib.new()
    /// [https://docs.python.org/3/library/hashlib.html#hashlib.new].
    #[serde(default)]
    pub invalid_password_hash_function: InvalidPasswordHashMethod,
    /// If report_invalid_password_hash is configured, uses provided secret key
    /// when generating password hashes to make them unique and distinct from
    /// any other Keystone installations out there. Should be some secret static
    /// value specific to the current installation (the same value should be
    /// used in distributed installations working with the same backend, to make
    /// them all generate equal hashes for equal invalid passwords). 16 bytes
    /// (128 bits) or more is recommended.
    #[serde(default)]
    pub invalid_password_hash_key: Option<String>,
    /// This option has a sample default set, which means that its actual
    /// default value may vary from the one documented above.
    ///
    /// If report_invalid_password_hash is configured, defines the number of
    /// characters of hash of invalid password to be returned. When not
    /// specified, returns full hash. Its length depends on implementation and
    /// invalid_password_hash_function configuration, but is typically 16+
    /// characters. It’s recommended to use the least reasonable value however -
    /// it’s the most effective measure to protect the hashes.
    #[serde(default)]
    pub invalid_password_hash_max_chars: Option<u8>,

    /// The maximum number of times that a user can fail to authenticate before
    /// the user account is locked for the number of seconds specified by
    /// [security_compliance] lockout_duration. This feature is disabled by
    /// default. If this feature is enabled and [security_compliance]
    /// lockout_duration is not set, then users may be locked out indefinitely
    /// until the user is explicitly enabled via the API. This feature depends
    /// on the sql backend for the [identity] driver.
    #[serde(default)]
    pub lockout_failure_attempts: Option<u16>,
    /// The number of seconds a user account will be locked when the maximum
    /// number of failed authentication attempts (as specified by
    /// [security_compliance] lockout_failure_attempts) is exceeded. Setting
    /// this option will have no effect unless you also set
    /// [security_compliance] lockout_failure_attempts to a non-zero value. This
    /// feature depends on the sql backend for the [identity] driver.
    //#[serde(default = "AccountLockoutDuration::default")]
    #[serde(
        deserialize_with = "optional_timedelta_from_seconds",
        default = "AccountLockoutDuration::default"
    )]
    pub lockout_duration: Option<TimeDelta>,
    /// The number of days that a password must be used before the user can
    /// change it. This prevents users from changing their passwords immediately
    /// in order to wipe out their password history and reuse an old password.
    /// This feature does not prevent administrators from manually resetting
    /// passwords. It is disabled by default and allows for immediate password
    /// changes. This feature depends on the sql backend for the [identity]
    /// driver. Note: If [security_compliance] password_expires_days is set,
    /// then the value for this option should be less than the
    /// password_expires_days.
    #[serde(default)]
    pub minimum_password_age: u32,
    /// The number of days for which a password will be considered valid before
    /// requiring it to be changed. This feature is disabled by default. If
    /// enabled, new password changes will have an expiration date,
    /// however existing passwords would not be impacted. This feature depends
    /// on the sql backend for the [identity] driver.
    #[serde(default)]
    pub password_expires_days: Option<u64>,
    /// The regular expression used to validate password strength requirements.
    /// By default, the regular expression will match any password. The
    /// following is an example of a pattern which requires at least 1 letter, 1
    /// digit, and have a minimum length of 7 characters:
    /// ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$ This feature depends on the sql backend
    /// for the [identity] driver.
    #[serde(default)]
    pub password_regex: Option<String>,
    /// Describe your password regular expression here in language for humans.
    /// If a password fails to match the regular expression, the contents of
    /// this configuration variable will be returned to users to explain why
    /// their requested password was insufficient.
    #[serde(default)]
    pub password_regex_description: Option<String>,
    /// This option has a sample default set, which means that its actual
    /// default value may vary from the one documented above.
    ///
    /// When configured, enriches the corresponding output channel with hash of
    /// invalid password, which could be further used to distinguish bruteforce
    /// attacks from e.g. external user automations that did not timely update
    /// rotated password by analyzing variability of the hash value. Additional
    /// configuration parameters are available using other
    /// invalid_password_hash_* configuration entries, that only take effect
    /// when this option is activated.
    #[serde(default = "ReportInvalidPasswordHash::default")]
    pub report_invalid_password_hash: Vec<InvalidPasswordHashReport>,
    /// This controls the number of previous user password iterations to keep in
    /// history, in order to enforce that newly created passwords are unique.
    /// The total number which includes the new password should not be greater
    /// or equal to this value. Setting the value to zero (the default) disables
    /// this feature. Thus, to enable this feature, values must be greater than
    /// 0. This feature depends on the sql backend for the [identity] driver.
    #[serde(default)]
    pub unique_last_password_count: Option<u16>,
}

// /// Deserializes an i64 and interprets it as total SECONDS for
// /// chrono::TimeDelta.
// fn timedelta_from_seconds<'de, D>(deserializer: D) -> Result<TimeDelta, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     // Read the input number from JSON as an i64
//     let seconds = i64::deserialize(deserializer)?;
//
//     // Convert the number into a TimeDelta representing seconds
//     TimeDelta::try_seconds(seconds)
//         .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for seconds"))
// }

/// Deserializes an Option<i64> and interprets Some(i64) as total SECONDS for
/// TimeDelta.
fn optional_timedelta_from_seconds<'de, D>(deserializer: D) -> Result<Option<TimeDelta>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the field content into Option<i64>.
    // Serde handles 'null' or an absent field by returning None here.
    let seconds_opt: Option<i64> = Option::deserialize(deserializer)?;

    match seconds_opt {
        // If a number was present, convert it to TimeDelta and wrap it in Some.
        Some(seconds) => TimeDelta::try_seconds(seconds)
            .map(Some) // Map TimeDelta to Some(TimeDelta)
            .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for optional seconds")),

        // If None was present (null or missing field), return Ok(None).
        None => Ok(None),
    }
}

impl Default for SecurityComplianceSection {
    fn default() -> Self {
        Self {
            disable_user_account_days_inactive: None,
            change_password_upon_first_use: false,
            invalid_password_hash_function: InvalidPasswordHashMethod::default(),
            invalid_password_hash_key: None,
            invalid_password_hash_max_chars: None,
            lockout_failure_attempts: None,
            lockout_duration: AccountLockoutDuration::default(),
            minimum_password_age: 0,
            password_expires_days: None,
            password_regex: None,
            password_regex_description: None,
            report_invalid_password_hash: ReportInvalidPasswordHash::default(),
            unique_last_password_count: None,
        }
    }
}

struct AccountLockoutDuration {}
impl AccountLockoutDuration {
    fn default() -> Option<TimeDelta> {
        Some(TimeDelta::seconds(1800))
    }
}

struct ReportInvalidPasswordHash {}
impl ReportInvalidPasswordHash {
    fn default() -> Vec<InvalidPasswordHashReport> {
        vec![InvalidPasswordHashReport::Event]
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub enum InvalidPasswordHashReport {
    #[default]
    Event,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub enum InvalidPasswordHashMethod {
    #[default]
    Sha256,
}
fn default_sql_driver() -> String {
    "sql".into()
}

fn default_user_options_mapping() -> HashMap<String, String> {
    HashMap::from([
        (
            "1000".into(),
            "ignore_change_password_upon_first_use".into(),
        ),
        ("1001".into(), "ignore_password_expiry".into()),
        ("1002".into(), "ignore_lockout_failure_attempts".into()),
        ("1003".into(), "lock_password".into()),
    ])
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct TokenSection {
    #[serde(default)]
    pub provider: TokenProvider,
    /// The amount of time that a token should remain valid (in seconds).
    /// Drastically reducing this value may break "long-running" operations
    /// that involve multiple services to coordinate together, and will
    /// force users to authenticate with keystone more frequently. Drastically
    /// increasing this value will increase the number of tokens that will be
    /// simultaneously valid. Keystone tokens are also bearer tokens, so a
    /// shorter duration will also reduce the potential security impact of a
    /// compromised token.
    #[serde(default)]
    pub expiration: usize,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub enum TokenProvider {
    #[default]
    #[serde(rename = "fernet")]
    Fernet,
}

impl Config {
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        let mut builder = config::Config::builder();

        if std::path::Path::new(&path).is_file() {
            builder = builder.add_source(File::from(path).format(FileFormat::Ini));
        }

        builder.try_into()
    }
}

impl TryFrom<config::ConfigBuilder<config::builder::DefaultState>> for Config {
    type Error = Report;
    fn try_from(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, Self::Error> {
        let mut builder = builder;
        builder = builder
            .set_default("api_policy.enable", "true")?
            .set_default("api_policy.opa_base_url", "http://localhost:8181")?
            .set_default("identity.max_password_length", "4096")?
            .set_default("fernet_tokens.key_repository", "/etc/keystone/fernet-keys/")?
            .set_default("fernet_tokens.max_active_keys", "3")?
            .set_default("revoke.expiration_buffer", "1800")?
            .set_default("token.expiration", "3600")?;

        builder
            .build()
            .wrap_err("Failed to read configuration file")?
            .try_deserialize()
            .wrap_err("Failed to parse configuration file")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_db_connection() {
        let sot = DatabaseSection {
            connection: "mysql://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
    }
}
