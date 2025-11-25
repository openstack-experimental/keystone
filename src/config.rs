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
    /// Entry point for the token revocation backend driver in the `keystone.revoke` namespace.
    /// Keystone only provides a `sql` driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// The number of seconds after a token has expired before a corresponding revocation event may
    /// be purged from the backend.
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

#[derive(Debug, Default, Deserialize, Clone)]
pub struct SecurityComplianceSection {
    pub password_expires_days: Option<u64>,
    pub disable_user_account_days_inactive: Option<i16>,
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
    /// The amount of time that a token should remain valid (in seconds). Drastically reducing this
    /// value may break "long-running" operations that involve multiple services to coordinate
    /// together, and will force users to authenticate with keystone more frequently. Drastically
    /// increasing this value will increase the number of tokens that will be simultaneously valid.
    /// Keystone tokens are also bearer tokens, so a shorter duration will also reduce the
    /// potential security impact of a compromised token.
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
