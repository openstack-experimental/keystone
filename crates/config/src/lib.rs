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
//! # Keystone configuration
//!
//! Parse of the Keystone configuration file with the following features:
//!
//! - File is parsed as the INI file keeping full compatibility with the legacy
//!   OpenStack config format
//! - Additional file is loaded overloading the initial config with the file
//!   name coming from the `KEYSTONE_SITE_VARS_FILE` environment variable. When
//!   it is not set no additional file is loaded.
//! - Environment variables take final precedence. They use the traditional
//!   OpenStack style and look like `OS_API_POLICY__OPA_BASE_URL` for setting
//!   `[api_policy].opa_base_url` variable.
//!
//! # Example
//!
//! ```no_run
//! use openstack_keystone_config::Config;
//!
//! let cfg = Config::new("/etc/keystone/keystone.conf".into()).unwrap();
//! ```
use std::env;
use std::path::PathBuf;

use config::{File, FileFormat};
use eyre::{Report, WrapErr};
use serde::Deserialize;

mod application_credentials;
mod assignment;
mod auth;
mod catalog;
mod common;
mod database;
mod default;
mod distributed_storage;
mod federation;
mod fernet_token;
mod identity;
mod identity_mapping;
mod k8s_auth;
mod listener;
mod policy;
mod resource;
mod revoke;
mod role;
mod security_compliance;
mod token;
mod token_restriction;
mod trust;
mod webauthn;

pub use application_credentials::*;
pub use assignment::*;
pub use auth::*;
pub use catalog::*;
pub use database::*;
pub use default::*;
pub use distributed_storage::*;
pub use federation::*;
pub use fernet_token::*;
pub use identity::*;
pub use identity_mapping::*;
pub use k8s_auth::*;
pub use listener::*;
pub use policy::*;
pub use resource::*;
pub use revoke::*;
pub use role::*;
pub use security_compliance::*;
pub use token::*;
pub use token_restriction::*;
pub use trust::*;
pub use webauthn::*;

/// Keystone configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    /// Application credentials provider configuration.
    #[serde(default)]
    pub application_credential: ApplicationCredentialProvider,

    /// API policy enforcement.
    #[serde(default)]
    pub api_policy: PolicyProvider,

    /// Assignments (roles) provider configuration.
    #[serde(default)]
    pub assignment: AssignmentProvider,

    /// Authentication configuration.
    pub auth: AuthProvider,

    /// Catalog provider configuration.
    #[serde(default)]
    pub catalog: CatalogProvider,

    /// Database configuration.
    //#[serde(default)]
    pub database: DatabaseSection,

    /// Global configuration options.
    #[serde(rename = "DEFAULT", default)]
    pub default: DefaultSection,

    /// Distributed storage configuration.
    #[serde(default)]
    pub distributed_storage: Option<DistributedStorageConfiguration>,

    /// Federation provider configuration.
    #[serde(default)]
    pub federation: FederationProvider,

    /// Fernet tokens provider configuration.
    #[serde(default)]
    pub fernet_tokens: FernetTokenProvider,

    /// Identity provider configuration.
    #[serde(default)]
    pub identity: IdentityProvider,

    /// Identity mapping provider configuration.
    #[serde(default)]
    pub identity_mapping: IdentityMappingProvider,

    /// K8s Auth provider configuration.
    #[serde(default)]
    pub k8s_auth: K8sAuthProvider,

    /// Server listener configuration.
    #[serde(default)]
    pub listener: Listener,

    /// Resource provider configuration.
    #[serde(default)]
    pub resource: ResourceProvider,

    /// Revoke provider configuration.
    #[serde(default)]
    pub revoke: RevokeProvider,

    /// Role provider configuration.
    #[serde(default)]
    pub role: RoleProvider,

    /// Security compliance configuration.
    #[serde(default)]
    pub security_compliance: SecurityComplianceProvider,

    /// Token provider configuration.
    #[serde(default)]
    pub token: TokenProvider,

    /// Token restriction provider configuration.
    #[serde(default)]
    pub token_restriction: TokenRestrictionProvider,

    /// Trust provider configuration.
    #[serde(default)]
    pub trust: TrustProvider,

    /// Webauthn configuration.
    #[serde(default)]
    pub webauthn: WebauthnSection,
}

impl Config {
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        let mut builder = config::Config::builder();

        if std::path::Path::new(&path).is_file() {
            builder = builder.add_source(File::from(path).format(FileFormat::Ini));
        }

        if let Ok(site_vars_file) = env::var("KEYSTONE_SITE_VARS_FILE") {
            builder = builder.add_source(File::with_name(&site_vars_file));
        }

        builder = builder.add_source(
            config::Environment::with_prefix("OS")
                .prefix_separator("_")
                .separator("__"),
        );

        builder.try_into()
    }
}

impl TryFrom<config::ConfigBuilder<config::builder::DefaultState>> for Config {
    type Error = Report;
    fn try_from(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, Self::Error> {
        builder
            .build()
            .wrap_err("Failed to read configuration file")?
            .try_deserialize()
            .wrap_err("Failed to parse configuration file")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_env() {
        temp_env::with_var("OS_API_POLICY__OPA_BASE_URL", Some("http://test/"), || {
            let mut cfg_file = NamedTempFile::new().unwrap();
            write!(
                cfg_file,
                r#"
[auth]
methods = []
[database]
connection = "foo"
            "#
            )
            .unwrap();

            let cfg = Config::new(cfg_file.path().to_path_buf()).unwrap();
            assert_eq!("http://test/", cfg.api_policy.opa_base_url.to_string());
        });
    }

    #[test]
    fn test_site_vars() {
        let mut site_vars_file = NamedTempFile::with_suffix(".toml").unwrap();
        write!(
            site_vars_file,
            r#"
[distributed_storage]
node_id = 1
cluster_addr = "http://foo:8300"
path = "/tmp"
        "#
        )
        .unwrap();
        temp_env::with_var(
            "KEYSTONE_SITE_VARS_FILE",
            Some(site_vars_file.path()),
            || {
                let mut cfg_file = NamedTempFile::new().unwrap();
                write!(
                    cfg_file,
                    r#"
[auth]
methods = []
[database]
connection = "foo"
            "#
                )
                .unwrap();

                let cfg = Config::new(cfg_file.path().to_path_buf()).unwrap();
                let ds = cfg.distributed_storage.unwrap();
                assert_eq!(1, ds.node_id);
                assert_eq!("http://foo:8300/", ds.cluster_addr.to_string());
            },
        );
    }
}
