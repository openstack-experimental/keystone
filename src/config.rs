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
//! Parsing of the Keystone configuration file implementation.
use config::{File, FileFormat};
use eyre::{Report, WrapErr};
use serde::Deserialize;
use std::path::PathBuf;

mod application_credentials;
mod assignment;
mod auth;
mod catalog;
mod common;
mod database;
mod default;
mod federation;
mod fernet_token;
mod identity;
mod identity_mapping;
mod policy;
mod resource;
mod revoke;
mod security_compliance;
mod token;
mod trust;

use application_credentials::ApplicationCredentialProvider;
use assignment::AssignmentProvider;
use auth::AuthProvider;
use catalog::CatalogProvider;
use database::DatabaseSection;
pub use default::DefaultSection;
use federation::FederationProvider;
pub use fernet_token::FernetTokenProvider;
pub use identity::*;
use identity_mapping::IdentityMappingProvider;
use policy::PolicyProvider;
use resource::ResourceProvider;
use revoke::RevokeProvider;
use security_compliance::SecurityComplianceProvider;
use token::TokenProvider;
pub use token::TokenProviderDriver;
use trust::TrustProvider;

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

    /// Resource provider configuration.
    #[serde(default)]
    pub resource: ResourceProvider,

    /// Revoke provider configuration.
    #[serde(default)]
    pub revoke: RevokeProvider,

    /// Security compliance configuration.
    #[serde(default)]
    pub security_compliance: SecurityComplianceProvider,

    /// Token provider configuration.
    #[serde(default)]
    pub token: TokenProvider,

    /// Trust provider configuration.
    #[serde(default)]
    pub trust: TrustProvider,
}

impl Config {
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        let mut builder = config::Config::builder();

        if std::path::Path::new(&path).is_file() {
            builder = builder
                .add_source(File::from(path).format(FileFormat::Ini))
                .add_source(
                    config::Environment::with_prefix("OS")
                        .prefix_separator("_")
                        .separator("__"),
                );
        }

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
