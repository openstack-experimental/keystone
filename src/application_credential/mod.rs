// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # Application credentials provider
//!
//! Application credentials provide a way to delegate a user’s authorization to
//! an application without sharing the user’s password authentication. This is a
//! useful security measure, especially for situations where the user’s
//! identification is provided by an external source, such as LDAP or a
//! single-sign-on service. Instead of storing user passwords in config files, a
//! user creates an application credential for a specific project, with all or a
//! subset of the role assignments they have on that project, and then stores
//! the application credential identifier and secret in the config file.
//!
//! Multiple application credentials may be active at once, so you can easily
//! rotate application credentials by creating a second one, converting your
//! applications to use it one by one, and finally deleting the first one.
//!
//! Application credentials are limited by the lifespan of the user that created
//! them. If the user is deleted, disabled, or loses a role assignment on a
//! project, the application credential is deleted.
//!
//! Application credentials can have their privileges limited in two ways.
//! First, the owner may specify a subset of their own roles that the
//! application credential may assume when getting a token for a project. For
//! example, if a user has the member role on a project, they also have the
//! implied role reader and can grant the application credential only the reader
//! role for the project:
//!
//! ```yaml
//! "roles": [
//!     {"name": "reader"}
//! ]
//! ```
//!
//! Users also have the option of delegating more fine-grained access control to
//! their application credentials by using access rules. For example, to create
//! an application credential that is constricted to creating servers in nova,
//! the user can add the following access rules:
//!
//! ```yaml
//! "access_rules": [
//!     {
//!         "path": "/v2.1/servers",
//!         "method": "POST",
//!         "service": "compute"
//!     }
//! ]
//! ```
//!
//! The "path" attribute of application credential access rules uses a wildcard
//! syntax to make it more flexible. For example, to create an application
//! credential that is constricted to listing server IP addresses, you could use
//! either of the following access rules:
//!
//! ```yaml
//! "access_rules": [
//!     {
//!         "path": "/v2.1/servers/*/ips",
//!         "method": "GET",
//!         "service": "compute"
//!     }
//! ]
//! ```
//!
//! or equivalently:
//!
//! ```yaml
//! "access_rules": [
//!     {
//!         "path": "/v2.1/servers/{server_id}/ips",
//!         "method": "GET",
//!         "service": "compute"
//!     }
//! ]
//! ```
//!
//! In both cases, a request path containing any server ID will match the access
//! rule. For even more flexibility, the recursive wildcard ** indicates that
//! request paths containing any number of / will be matched. For example:
//!
//! ```yaml
//! "access_rules": [
//!     {
//!         "path": "/v2.1/**",
//!         "method": "GET",
//!         "service": "compute"
//!     }
//! ]
//! ```
//!
//! will match any nova API for version 2.1.
//!
//! An access rule created for one application credential can be re-used by
//! providing its ID to another application credential, for example:
//!
//! ```yaml
//! "access_rules": [
//!     {
//!         "id": "abcdef"
//!     }
//! ]
//! ```

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use rand::{Rng, rng};
use secrecy::SecretString;
use uuid::Uuid;
use validator::Validate;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;

use backend::{ApplicationCredentialBackend, SqlBackend};
use types::*;

pub use error::ApplicationCredentialProviderError;
#[cfg(test)]
pub use mock::MockApplicationCredentialProvider;
pub use types::ApplicationCredentialApi;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;

/// Application Credential Provider.
#[derive(Clone, Debug)]
pub struct ApplicationCredentialProvider {
    backend_driver: Box<dyn ApplicationCredentialBackend>,
}

impl ApplicationCredentialProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, ApplicationCredentialProviderError> {
        let mut backend_driver = if let Some(driver) = plugin_manager
            .get_application_credential_backend(config.application_credential.driver.clone())
        {
            driver.clone()
        } else {
            match config.application_credential.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                other => {
                    return Err(ApplicationCredentialProviderError::UnsupportedDriver(
                        other.to_string(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ApplicationCredentialApi for ApplicationCredentialProvider {
    /// Create a new application credential.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        rec.validate()?;
        // TODO: Check app creds count
        let mut new_rec = rec;
        if new_rec.id.is_none() {
            new_rec.id = Some(Uuid::new_v4().simple().to_string());
        }
        if let Some(ref mut rules) = new_rec.access_rules {
            for rule in rules {
                if rule.id.is_none() {
                    rule.id = Some(Uuid::new_v4().simple().to_string());
                }
            }
        }
        if new_rec.secret.is_none() {
            new_rec.secret = Some(generate_secret());
        }
        self.backend_driver
            .create_application_credential(state, new_rec)
            .await
    }

    /// Get a single application credential by ID.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        self.backend_driver
            .get_application_credential(state, id)
            .await
    }

    /// List application credentials.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<impl IntoIterator<Item = ApplicationCredential>, ApplicationCredentialProviderError>
    {
        params.validate()?;
        self.backend_driver
            .list_application_credentials(state, params)
            .await
    }
}

/// Generate application credential secret.
///
/// Use the same algorithm as the python Keystone uses:
///
///  - use random 64 bytes
///  - apply base64 encoding with no padding
pub fn generate_secret() -> SecretString {
    const LENGTH: usize = 64;

    // 1. Generate 64 cryptographically secure random bytes (Analogous to
    //    `secrets.token_bytes(length)`)
    let mut secret_bytes = [0u8; LENGTH];
    rng().fill(&mut secret_bytes[..]);

    // 2. Base64 URL-safe encoding (Analogous to `base64.urlsafe_b64encode(secret)`)
    //    with stripping padding handled automatically by `URL_SAFE_NO_PAD` engine.
    let encoded_secret = general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);

    SecretString::new(encoded_secret.into())
}
