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
use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use rand::{RngExt, rng};
use secrecy::SecretString;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;

use crate::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend, types::*,
};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::{
    RoleApi,
    types::{Role, RoleListParameters},
};

/// Application Credential Provider.
pub struct ApplicationCredentialService {
    backend_driver: Arc<dyn ApplicationCredentialBackend>,
}

impl ApplicationCredentialService {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ApplicationCredentialProviderError> {
        let backend_driver = plugin_manager
            .get_application_credential_backend(config.application_credential.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ApplicationCredentialApi for ApplicationCredentialService {
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
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        if let Some(mut app_cred) = self
            .backend_driver
            .get_application_credential(state, id)
            .await?
        {
            let roles: BTreeMap<String, Role> = state
                .provider
                .get_role_provider()
                .list_roles(state, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect();
            for cred_role in app_cred.roles.iter_mut() {
                if let Some(role) = roles.get(&cred_role.id) {
                    cred_role.name = Some(role.name.clone());
                    cred_role.domain_id = role.domain_id.clone();
                }
            }
            Ok(Some(app_cred))
        } else {
            Ok(None)
        }
    }

    /// List application credentials.
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError> {
        params.validate()?;
        let mut creds = self
            .backend_driver
            .list_application_credentials(state, params)
            .await?;

        let roles: BTreeMap<String, Role> = state
            .provider
            .get_role_provider()
            .list_roles(state, &RoleListParameters::default())
            .await?
            .into_iter()
            .map(|x| (x.id.clone(), x))
            .collect();
        for cred in creds.iter_mut() {
            for cred_role in cred.roles.iter_mut() {
                if let Some(role) = roles.get(&cred_role.id) {
                    cred_role.name = Some(role.name.clone());
                    cred_role.domain_id = role.domain_id.clone();
                }
            }
        }
        Ok(creds)
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
