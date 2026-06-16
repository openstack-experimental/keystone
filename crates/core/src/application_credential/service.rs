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
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use rand::{RngExt, rng};
use secrecy::SecretString;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::application_credential::{
    ApplicationCredentialApi, ApplicationCredentialProviderError,
    backend::ApplicationCredentialBackend,
};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::RoleApi;

/// Application Credential Provider.
pub struct ApplicationCredentialService {
    backend_driver: Arc<dyn ApplicationCredentialBackend>,
}

impl ApplicationCredentialService {
    /// Create a new application credential service.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    /// - `plugin_manager`: The plugin manager to retrieve the backend driver.
    ///
    /// # Returns
    /// - `Result<Self, ApplicationCredentialProviderError>` - The created
    ///   service or an error.
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
    /// Create a standalone access rule owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `rule`: The access rule to create.
    ///
    /// # Returns
    /// - `Result<AccessRule, ApplicationCredentialProviderError>` - The created
    ///   access rule or an error.
    async fn create_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        rule: AccessRuleCreate,
    ) -> Result<AccessRule, ApplicationCredentialProviderError> {
        let mut rule = rule;
        rule.validate()?;
        // The provider prepares the final data; the driver only persists it.
        if rule.id.is_none() {
            rule.id = Some(Uuid::new_v4().simple().to_string());
        }
        self.backend_driver
            .create_access_rule(state, user_id, rule)
            .await
    }

    /// Create a new application credential.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rec`: The application credential creation request.
    ///
    /// # Returns
    /// - `Result<ApplicationCredentialCreateResponse,
    ///   ApplicationCredentialProviderError>` - The creation response or an
    ///   error.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        rec.validate()?;
        // TODO: implement some filters.
        let roles: HashSet<String> = state
            .provider
            .get_role_provider()
            .list_roles(state, &RoleListParameters::default())
            .await?
            .iter()
            .map(|role| role.id.clone())
            .collect();
        for role in rec.roles.iter() {
            if !roles.contains(&role.id) {
                return Err(ApplicationCredentialProviderError::RoleNotFound(
                    role.id.clone(),
                ));
            }
        }
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
        let response = self
            .backend_driver
            .create_application_credential(state, new_rec.clone())
            .await?;

        state
            .event_dispatcher
            .emit(Event::new(
                Operation::Create,
                EventPayload::ApplicationCredential {
                    id: new_rec.id.unwrap_or_default(),
                    project_id: new_rec.project_id.clone(),
                },
            ))
            .await;

        Ok(response)
    }

    /// Delete a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<(), ApplicationCredentialProviderError>` - Unit on success, or
    ///   an error.
    async fn delete_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<(), ApplicationCredentialProviderError> {
        self.backend_driver
            .delete_access_rule(state, user_id, id)
            .await
    }

    /// Get a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<Option<AccessRule>, ApplicationCredentialProviderError>` - The
    ///   access rule if found, or an error.
    async fn get_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError> {
        self.backend_driver
            .get_access_rule(state, user_id, id)
            .await
    }

    /// Get a single application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the application credential.
    ///
    /// # Returns
    /// - `Result<Option<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - The credential if found, or an
    ///   error.
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

    /// List all access rules owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rules.
    ///
    /// # Returns
    /// - `Result<Vec<AccessRule>, ApplicationCredentialProviderError>` - A list
    ///   of access rules or an error.
    async fn list_access_rules<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError> {
        self.backend_driver.list_access_rules(state, user_id).await
    }

    /// List application credentials.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the list of credentials.
    ///
    /// # Returns
    /// - `Result<Vec<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - A list of application
    ///   credentials or an error.
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
///
/// # Returns
/// - `SecretString` - The generated secret.
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
