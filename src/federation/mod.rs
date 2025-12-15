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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! fedefation.
use async_trait::async_trait;
use uuid::Uuid;

pub mod api;
pub mod backend;
pub mod error;
#[cfg(test)]
pub mod mock;
pub mod types;

use crate::config::Config;
use crate::federation::backend::{FederationBackend, SqlBackend};
use crate::federation::error::FederationProviderError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use types::*;

#[cfg(test)]
pub use mock::MockFederationProvider;
pub use types::FederationApi;

#[derive(Clone, Debug)]
pub struct FederationProvider {
    backend_driver: Box<dyn FederationBackend>,
}

impl FederationProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, FederationProviderError> {
        let backend_driver = if let Some(driver) =
            plugin_manager.get_federation_backend(config.federation.driver.clone())
        {
            driver.clone()
        } else {
            match config.federation.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(FederationProviderError::UnsupportedDriver(
                        config.resource.driver.clone(),
                    ));
                }
            }
        };
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl FederationApi for FederationProvider {
    /// Cleanup expired resources.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError> {
        self.backend_driver.cleanup(state).await
    }

    /// Create new auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        self.backend_driver
            .create_auth_state(state, auth_state)
            .await
    }

    /// Create Identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let mut mod_idp = idp;
        if mod_idp.id.is_none() {
            mod_idp.id = Some(Uuid::new_v4().simple().to_string());
        }

        self.backend_driver
            .create_identity_provider(state, mod_idp)
            .await
    }

    /// Create mapping.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_mapping(
        &self,
        state: &ServiceState,
        mapping: Mapping,
    ) -> Result<Mapping, FederationProviderError> {
        let mut mod_mapping = mapping;
        mod_mapping.id = Uuid::new_v4().into();
        if let Some(_pid) = &mod_mapping.token_project_id {
            // ensure domain_id is set and matches the one of the project_id.
            if let Some(_did) = &mod_mapping.domain_id {
                // TODO: Get the project_id and compare the domain_id
            } else {
                return Err(FederationProviderError::MappingTokenProjectDomainUnset);
            }
            // TODO: ensure current user has access to the project
        }

        self.backend_driver.create_mapping(state, mod_mapping).await
    }

    /// Delete auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_auth_state(state, id).await
    }

    /// Delete identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver
            .delete_identity_provider(state, id)
            .await
    }

    /// Delete identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_mapping(state, id).await
    }

    /// Get auth state by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        self.backend_driver.get_auth_state(state, id).await
    }

    /// Get single IDP by ID.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        self.backend_driver.get_identity_provider(state, id).await
    }

    /// Get single mapping by ID.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        self.backend_driver.get_mapping(state, id).await
    }

    /// List IDP.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .list_identity_providers(state, params)
            .await
    }

    /// List mappings.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        self.backend_driver.list_mappings(state, params).await
    }

    /// Update Identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        self.backend_driver
            .update_identity_provider(state, id, idp)
            .await
    }

    /// Update mapping
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        mapping: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError> {
        let current = self
            .backend_driver
            .get_mapping(state, id)
            .await?
            .ok_or_else(|| FederationProviderError::MappingNotFound(id.to_string()))?;

        if let Some(_new_idp_id) = &mapping.idp_id {
            // TODO: Check the new idp_id domain escaping
        }

        if let Some(_pid) = &mapping.token_project_id {
            // ensure domain_id is set and matches the one of the project_id.
            if let Some(_did) = &current.domain_id {
                // TODO: Get the project_id and compare the domain_id
            } else {
                return Err(FederationProviderError::MappingTokenProjectDomainUnset);
            }
            // TODO: ensure current user has access to the project
        }
        // TODO: Pass current to the backend to skip re-fetching
        self.backend_driver.update_mapping(state, id, mapping).await
    }
}
