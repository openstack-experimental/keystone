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
//! federation.
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::federation::*;

use crate::federation::{FederationApi, FederationProviderError, backend::FederationBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub struct FederationService {
    backend_driver: Arc<dyn FederationBackend>,
}

impl FederationService {
    /// Create new federation service.
    ///
    /// # Parameters
    /// - `config`: The configuration for the federation service.
    /// - `plugin_manager`: The plugin manager to resolve the federation
    ///   backend.
    ///
    /// # Returns
    /// - `Result<Self, FederationProviderError>` - The newly created
    ///   `FederationService` or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, FederationProviderError> {
        let backend_driver = plugin_manager
            .get_federation_backend(config.federation.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl FederationApi for FederationService {
    /// Cleanup expired resources.
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError> {
        self.backend_driver.cleanup(state).await
    }

    /// Create new auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth_state`: The authentication state to create.
    ///
    /// # Returns
    /// - `Result<AuthState, FederationProviderError>` - The created `AuthState`
    ///   or an error.
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
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp`: The identity provider details to create.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The created
    ///   `IdentityProvider` or an error.
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
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `mapping`: The mapping to create.
    ///
    /// # Returns
    /// - `Result<Mapping, FederationProviderError>` - The created `Mapping` or
    ///   an error.
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
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_auth_state(state, id).await
    }

    /// Delete identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver
            .delete_identity_provider(state, id)
            .await
    }

    /// Delete mapping.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the mapping to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_mapping(state, id).await
    }

    /// Get auth state by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<AuthState>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the auth state if found, or an `Error`.
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        self.backend_driver.get_auth_state(state, id).await
    }

    /// Get single IDP by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - A
    ///   `Result` containing an `Option` with the identity provider if found,
    ///   or an `Error`.
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        self.backend_driver.get_identity_provider(state, id).await
    }

    /// Get single mapping by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the mapping to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<Mapping>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the mapping if found, or an `Error`.
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        self.backend_driver.get_mapping(state, id).await
    }

    /// List IDP.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for identity providers.
    ///
    /// # Returns
    /// - `Result<Vec<IdentityProvider>, FederationProviderError>` - A list of
    ///   identity providers or an error.
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
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for mappings.
    ///
    /// # Returns
    /// - `Result<Vec<Mapping>, FederationProviderError>` - A list of mappings
    ///   or an error.
    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        self.backend_driver.list_mappings(state, params).await
    }

    /// Update Identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to update.
    /// - `idp`: The update details for the identity provider.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The updated
    ///   `IdentityProvider` or an error.
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
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the mapping to update.
    /// - `mapping`: The update details for the mapping.
    ///
    /// # Returns
    /// - `Result<Mapping, FederationProviderError>` - The updated `Mapping` or
    ///   an error.
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
