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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::federation::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod provider_api;
pub mod service;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use service::FederationService;

pub use crate::federation::error::FederationProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockFederationProvider;
pub use provider_api::FederationApi;

pub enum FederationProvider {
    Service(FederationService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockFederationProvider),
}

impl FederationProvider {
    /// Create a new FederationProvider.
    ///
    /// # Parameters
    /// - `config`: The configuration for the federation provider.
    /// - `plugin_manager`: The plugin manager to resolve the federation
    ///   backend.
    ///
    /// # Returns
    /// - `Result<Self, FederationProviderError>` - The newly created
    ///   `FederationProvider` or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, FederationProviderError> {
        Ok(Self::Service(FederationService::new(
            config,
            plugin_manager,
        )?))
    }
}

#[async_trait]
impl FederationApi for FederationProvider {
    /// Cleanup expired resources.
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError> {
        match self {
            Self::Service(provider) => provider.cleanup(state).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.cleanup(state).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.create_auth_state(state, auth_state).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_auth_state(state, auth_state).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.create_identity_provider(state, idp).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_identity_provider(state, idp).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_mapping(
        &self,
        state: &ServiceState,
        mapping: Mapping,
    ) -> Result<Mapping, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.create_mapping(state, mapping).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_mapping(state, mapping).await,
        }
    }

    /// Delete auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        match self {
            Self::Service(provider) => provider.delete_identity_provider(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_auth_state(state, id).await,
        }
    }

    /// Delete identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        match self {
            Self::Service(provider) => provider.delete_identity_provider(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_identity_provider(state, id).await,
        }
    }

    /// Delete mapping.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the mapping to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        match self {
            Self::Service(provider) => provider.delete_mapping(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_mapping(state, id).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.get_auth_state(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_auth_state(state, id).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.get_identity_provider(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_identity_provider(state, id).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.get_mapping(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_mapping(state, id).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.list_identity_providers(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_identity_providers(state, params).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.list_mappings(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_mappings(state, params).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.update_identity_provider(state, id, idp).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_identity_provider(state, id, idp).await,
        }
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        mapping: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError> {
        match self {
            Self::Service(provider) => provider.update_mapping(state, id, mapping).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_mapping(state, id, mapping).await,
        }
    }
}
