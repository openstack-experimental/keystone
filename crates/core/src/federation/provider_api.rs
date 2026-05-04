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

use openstack_keystone_core_types::federation::*;

use crate::federation::error::FederationProviderError;
use crate::keystone::ServiceState;

/// Federation provider interface.
#[async_trait]
pub trait FederationApi: Send + Sync {
    /// Cleanup expired resources
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError>;

    /// Create identity provider.
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
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Create authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `state`: The authentication state to create.
    ///
    /// # Returns
    /// - `Result<AuthState, FederationProviderError>` - The created `AuthState`
    ///   or an error.
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError>;

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
    ) -> Result<Mapping, FederationProviderError>;

    /// Delete authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the authentication state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

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
    ) -> Result<(), FederationProviderError>;

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
    ) -> Result<(), FederationProviderError>;

    /// Get authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the authentication state to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<AuthState>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the AuthState if found, or an `Error`.
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError>;

    /// Get identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - A
    ///   `Result` containing an `Option` with the IdentityProvider if found, or
    ///   an `Error`.
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    /// Get mapping.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the mapping to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<Mapping>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the Mapping if found, or an `Error`.
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError>;

    /// List identity providers.
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
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

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
    ) -> Result<Vec<Mapping>, FederationProviderError>;

    /// Update identity provider.
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
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Update mapping.
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
    ) -> Result<Mapping, FederationProviderError>;
}
