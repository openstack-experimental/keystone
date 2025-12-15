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

use async_trait::async_trait;

use super::super::types::*;
use crate::federation::{FederationProviderError, backend::FederationBackend};
use crate::keystone::ServiceState;

mod auth_state;
mod identity_provider;
mod mapping;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {}

#[async_trait]
impl FederationBackend for SqlBackend {
    /// Cleanup expired resources.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError> {
        Ok(auth_state::delete_expired(&state.db).await?)
    }

    /// Create new auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        Ok(auth_state::create(&state.db, auth_state).await?)
    }

    /// Create Identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::create(&state.db, idp).await?)
    }

    /// Create mapping.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_mapping(
        &self,
        state: &ServiceState,
        idp: Mapping,
    ) -> Result<Mapping, FederationProviderError> {
        Ok(mapping::create(&state.db, idp).await?)
    }

    /// Delete auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        Ok(auth_state::delete(&state.db, id).await?)
    }

    /// Delete mapping.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        Ok(mapping::delete(&state.db, id).await?)
    }

    /// Delete identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        Ok(identity_provider::delete(&state.db, id).await?)
    }

    /// Get auth state by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        Ok(auth_state::get(&state.db, id).await?)
    }

    /// Get single IDP by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::get(&state.db, id).await?)
    }

    /// Get single mapping by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        Ok(mapping::get(&state.db, id).await?)
    }

    /// List IDPs.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::list(&state.db, params).await?)
    }

    /// List Mapping.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        Ok(mapping::list(&state.db, params).await?)
    }

    /// Update Identity provider.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::update(&state.db, id, idp).await?)
    }

    /// Update mapping.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError> {
        Ok(mapping::update(&state.db, id, idp).await?)
    }
}

#[cfg(test)]
mod tests {}
