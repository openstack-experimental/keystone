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

//! # IdMapping provider
//!
//! IdMapping provider provides a mapping of the entity ID between
//! Keystone and the remote system (i.e. LDAP, IdP, OpenFGA, SCIM, etc).

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::idmapping::*;

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod provider_api;
pub mod service;

use crate::idmapping::service::IdMappingService;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub use error::IdMappingProviderError;
pub use hook::IdMappingHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockIdMappingProvider;
pub use provider_api::IdMappingApi;

pub enum IdMappingProvider {
    Service(IdMappingService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockIdMappingProvider),
}

impl IdMappingProvider {
    /// Create a new `IdMappingProvider`.
    ///
    /// # Parameters
    /// - `config`: The configuration.
    /// - `plugin_manager`: The plugin manager.
    ///
    /// # Returns
    /// - `Result<Self, IdMappingProviderError>` - The new provider or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdMappingProviderError> {
        Ok(Self::Service(IdMappingService::new(
            config,
            plugin_manager,
        )?))
    }
}

#[async_trait]
impl IdMappingApi for IdMappingProvider {
    /// Get the `IdMapping` by the local data.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .get_by_local_id(state, local_id, domain_id, entity_type)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .get_by_local_id(state, local_id, domain_id, entity_type)
                    .await
            }
        }
    }

    /// Get the `IdMapping` by the public identifier.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        match self {
            Self::Service(provider) => provider.get_by_public_id(state, public_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_by_public_id(state, public_id).await,
        }
    }
}
