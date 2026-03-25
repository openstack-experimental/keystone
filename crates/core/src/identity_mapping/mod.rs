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

//! # Identity mapping provider
//!
//! Identity mapping provider provides a mapping of the entity ID between
//! Keystone and the remote system (i.e. LDAP, IdP, OpenFGA, SCIM, etc).

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::identity_mapping::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod provider_api;
pub mod service;

use crate::identity_mapping::service::IdentityMappingService;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub use error::IdentityMappingProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockIdentityMappingProvider;
pub use provider_api::IdentityMappingApi;

pub enum IdentityMappingProvider {
    Service(IdentityMappingService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockIdentityMappingProvider),
}

impl IdentityMappingProvider {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdentityMappingProviderError> {
        Ok(Self::Service(IdentityMappingService::new(
            config,
            plugin_manager,
        )?))
    }
}

#[async_trait]
impl IdentityMappingApi for IdentityMappingProvider {
    /// Get the `IdMapping` by the local data.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
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

    /// Get the IdMapping by the public_id.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
        match self {
            Self::Service(provider) => provider.get_by_public_id(state, public_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_by_public_id(state, public_id).await,
        }
    }
}
