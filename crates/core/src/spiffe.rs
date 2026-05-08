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
//! # SPIFFE identity management

use async_trait::async_trait;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::spiffe::*;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub use crate::spiffe::service::SpiffeService;
pub use error::SpiffeProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockSpiffeProvider;
pub use provider_api::SpiffeApi;

/// Spiffe provider.
pub enum SpiffeProvider {
    Service(SpiffeService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockSpiffeProvider),
}

impl SpiffeProvider {
    /// Create a new `K8sAuthProvider`.
    ///
    /// # Arguments
    /// * `config` - Reference to the [`Config`].
    /// * `plugin_manager` - Reference to the [`PluginManagerApi`].
    ///
    /// # Returns
    /// * Success with a new `K8sAuthProvider` instance.
    /// * `K8sAuthProviderError` if the service could not be initialized.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, SpiffeProviderError> {
        Ok(Self::Service(SpiffeService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl SpiffeApi for SpiffeProvider {
    /// Register new binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `binding` - [`SpiffeBindingCreate`] data for the new binding.
    ///
    /// # Returns
    /// * Success with the created [`SpiffeBinding`].
    /// * Error if the instance could not be created.
    async fn create_binding(
        &self,
        state: &ServiceState,
        binding: SpiffeBindingCreate,
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        match self {
            Self::Service(provider) => provider.create_binding(state, binding).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_binding(state, binding).await,
        }
    }

    /// Delete SPIFFE binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID of a binding to delete.
    ///
    /// # Returns
    /// * Success if the binding was deleted.
    /// * Error if the deletion failed.
    async fn delete_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<(), SpiffeProviderError> {
        match self {
            Self::Service(provider) => provider.delete_binding(state, svid).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_binding(state, svid).await,
        }
    }

    /// Fetch binding for the SVID.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID identifier to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`SpiffeBinding`] if found,
    /// or an `Error`.
    async fn get_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<Option<SpiffeBinding>, SpiffeProviderError> {
        match self {
            Self::Service(provider) => provider.get_binding(state, svid).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_binding(state, svid).await,
        }
    }

    /// List SpiffeBindings.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`SpiffeBindingListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`SpiffeBinding`].
    /// * Error if the listing failed.
    async fn list_bindings(
        &self,
        state: &ServiceState,
        params: &SpiffeBindingListParameters,
    ) -> Result<Vec<SpiffeBinding>, SpiffeProviderError> {
        match self {
            Self::Service(provider) => provider.list_bindings(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_bindings(state, params).await,
        }
    }

    /// Update binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The SVID for the binding to update.
    /// * `data` - [`SpiffeBindingUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`SpiffeBinding`].
    /// * Error if the update failed.
    async fn update_binding<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: SpiffeBindingUpdate,
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        match self {
            Self::Service(provider) => provider.update_binding(state, id, data).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_binding(state, id, data).await,
        }
    }
}
