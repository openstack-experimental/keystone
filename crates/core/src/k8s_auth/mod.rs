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
//! # Kubernetes authentication.

use async_trait::async_trait;

use std::sync::Arc;

mod auth;
pub mod backend;
mod client;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

pub use client::K8sHttpClient;
pub use error::K8sAuthProviderError;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::k8s_auth::*;

use crate::auth::AuthenticationResult;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
pub use hook::K8sAuthHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockK8sAuthProvider;
pub use provider_api::K8sAuthApi;

use service::K8sAuthService;

/// K8s Auth provider.
pub enum K8sAuthProvider {
    Service(K8sAuthService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockK8sAuthProvider),
}

impl K8sAuthProvider {
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
        http_client: Arc<dyn K8sHttpClient>,
    ) -> Result<Self, K8sAuthProviderError> {
        Ok(Self::Service(K8sAuthService::new(
            config,
            plugin_manager,
            http_client,
        )?))
    }
}

#[async_trait]
impl K8sAuthApi for K8sAuthProvider {
    /// Authenticate via K8s TokenReview + mapping engine.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    ///
    /// # Returns
    /// * Success with [`AuthenticationResult`] via mapping engine.
    /// * `K8sAuthProviderError` if authentication fails.
    async fn authenticate_by_k8s_mapping(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<AuthenticationResult, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.authenticate_by_k8s_mapping(state, req).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.authenticate_by_k8s_mapping(state, req).await,
        }
    }

    /// Register new K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `instance` - [`K8sAuthInstanceCreate`] data for the new instance.
    ///
    /// # Returns
    /// * Success with the created [`K8sAuthInstance`].
    /// * `K8sAuthProviderError` if the instance could not be created.
    #[tracing::instrument(skip(self, state))]
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        instance: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.create_auth_instance(state, instance).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_auth_instance(state, instance).await,
        }
    }

    /// Delete K8s auth provider.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to delete.
    ///
    /// # Returns
    /// * Success if the instance was deleted.
    /// * `K8sAuthProviderError` if the deletion failed.
    #[tracing::instrument(skip(self, state))]
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.delete_auth_instance(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_auth_instance(state, id).await,
        }
    }

    /// Get K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`K8sAuthInstance`] if found,
    /// or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.get_auth_instance(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_auth_instance(state, id).await,
        }
    }

    /// List K8s auth instances.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthInstanceListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthInstance`].
    /// * `K8sAuthProviderError` if the listing failed.
    #[tracing::instrument(skip(self, state))]
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.list_auth_instances(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_auth_instances(state, params).await,
        }
    }

    /// Update K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to update.
    /// * `data` - [`K8sAuthInstanceUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`K8sAuthInstance`].
    /// * `K8sAuthProviderError` if the update failed.
    #[tracing::instrument(skip(self, state))]
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.update_auth_instance(state, id, data).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_auth_instance(state, id, data).await,
        }
    }
}
