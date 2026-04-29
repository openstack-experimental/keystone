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

mod auth;
pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;
mod types;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::k8s_auth::*;
use openstack_keystone_core_types::token::TokenRestriction;

use crate::auth::AuthenticatedInfo;
use crate::k8s_auth::service::K8sAuthService;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub use error::K8sAuthProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockK8sAuthProvider;
pub use provider_api::K8sAuthApi;

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
    ) -> Result<Self, K8sAuthProviderError> {
        Ok(Self::Service(K8sAuthService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl K8sAuthApi for K8sAuthProvider {
    /// Authenticate (exchange) the K8s Service account token.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    ///
    /// # Returns
    /// * Success with the [`AuthenticatedInfo`] and [`TokenRestriction`].
    /// * `K8sAuthProviderError` if authentication fails.
    async fn authenticate_by_k8s_sa_token(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<(AuthenticatedInfo, TokenRestriction), K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.authenticate_by_k8s_sa_token(state, req).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.authenticate_by_k8s_sa_token(state, req).await,
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

    /// Register new K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `role` - [`K8sAuthRoleCreate`] data for the new role.
    ///
    /// # Returns
    /// * Success with the created [`K8sAuthRole`].
    /// * `K8sAuthProviderError` if the role could not be created.
    #[tracing::instrument(skip(self, state))]
    async fn create_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.create_auth_role(state, role).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_auth_role(state, role).await,
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

    /// Delete K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to delete.
    ///
    /// # Returns
    /// * Success if the role was deleted.
    /// * `K8sAuthProviderError` if the deletion failed.
    #[tracing::instrument(skip(self, state))]
    async fn delete_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.delete_auth_role(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_auth_role(state, id).await,
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

    /// Get K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`K8sAuthRole`] if found, or
    /// an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn get_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.get_auth_role(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_auth_role(state, id).await,
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

    /// List K8s auth roles.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthRoleListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthRole`].
    /// * `K8sAuthProviderError` if the listing failed.
    #[tracing::instrument(skip(self, state))]
    async fn list_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.list_auth_roles(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_auth_roles(state, params).await,
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

    /// Update K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to update.
    /// * `data` - [`K8sAuthRoleUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`K8sAuthRole`].
    /// * `K8sAuthProviderError` if the update failed.
    #[tracing::instrument(skip(self, state))]
    async fn update_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        match self {
            Self::Service(provider) => provider.update_auth_role(state, id, data).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_auth_role(state, id, data).await,
        }
    }
}
