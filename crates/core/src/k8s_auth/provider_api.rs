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
//! # K8s Auth interface.

use async_trait::async_trait;

use openstack_keystone_core_types::k8s_auth::*;

use crate::auth::AuthenticationResult;
use crate::k8s_auth::K8sAuthProviderError;
use crate::keystone::ServiceState;

/// The trait for managing the K8s_auth functionality.
#[async_trait]
pub trait K8sAuthApi: Send + Sync {
    /// Authenticate (exchange) the K8s Service account token.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    ///
    /// # Returns
    /// * Success with the [`AuthenticatedInfo`] and [`TokenRestriction`].
    /// * Error if authentication fails.
    async fn authenticate_by_k8s_sa_token(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<AuthenticationResult, K8sAuthProviderError>;

    /// Register new K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `config` - [`K8sAuthInstanceCreate`] data for the new instance.
    ///
    /// # Returns
    /// * Success with the created [`K8sAuthInstance`].
    /// * Error if the instance could not be created.
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        config: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

    /// Register new K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `role` - [`K8sAuthRoleCreate`] data for the new role.
    ///
    /// # Returns
    /// * Success with the created [`K8sAuthRole`].
    /// * Error if the role could not be created.
    async fn create_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError>;

    /// Delete K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to delete.
    ///
    /// # Returns
    /// * Success if the instance was deleted.
    /// * Error if the deletion failed.
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError>;

    /// Delete K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to delete.
    ///
    /// # Returns
    /// * Success if the role was deleted.
    /// * Error if the deletion failed.
    async fn delete_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError>;

    /// Fetch auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`K8sAuthInstance`] if found,
    /// or an `Error`.
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError>;

    /// Fetch auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`K8sAuthRole`] if found, or
    /// an `Error`.
    async fn get_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError>;

    /// List K8s auth instances.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthInstanceListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthInstance`].
    /// * Error if the listing failed.
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError>;

    /// List K8s auth roles.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthRoleListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthRole`].
    /// * Error if the listing failed.
    async fn list_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError>;

    /// Update K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to update.
    /// * `data` - [`K8sAuthInstanceUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`K8sAuthInstance`].
    /// * Error if the update failed.
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

    /// Update K8s auth role.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the role to update.
    /// * `data` - [`K8sAuthRoleUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`K8sAuthRole`].
    /// * Error if the update failed.
    async fn update_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError>;
}
