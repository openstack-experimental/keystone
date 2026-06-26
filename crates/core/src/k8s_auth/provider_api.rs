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
use crate::auth::ExecutionContext;
use crate::k8s_auth::K8sAuthProviderError;

/// The trait for managing the K8s_auth functionality.
#[async_trait]
pub trait K8sAuthApi: Send + Sync {
    /// Authenticate via K8s TokenReview + mapping engine.
    ///
    /// Validates the JWT through the K8s TokenReview API, flattens the
    /// response into claims, and delegates to the unified mapping engine
    /// for identity resolution and shadow registry upsert.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    ///
    /// # Returns
    /// * Success with [`AuthenticationResult`] via mapping engine.
    /// * `K8sAuthProviderError` if authentication fails.
    async fn authenticate_by_k8s_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
    async fn create_auth_instance<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        config: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError>;

    /// List K8s auth instances.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthInstanceListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthInstance`].
    /// * Error if the listing failed.
    async fn list_auth_instances<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError>;

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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError>;
}
