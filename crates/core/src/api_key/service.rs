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
//! # API Key provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::api_key::*;

use crate::api_key::{ApiKeyApi, ApiKeyProviderError, backend::ApiKeyBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

/// API Key Provider.
pub struct ApiKeyService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn ApiKeyBackend>,
}

impl ApiKeyService {
    /// Create a new `ApiKeyService`.
    ///
    /// # Arguments
    /// * `config` - Reference to the [`Config`].
    /// * `plugin_manager` - Reference to the [`PluginManagerApi`].
    ///
    /// # Returns
    /// * Success with a new `ApiKeyService` instance.
    /// * `ApiKeyProviderError` if the backend driver cannot be loaded.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ApiKeyProviderError> {
        let backend_driver = plugin_manager
            .get_api_key_backend(config.api_key.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ApiKeyApi for ApiKeyService {
    async fn create(
        &self,
        state: &ServiceState,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        self.backend_driver.create(state, data).await
    }

    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver
            .get_by_client_id(state, domain_id, client_id)
            .await
    }

    async fn get_by_lookup_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver
            .get_by_lookup_hash(state, domain_id, lookup_hash)
            .await
    }

    async fn list(
        &self,
        state: &ServiceState,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver.list(state, params).await
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        self.backend_driver
            .update(state, domain_id, client_id, data)
            .await
    }

    async fn revoke<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        self.backend_driver
            .revoke(state, domain_id, client_id, revoked_by)
            .await
    }

    async fn update_last_used<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        last_used_at: i64,
    ) -> Result<(), ApiKeyProviderError> {
        self.backend_driver
            .update_last_used(state, domain_id, lookup_hash, last_used_at)
            .await
    }

    async fn update_secret_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        secret_hash: String,
    ) -> Result<(), ApiKeyProviderError> {
        self.backend_driver
            .update_secret_hash(state, domain_id, lookup_hash, secret_hash)
            .await
    }
}
