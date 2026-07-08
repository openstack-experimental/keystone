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
//! # Dynamic plugin identity index provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;

use crate::auth::ExecutionContext;
use crate::dynamic_plugin_identity::{
    DynamicPluginIdentityApi, backend::DynamicPluginIdentityBackend,
    error::DynamicPluginIdentityProviderError,
};
use crate::plugin_manager::PluginManagerApi;

/// Dynamic plugin identity index Provider.
pub struct DynamicPluginIdentityService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn DynamicPluginIdentityBackend>,
}

impl DynamicPluginIdentityService {
    /// Create a new `DynamicPluginIdentityService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, DynamicPluginIdentityProviderError> {
        let backend_driver = plugin_manager
            .get_dynamic_plugin_identity_backend(config.dynamic_plugin_identity.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `DynamicPluginIdentityService` from a backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: DynamicPluginIdentityBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

#[async_trait]
impl DynamicPluginIdentityApi for DynamicPluginIdentityService {
    async fn create_or_resolve<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
        user_id: &'a str,
    ) -> Result<String, DynamicPluginIdentityProviderError> {
        self.backend_driver
            .create_or_resolve(ctx.state(), plugin_name, external_id, user_id)
            .await
    }

    async fn find<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<Option<String>, DynamicPluginIdentityProviderError> {
        self.backend_driver
            .find(ctx.state(), plugin_name, external_id)
            .await
    }

    async fn purge<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError> {
        self.backend_driver
            .purge(ctx.state(), plugin_name, external_id)
            .await
    }

    async fn purge_by_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError> {
        self.backend_driver
            .purge_by_user(ctx.state(), user_id)
            .await
    }
}
