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
//! # SCIM resource index provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::scim::*;

use crate::auth::ExecutionContext;
use crate::plugin_manager::PluginManagerApi;
use crate::scim_resource::{
    ScimResourceApi, backend::ScimResourceBackend, error::ScimResourceProviderError,
};

/// SCIM resource index Provider.
pub struct ScimResourceService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn ScimResourceBackend>,
}

impl ScimResourceService {
    /// Create a new `ScimResourceService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ScimResourceProviderError> {
        let backend_driver = plugin_manager
            .get_scim_resource_backend(config.scim_resource.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `ScimResourceService` from a backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: ScimResourceBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

#[async_trait]
impl ScimResourceApi for ScimResourceService {
    async fn create_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ScimResourceIndexCreate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        self.backend_driver.create(ctx.state(), data).await
    }

    async fn get_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .get(
                ctx.state(),
                domain_id,
                provider_id,
                resource_type,
                keystone_id,
            )
            .await
    }

    async fn get_index_by_external_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        external_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .get_by_external_id(
                ctx.state(),
                domain_id,
                provider_id,
                resource_type,
                external_id,
            )
            .await
    }

    async fn list_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
    ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .list(ctx.state(), domain_id, provider_id, resource_type)
            .await
    }

    async fn update_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
        data: ScimResourceIndexUpdate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        self.backend_driver
            .update(
                ctx.state(),
                domain_id,
                provider_id,
                resource_type,
                keystone_id,
                data,
            )
            .await
    }
}
