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

//! # Domain configuration provider service

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::domain_config::*;

use crate::domain_config::api::DomainConfigApi;
use crate::domain_config::backend::DomainConfigBackend;
use crate::domain_config::error::DomainConfigProviderError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

/// The backend source the configuration API reads and writes.
///
/// python-keystone's domain config API always targets the database, whatever
/// `[identity] domain_configurations_from_database` is set to -- that switch
/// only decides whether the *identity manager* consults the stored
/// configuration. The file source (`fs`) is operator-managed on disk and never
/// written through the API.
const API_BACKEND: &str = "sql";

/// Domain configuration provider service.
///
/// A thin pass-through to the `sql` domain-config backend; every method
/// forwards verbatim.
pub struct DomainConfigService {
    backend_driver: Arc<dyn DomainConfigBackend>,
}

impl DomainConfigService {
    /// Create a new `DomainConfigService`.
    ///
    /// # Parameters
    /// - `_config`: The service configuration (unused: the API backend is
    ///   always `sql`).
    /// - `plugin_manager`: The plugin manager used to resolve the backend
    ///   driver.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The initialized service,
    ///   or [`DomainConfigProviderError::UnsupportedDriver`] when the `sql`
    ///   backend is not registered.
    pub fn new<P: PluginManagerApi>(
        _config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, DomainConfigProviderError> {
        let backend_driver = plugin_manager
            .get_domain_config_backend(API_BACKEND)?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl DomainConfigApi for DomainConfigService {
    async fn create_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        self.backend_driver
            .create_domain_config(state, domain_id, config)
            .await
    }

    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config(state, domain_id)
            .await
    }

    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config_group(state, domain_id, group)
            .await
    }

    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config_option(state, domain_id, group, option)
            .await
    }

    async fn update_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        self.backend_driver
            .update_domain_config(state, domain_id, config)
            .await
    }

    async fn update_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        self.backend_driver
            .update_domain_config_group(state, domain_id, group, config)
            .await
    }

    async fn update_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError> {
        self.backend_driver
            .update_domain_config_option(state, domain_id, option)
            .await
    }

    async fn delete_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config(state, domain_id)
            .await
    }

    async fn delete_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config_group(state, domain_id, group)
            .await
    }

    async fn delete_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config_option(state, domain_id, group, option)
            .await
    }

    async fn get_default_config(
        &self,
        state: &ServiceState,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        self.backend_driver.get_default_config(state).await
    }

    async fn get_default_group(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        self.backend_driver.get_default_group(state, group).await
    }

    async fn get_default_option<'a>(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        self.backend_driver
            .get_default_option(state, group, option)
            .await
    }
}
