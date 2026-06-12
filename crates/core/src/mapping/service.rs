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
//! # Mapping provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::mapping::*;

use crate::keystone::ServiceState;
use crate::mapping::{MappingApi, MappingProviderError, backend::MappingBackend};
use crate::plugin_manager::PluginManagerApi;

/// Mapping Provider service.
pub struct MappingService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn MappingBackend>,
}

impl MappingService {
    /// Create a new `MappingService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, MappingProviderError> {
        let backend_driver = plugin_manager
            .get_mapping_backend(config.mapping.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl MappingApi for MappingService {
    /// Create a mapping ruleset.
    async fn create_ruleset(
        &self,
        state: &ServiceState,
        ruleset: MappingRuleSetCreate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        self.backend_driver.create_ruleset(state, ruleset).await
    }

    /// Delete a mapping ruleset.
    async fn delete_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        self.backend_driver.delete_ruleset(state, mapping_id).await
    }

    /// Delete a virtual user shadow record.
    async fn delete_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        self.backend_driver
            .delete_virtual_user(state, user_id)
            .await
    }

    /// Fetch a mapping ruleset by ID.
    async fn get_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        self.backend_driver.get_ruleset(state, mapping_id).await
    }

    /// Fetch a virtual user shadow record by user ID.
    async fn get_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError> {
        self.backend_driver.get_virtual_user(state, user_id).await
    }

    /// List mapping rulesets.
    async fn list_rulesets(
        &self,
        state: &ServiceState,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError> {
        self.backend_driver.list_rulesets(state, params).await
    }

    /// Mutate rules within a mapping ruleset imperatively.
    async fn mutate_rules<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        mutations: RuleMutations,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        self.backend_driver
            .mutate_rules(state, mapping_id, mutations)
            .await
    }

    /// Update a mapping ruleset.
    async fn update_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        self.backend_driver
            .update_ruleset(state, mapping_id, data)
            .await
    }
}
