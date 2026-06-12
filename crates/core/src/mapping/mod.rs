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

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::mapping::*;

pub mod backend;
pub mod error;
pub mod hook;
mod interpolation;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod provider_api;
pub mod service;
mod validation;
mod version;

use crate::keystone::ServiceState;
use crate::mapping::service::MappingService;
use crate::plugin_manager::PluginManagerApi;

pub use backend::MappingBackend;
pub use error::MappingProviderError;
pub use hook::MappingHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockMappingProvider;
pub use provider_api::MappingApi;
pub use validation::{validate_regex, validate_ruleset_create, validate_ruleset_update};

pub enum MappingProvider {
    Service(MappingService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockMappingProvider),
}

impl MappingProvider {
    /// Create a new `MappingProvider`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, MappingProviderError> {
        Ok(Self::Service(MappingService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl MappingApi for MappingProvider {
    /// Create a mapping ruleset.
    async fn create_ruleset(
        &self,
        state: &ServiceState,
        ruleset: MappingRuleSetCreate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.create_ruleset(state, ruleset).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_ruleset(state, ruleset).await,
        }
    }

    /// Delete a mapping ruleset.
    async fn delete_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        match self {
            Self::Service(provider) => provider.delete_ruleset(state, mapping_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_ruleset(state, mapping_id).await,
        }
    }

    /// Delete a virtual user shadow record.
    async fn delete_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        match self {
            Self::Service(provider) => provider.delete_virtual_user(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_virtual_user(state, user_id).await,
        }
    }

    /// Fetch a mapping ruleset by ID.
    async fn get_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.get_ruleset(state, mapping_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_ruleset(state, mapping_id).await,
        }
    }

    /// Fetch a virtual user shadow record by user ID.
    async fn get_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.get_virtual_user(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_virtual_user(state, user_id).await,
        }
    }

    /// List mapping rulesets.
    async fn list_rulesets(
        &self,
        state: &ServiceState,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.list_rulesets(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_rulesets(state, params).await,
        }
    }

    /// Mutate rules within a mapping ruleset imperatively.
    async fn mutate_rules<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        mutations: RuleMutations,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.mutate_rules(state, mapping_id, mutations).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.mutate_rules(state, mapping_id, mutations).await,
        }
    }

    /// Update a mapping ruleset.
    async fn update_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        match self {
            Self::Service(provider) => provider.update_ruleset(state, mapping_id, data).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.update_ruleset(state, mapping_id, data).await,
        }
    }
}
