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
//! # Mapping provider - internal mocking tools.
use async_trait::async_trait;
use mockall::mock;

use openstack_keystone_core_types::mapping::*;

use crate::keystone::ServiceState;
use crate::mapping::{MappingApi, error::MappingProviderError};

mock! {
    pub MappingProvider {}

    #[async_trait]
    impl MappingApi for MappingProvider {
        /// Create a mapping ruleset.
        async fn create_ruleset(
            &self,
            state: &ServiceState,
            ruleset: MappingRuleSetCreate,
        ) -> Result<MappingRuleSet, MappingProviderError>;

        /// Delete a mapping ruleset.
        async fn delete_ruleset<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
        ) -> Result<(), MappingProviderError>;

        /// Delete a virtual user shadow record.
        async fn delete_virtual_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<(), MappingProviderError>;

        /// Fetch a mapping ruleset by ID.
        async fn get_ruleset<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
        ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

        /// Fetch a virtual user shadow record by user ID.
        async fn get_virtual_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<VirtualUser>, MappingProviderError>;

        /// List mapping rulesets.
        async fn list_rulesets(
            &self,
            state: &ServiceState,
            params: &MappingRuleSetListParameters,
        ) -> Result<Vec<MappingRuleSet>, MappingProviderError>;

        /// Mutate rules within a mapping ruleset imperatively.
        async fn mutate_rules<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
            mutations: RuleMutations,
        ) -> Result<MappingRuleSet, MappingProviderError>;

        /// Update a mapping ruleset.
        async fn update_ruleset<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
            data: MappingRuleSetUpdate,
        ) -> Result<MappingRuleSet, MappingProviderError>;
    }
}
