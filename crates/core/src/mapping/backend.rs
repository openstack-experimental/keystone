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
//! # Mapping provider: Backends.

use async_trait::async_trait;

use openstack_keystone_core_types::mapping::*;

use crate::keystone::ServiceState;
use crate::mapping::error::MappingProviderError;

/// Mapping Backend trait.
///
/// Backend driver interface expected by the mapping provider.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait MappingBackend: Send + Sync {
    /// Create a mapping ruleset.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `ruleset`: The ruleset definition to create.
    ///
    /// # Returns
    /// - `Result<MappingRuleSet, MappingProviderError>` - The created
    ///   `MappingRuleSet` or an error.
    async fn create_ruleset(
        &self,
        state: &ServiceState,
        ruleset: MappingRuleSetCreate,
    ) -> Result<MappingRuleSet, MappingProviderError>;

    /// Create a virtual user shadow record.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `metadata`: The virtual user metadata to persist.
    ///
    /// # Returns
    /// - `Result<VirtualUser, MappingProviderError>` - The created
    ///   `VirtualUser` or an error.
    async fn create_virtual_user(
        &self,
        state: &ServiceState,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, MappingProviderError>;

    /// Delete a mapping ruleset.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `mapping_id`: The ID of the ruleset to delete.
    ///
    /// # Returns
    /// - `Result<(), MappingProviderError>` - Ok if successful, or an error.
    async fn delete_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError>;

    /// Delete a virtual user shadow record.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to delete.
    ///
    /// # Returns
    /// - `Result<(), MappingProviderError>` - Ok if successful, or an error.
    async fn delete_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError>;

    /// Fetch a mapping ruleset by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `mapping_id`: The ID of the ruleset to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<MappingRuleSet>, MappingProviderError>` - A `Result`
    ///   containing an `Option` with the `MappingRuleSet` if found, or an
    ///   error.
    async fn get_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

    /// Fetch a virtual user shadow record by user ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<VirtualUser>, MappingProviderError>` - A
    ///   `Result` containing an `Option` with the `VirtualUser` if
    ///   found, or an error.
    async fn get_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError>;

    /// List mapping rulesets.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for rulesets.
    ///
    /// # Returns
    /// - `Result<Vec<MappingRuleSet>, MappingProviderError>` - A list of
    ///   `MappingRuleSet` entries or an error.
    async fn list_rulesets(
        &self,
        state: &ServiceState,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError>;

    /// List virtual user shadow records.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for virtual users.
    ///
    /// # Returns
    /// - `Result<Vec<VirtualUser>, MappingProviderError>` - A list of
    ///   `VirtualUser` entries or an error.
    async fn list_virtual_users(
        &self,
        state: &ServiceState,
        params: &VirtualUserListParameters,
    ) -> Result<Vec<VirtualUser>, MappingProviderError>;

    /// Mutate rules within a mapping ruleset imperatively.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `mapping_id`: The ID of the ruleset to mutate.
    /// - `mutations`: The ordered batch of `RuleMutation` operations.
    ///
    /// # Returns
    /// - `Result<MappingRuleSet, MappingProviderError>` - The updated
    ///   `MappingRuleSet` with mutations applied, or an error.
    async fn mutate_rules<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        mutations: RuleMutations,
    ) -> Result<MappingRuleSet, MappingProviderError>;

    /// Update a mapping ruleset.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `mapping_id`: The ID of the ruleset to update.
    /// - `data`: The update details for the ruleset.
    ///
    /// # Returns
    /// - `Result<MappingRuleSet, MappingProviderError>` - The updated
    ///   `MappingRuleSet` or an error.
    async fn update_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError>;

    /// Update a virtual user shadow record.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to update.
    /// - `metadata`: The updated virtual user metadata.
    ///
    /// # Returns
    /// - `Result<VirtualUser, MappingProviderError>` - The updated
    ///   `VirtualUser` or an error.
    async fn update_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, MappingProviderError>;
}
