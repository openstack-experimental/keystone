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
//! # Mapping provider API

use async_trait::async_trait;

use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::mapping::*;

use crate::auth::ExecutionContext;
use crate::mapping::error::MappingProviderError;

/// Mapping provider interface.
#[async_trait]
pub trait MappingApi: Send + Sync {
    /// Create a mapping ruleset.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `ruleset`: The ruleset definition to create.
    ///
    /// # Returns
    /// - `Result<MappingRuleSet, MappingProviderError>` - The created
    ///   `MappingRuleSet` or an error.
    async fn create_ruleset<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        ruleset: MappingRuleSetCreate,
    ) -> Result<MappingRuleSet, MappingProviderError>;

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
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError>;

    /// Permanently delete a virtual user shadow record.
    ///
    /// Permanently removes the record from the shadow registry. Used by the
    /// archive cleanup task after the retention period expires. For immediate
    /// deactivation (preferred, preserves forensic evidence), use
    /// `disable_virtual_user` instead. Per ADR-0020 §4 §D8: deactivation
    /// (`enabled: false`) is preferred over deletion for auditability.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to delete.
    ///
    /// # Returns
    /// - `Result<(), MappingProviderError>` - Ok if successful, or an error.
    async fn delete_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

    /// Fetch a ruleset by its `(domain_id, source)` composite index.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The owning domain identifier.
    /// - `source`: The identity source.
    ///
    /// # Returns
    /// - `Result<Option<MappingRuleSet>, MappingProviderError>` - A `Result`
    ///   containing an `Option` with the `MappingRuleSet` if found, or an
    ///   error.
    async fn get_ruleset_by_source<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        source: &'a IdentitySource,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

    /// Fetch a virtual user shadow record by user ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<VirtualUser>, MappingProviderError>` - A `Result`
    ///   containing an `Option` with the `VirtualUser` if found, or an error.
    async fn get_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
    async fn list_rulesets<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError>;

    /// Mutate rules within a mapping ruleset imperatively.
    ///
    /// Applies a batch of mutations (insert, update, delete) atomically against
    /// the live ruleset, enforcing immutability protection for System Mappings.
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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError>;

    /// Disable a virtual user shadow record.
    ///
    /// Sets `enabled` to `false`. Per ADR-0020 §10.12, this triggers the token
    /// revocation pipeline: `revocation:v1:user:<user_id>`.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to disable.
    ///
    /// # Returns
    /// - `Result<VirtualUser, MappingProviderError>` - The disabled
    ///   `VirtualUser` or an error.
    async fn disable_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError>;

    /// Enable (reactivate) a virtual user shadow record.
    ///
    /// Sets `enabled` to `true`.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The deterministic ID of the virtual user to enable.
    ///
    /// # Returns
    /// - `Result<VirtualUser, MappingProviderError>` - The enabled
    ///   `VirtualUser` or an error.
    async fn enable_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError>;

    /// Authenticate a principal through the unified mapping engine.
    ///
    /// Evaluates the flattened claims map against the ruleset identified by
    /// `(domain_id, source)`, performs a shadow registry upsert, and returns
    /// an `AuthenticationResult` with `IdentityInfo::Principal` and
    /// `AuthenticationContext::Mapping`.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `req`: The mapping authentication request containing domain, source,
    ///   workload ID, and claims map.
    ///
    /// # Returns
    /// - `Result<AuthenticationResult, MappingProviderError>` - The
    ///   authentication result on success, or an error.
    async fn authenticate_by_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        req: &'a MappingAuthRequest,
    ) -> Result<AuthenticationResult, MappingProviderError>;
}
