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

use async_trait::async_trait;

use openstack_keystone_core_types::idmapping::*;

use crate::auth::ExecutionContext;
use crate::idmapping::IdMappingProviderError;

/// IdMapping provider API.
#[async_trait]
pub trait IdMappingApi: Send + Sync {
    /// Get the `IdMapping` by the local data.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    async fn get_by_local_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdMappingProviderError>;

    /// Get the `IdMapping` by the public identifier.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    async fn get_by_public_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdMappingProviderError>;

    /// Create a new `IdMapping`.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    /// - `public_id`: The public identifier to use. If `None`, one is
    ///   generated deterministically from `domain_id`, `entity_type` and
    ///   `local_id`.
    ///
    /// # Returns
    /// - `Result<IdMapping, IdMappingProviderError>` - The created (or
    ///   already-existing, on a benign race) `IdMapping`, or an `Error`.
    async fn create_id_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
        public_id: Option<&'a str>,
    ) -> Result<IdMapping, IdMappingProviderError>;

    /// Delete the `IdMapping` by the public identifier.
    ///
    /// Silent/idempotent if no mapping is found.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<(), IdMappingProviderError>` - `Ok` on success (including
    ///   when nothing was found), or an `Error`.
    async fn delete_id_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        public_id: &'a str,
    ) -> Result<(), IdMappingProviderError>;

    /// Delete every `IdMapping` row belonging to a domain.
    ///
    /// Called when the domain itself is deleted, so id mappings for entities
    /// it used to own on a non-default backend don't outlive it. Idempotent:
    /// deleting a domain with no mapping rows is not an error.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `domain_id`: The domain identifier.
    ///
    /// # Returns
    /// - `Result<(), IdMappingProviderError>` - `Ok` on success (including
    ///   when nothing was found), or an `Error`.
    async fn delete_mappings_for_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<(), IdMappingProviderError>;
}
