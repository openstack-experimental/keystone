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

use crate::idmapping::IdMappingProviderError;
use crate::keystone::ServiceState;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IdMappingBackend: Send + Sync {
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
        state: &ServiceState,
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
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdMappingProviderError>;

    /// Create a new `IdMapping`.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    /// - `public_id`: The public identifier to store the mapping under.
    ///
    /// # Returns
    /// - `Result<IdMapping, IdMappingProviderError>` - The created (or, on a
    ///   benign race with a concurrent creator of the same local entity,
    ///   already-existing) `IdMapping`, or an `Error`.
    async fn create_id_mapping<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
        public_id: &'a str,
    ) -> Result<IdMapping, IdMappingProviderError>;

    /// Delete the `IdMapping` by the public identifier.
    ///
    /// Silent/idempotent if no mapping is found.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<(), IdMappingProviderError>` - `Ok` on success (including
    ///   when nothing was found), or an `Error`.
    async fn delete_id_mapping<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<(), IdMappingProviderError>;
}
