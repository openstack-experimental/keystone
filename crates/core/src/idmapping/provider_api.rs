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
}
