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

use crate::identity_mapping::IdentityMappingError;
use crate::identity_mapping::types::id_mapping::*;
use crate::keystone::ServiceState;

/// IdMapping provider API.
#[async_trait]
pub trait IdentityMappingApi {
    /// Get the `IdMapping` by the local data.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdentityMappingError>;

    /// Get the IdMapping by the public_id.
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdentityMappingError>;
}
