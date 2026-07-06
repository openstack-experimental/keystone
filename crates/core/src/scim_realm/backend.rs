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
//! # SCIM realm provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::scim::*;

use crate::keystone::ServiceState;
use crate::scim_realm::error::ScimRealmProviderError;

/// SCIM realm Backend trait.
///
/// Backend driver interface expected by the SCIM realm provider.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ScimRealmBackend: Send + Sync {
    /// Register a new SCIM realm.
    async fn create(
        &self,
        state: &ServiceState,
        data: ScimRealmResourceCreate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError>;

    /// Fetch a realm by its `(domain_id, provider_id)` coordinate.
    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<ScimRealmResource>, ScimRealmProviderError>;

    /// List realms for a domain.
    async fn list(
        &self,
        state: &ServiceState,
        params: &ScimRealmResourceListParameters,
    ) -> Result<Vec<ScimRealmResource>, ScimRealmProviderError>;

    /// Update (or enable/disable) a realm.
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        data: ScimRealmResourceUpdate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError>;
}
