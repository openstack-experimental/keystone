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
//! # Service grant provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::service_grant::*;

use crate::keystone::ServiceState;
use crate::service_grant::ServiceGrantProviderError;

/// Service grant Backend trait (ADR 0036 §4).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ServiceGrantBackend: Send + Sync {
    /// Count grants on a project, optionally only those of one grantee.
    async fn count_service_grants<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        grantee_client_id: Option<&'a str>,
    ) -> Result<usize, ServiceGrantProviderError>;

    /// Persist a new grant. `id` and `domain_id` are set by the caller.
    async fn create_service_grant(
        &self,
        state: &ServiceState,
        grant: ServiceGrant,
    ) -> Result<ServiceGrant, ServiceGrantProviderError>;

    /// Hard-delete a grant and its index entries.
    async fn delete_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<(), ServiceGrantProviderError>;

    /// Fetch a grant by its `(domain_id, id)` coordinate.
    async fn get_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError>;

    /// Fetch a grant by its globally unique id, whatever its domain.
    async fn get_service_grant_by_id<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError>;

    /// List grants matching every set filter, ordered by id.
    async fn list_service_grants(
        &self,
        state: &ServiceState,
        params: &ServiceGrantListParameters,
    ) -> Result<Vec<ServiceGrant>, ServiceGrantProviderError>;

    /// Apply a lifecycle update. Fails with `Conflict` when the stored
    /// version is not `expected_version`.
    async fn update_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
        update: ServiceGrantUpdate,
        expected_version: u64,
    ) -> Result<ServiceGrant, ServiceGrantProviderError>;
}
