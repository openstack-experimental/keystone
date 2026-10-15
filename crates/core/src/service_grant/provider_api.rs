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
//! # Service grant provider API.

use async_trait::async_trait;

use openstack_keystone_core_types::service_grant::*;

use crate::auth::ExecutionContext;
use crate::service_grant::ServiceGrantProviderError;

/// Managing service grants (ADR 0036 §4).
#[async_trait]
pub trait ServiceGrantApi: Send + Sync {
    /// Create a grant on behalf of the authenticated caller, who becomes the
    /// grantor. Requires a security context: the grantor, its roles and
    /// whether its chain may delegate all come from it.
    async fn create_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ServiceGrantCreate,
    ) -> Result<ServiceGrant, ServiceGrantProviderError>;

    /// Hard-delete (revoke) a grant.
    async fn delete_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<(), ServiceGrantProviderError>;

    /// Fetch a grant by its `(domain_id, id)` coordinate.
    async fn get_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError>;

    /// Fetch a grant by its globally unique id.
    async fn get_service_grant_by_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError>;

    /// List grants matching every set filter.
    async fn list_service_grants<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ServiceGrantListParameters,
    ) -> Result<Vec<ServiceGrant>, ServiceGrantProviderError>;

    /// Apply a lifecycle update (disable with a reason, re-enable, record a
    /// redemption) to the grant at `expected_version`.
    async fn update_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
        update: ServiceGrantUpdate,
        expected_version: u64,
    ) -> Result<ServiceGrant, ServiceGrantProviderError>;
}
