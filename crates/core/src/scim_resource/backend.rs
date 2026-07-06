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
//! # SCIM resource index provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::scim::*;

use crate::keystone::ServiceState;
use crate::scim_resource::error::ScimResourceProviderError;

/// SCIM resource ownership index Backend trait.
///
/// Backend driver interface expected by the SCIM resource index provider
/// (ADR 0024 §3.A).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ScimResourceBackend: Send + Sync {
    /// Anchor a newly-created SCIM resource.
    async fn create(
        &self,
        state: &ServiceState,
        data: ScimResourceIndexCreate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError>;

    /// Fetch the ownership anchor for `(domain_id, provider_id, type, id)`
    /// (ADR 0024 §3.C step 1).
    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError>;

    /// Fetch the ownership anchor by its realm-scoped `externalId` (ADR 0024
    /// §3.C last paragraph).
    async fn get_by_external_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        external_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError>;

    /// List all anchors owned by a realm for a given resource type.
    async fn list<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
    ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError>;

    /// Apply a partial update (e.g. soft-disable, `externalId` change).
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
        data: ScimResourceIndexUpdate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError>;
}
