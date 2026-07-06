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
//! # SCIM realm provider API

use async_trait::async_trait;

use openstack_keystone_core_types::scim::*;

use crate::auth::ExecutionContext;
use crate::scim_realm::error::ScimRealmProviderError;

/// SCIM realm provider interface (ADR 0024 §2).
#[async_trait]
pub trait ScimRealmApi: Send + Sync {
    /// Register a new SCIM realm.
    async fn create_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ScimRealmResourceCreate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError>;

    /// Fetch a realm by its `(domain_id, provider_id)` coordinate. Used by
    /// the Realm Activation Gate (ADR 0024 §2.B) on every SCIM resource
    /// request.
    async fn get_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<ScimRealmResource>, ScimRealmProviderError>;

    /// List realms registered for a domain.
    async fn list_realms<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ScimRealmResourceListParameters,
    ) -> Result<Vec<ScimRealmResource>, ScimRealmProviderError>;

    /// Update (including enable/disable) a realm.
    async fn update_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        data: ScimRealmResourceUpdate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError>;
}
