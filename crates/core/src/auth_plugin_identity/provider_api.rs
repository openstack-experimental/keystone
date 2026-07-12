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
//! # Dynamic plugin identity index provider API
use async_trait::async_trait;

use crate::auth::ExecutionContext;
use crate::auth_plugin_identity::error::AuthPluginIdentityProviderError;

/// Dynamic plugin identity-binding index provider interface (ADR 0025 §4).
#[async_trait]
pub trait DynamicPluginIdentityApi: Send + Sync {
    /// Atomically create the `(plugin_name, external_id) -> user_id` mapping
    /// if absent, otherwise resolve the existing (canonical) `user_id`.
    async fn create_or_resolve<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
        user_id: &'a str,
    ) -> Result<String, AuthPluginIdentityProviderError>;

    /// Look up the `user_id` mapped to `(plugin_name, external_id)`, if any.
    async fn find<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<Option<String>, AuthPluginIdentityProviderError>;

    /// Best-effort remove the `(plugin_name, external_id)` mapping.
    async fn purge<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<(), AuthPluginIdentityProviderError>;

    /// Best-effort remove every mapping pointing at `user_id`.
    async fn purge_by_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), AuthPluginIdentityProviderError>;

    /// List every `(external_id, user_id)` mapping for `plugin_name` - the
    /// enumeration primitive backing bulk revocation (ADR 0025 §4 "Bulk
    /// Revocation on Plugin Compromise").
    async fn list_by_plugin<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
    ) -> Result<Vec<(String, String)>, AuthPluginIdentityProviderError>;
}
