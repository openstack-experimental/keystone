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
//! # Dynamic plugin identity index provider: Backends.
use async_trait::async_trait;

use crate::dynamic_plugin_identity::error::DynamicPluginIdentityProviderError;
use crate::keystone::ServiceState;

/// Dynamic plugin identity-binding index Backend trait (ADR 0025 §4).
///
/// Backend driver interface for the `(plugin_name, external_id) -> user_id`
/// namespace-scoped mapping backing `provision_user`/`find_user`
/// (§6.B/§6.C).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DynamicPluginIdentityBackend: Send + Sync {
    /// Atomically create the `(plugin_name, external_id) -> user_id` mapping
    /// if absent, otherwise resolve the existing (canonical) `user_id`.
    ///
    /// Returns the canonical `user_id` for this `(plugin_name, external_id)`
    /// pair, which may differ from the requested `user_id` if a concurrent
    /// call already won the race.
    async fn create_or_resolve<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
        user_id: &'a str,
    ) -> Result<String, DynamicPluginIdentityProviderError>;

    /// Look up the `user_id` mapped to `(plugin_name, external_id)`, if any.
    async fn find<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<Option<String>, DynamicPluginIdentityProviderError>;

    /// Best-effort remove the `(plugin_name, external_id)` mapping (e.g. a
    /// lazily-detected stale entry pointing at a since-deleted user).
    async fn purge<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError>;

    /// Best-effort remove every mapping pointing at `user_id`, across all
    /// plugins - the proactive cleanup path invoked when the underlying
    /// Keystone user is hard-deleted (ADR 0025 orphan protection).
    async fn purge_by_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError>;
}
