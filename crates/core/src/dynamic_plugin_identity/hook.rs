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
//! # Dynamic plugin identity provider hooks for inter-provider events.
//!
//! Closes the orphan risk a raft-backed identity index has that SCIM's
//! raft index doesn't (see `crates/core/src/dynamic_plugin_identity/mod.rs`):
//! a dynamic-plugin-provisioned user is an ordinary Keystone user reachable
//! via the generic admin delete path, so nothing but this hook purges its
//! index entries when that happens.

use async_trait::async_trait;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;

/// Hook that purges dynamic-plugin identity index entries for a user that
/// has just been hard-deleted.
pub struct DynamicPluginIdentityHook {
    state: ServiceState,
}

impl DynamicPluginIdentityHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for DynamicPluginIdentityHook {
    async fn on_event(&self, event: &Event) {
        if let (Operation::Delete, EventPayload::User { id }) = (&event.operation, &event.payload) {
            let ctx = ExecutionContext::internal(&self.state);
            if let Err(e) = self
                .state
                .provider
                .get_dynamic_plugin_identity_provider()
                .purge_by_user(&ctx, id)
                .await
            {
                tracing::warn!(
                    user_id = %id,
                    error = %e,
                    "failed to purge dynamic plugin identity index entries for deleted user"
                );
            }
        }
    }
}
