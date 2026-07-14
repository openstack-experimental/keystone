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
//! # OAuth2 signing key provider hook for inter-provider events.

use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use async_trait::async_trait;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;

/// Hook that ensures OAuth2 signing keys are provisioned when a domain is
/// created.
pub struct Oauth2KeyHook {
    state: ServiceState,
}

impl Oauth2KeyHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for Oauth2KeyHook {
    async fn on_event(&self, event: &Event) {
        let (Operation::Create, EventPayload::Domain { id }) = (&event.operation, &event.payload)
        else {
            return;
        };

        // Raft storage may not be available in non-raft mode; keys are
        // only needed when the JWS token provider is active.
        if let Err(e) = self
            .state
            .provider
            .get_oauth2_key_provider()
            .ensure_domain_keys(&self.state, id)
            .await
            && !matches!(e, Oauth2KeyProviderError::RaftNotAvailable)
        {
            tracing::error!(
                domain_id = id,
                error = %e,
                "Failed to ensure OAuth2 keys for newly created domain",
            );
        }
    }
}
