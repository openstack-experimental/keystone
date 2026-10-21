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
//! # OAuth2 client provider hook for inter-provider events.
//!
//! Drops the per-domain OAuth2 settings when their domain is deleted, so a
//! later domain that reuses the id does not inherit the old DPoP mode.

use async_trait::async_trait;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use crate::oauth2_client::Oauth2ClientProviderError;

/// Hook that deletes the per-domain OAuth2 settings of a deleted domain.
pub struct Oauth2ClientHook {
    state: ServiceState,
}

impl Oauth2ClientHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for Oauth2ClientHook {
    async fn on_event(&self, event: &Event) {
        let (Operation::Delete, EventPayload::Domain { id }) = (&event.operation, &event.payload)
        else {
            return;
        };
        // Raft storage is not available in non-raft mode, where no settings
        // are stored.
        if let Err(e) = self
            .state
            .provider
            .get_oauth2_client_provider()
            .delete_domain_settings(&ExecutionContext::internal(&self.state), id)
            .await
            && !matches!(e, Oauth2ClientProviderError::RaftNotAvailable)
        {
            tracing::error!(
                domain_id = id,
                error = %e,
                "Failed to delete the OAuth2 settings of a deleted domain",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    async fn hook_with(client: MockOauth2ClientProvider) -> Oauth2ClientHook {
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_oauth2_client(client)),
        )
        .await;
        Oauth2ClientHook::new(state)
    }

    #[tokio::test]
    async fn test_domain_delete_removes_settings() {
        let mut client = MockOauth2ClientProvider::default();
        client
            .expect_delete_domain_settings()
            .withf(|_, domain_id| domain_id == "d1")
            .times(1)
            .returning(|_, _| Ok(()));
        let hook = hook_with(client).await;
        hook.on_event(&Event::new(
            Operation::Delete,
            EventPayload::Domain { id: "d1".into() },
        ))
        .await;
    }

    #[tokio::test]
    async fn test_other_events_are_ignored() {
        // No expectation set: any call would panic.
        let hook = hook_with(MockOauth2ClientProvider::default()).await;
        hook.on_event(&Event::new(
            Operation::Create,
            EventPayload::Domain { id: "d1".into() },
        ))
        .await;
        hook.on_event(&Event::new(
            Operation::Delete,
            EventPayload::User { id: "u1".into() },
        ))
        .await;
    }
}
