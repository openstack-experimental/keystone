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
//! Drops the per-domain OAuth2 settings and deletes the clients of a deleted
//! domain. The settings must go so a later domain that reuses the id does not
//! inherit the old DPoP mode. The clients must go because nothing can list
//! them once the domain is gone, while their `spiffe_ids` keep blocking every
//! other client from claiming the same identity.

use async_trait::async_trait;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use crate::oauth2_client::Oauth2ClientProviderError;
use openstack_keystone_core_types::oauth2_client::OAuth2ClientResourceListParameters;

/// Hook that deletes the OAuth2 settings and clients of a deleted domain.
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
        let provider = self.state.provider.get_oauth2_client_provider();
        let ctx = ExecutionContext::internal(&self.state);

        // Raft storage is not available in non-raft mode, where nothing is
        // stored.
        match provider
            .list(
                &ctx,
                &OAuth2ClientResourceListParameters {
                    domain_id: id.clone(),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(clients) => {
                for client in clients.into_iter().filter(|c| c.deleted_at.is_none()) {
                    if let Err(e) = provider.delete(&ctx, id, &client.provider_id).await {
                        tracing::error!(
                            domain_id = id,
                            provider_id = client.provider_id,
                            error = %e,
                            "Failed to delete an OAuth2 client of a deleted domain",
                        );
                    }
                }
            }
            Err(Oauth2ClientProviderError::RaftNotAvailable) => {}
            Err(e) => tracing::error!(
                domain_id = id,
                error = %e,
                "Failed to list the OAuth2 clients of a deleted domain",
            ),
        }

        if let Err(e) = provider.delete_domain_settings(&ctx, id).await
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

    use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;

    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    fn sample_client(provider_id: &str, deleted_at: Option<i64>) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: format!("id-{provider_id}"),
            provider_id: provider_id.into(),
            domain_id: "d1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at,
            name: provider_id.into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
            dpop_bound_access_tokens: false,
        }
    }

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
        client.expect_list().returning(|_, _| Ok(vec![]));
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
    async fn test_domain_delete_removes_live_clients_only() {
        let live = sample_client("live", None);
        let gone = sample_client("gone", Some(1));
        let mut provider = MockOauth2ClientProvider::default();
        provider
            .expect_list()
            .withf(|_, params| params.domain_id == "d1")
            .returning(move |_, _| Ok(vec![live.clone(), gone.clone()]));
        provider
            .expect_delete()
            .withf(|_, domain_id, provider_id| domain_id == "d1" && provider_id == "live")
            .times(1)
            .returning(|_, _, _| Ok((sample_client("live", Some(2)), 0)));
        provider
            .expect_delete_domain_settings()
            .times(1)
            .returning(|_, _| Ok(()));
        let hook = hook_with(provider).await;
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
