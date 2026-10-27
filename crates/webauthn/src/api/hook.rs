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
//! # Webauthn extension hook for inter-provider events.
//!
//! Deleting a user removes the passkeys and any pending ceremony state the
//! user registered.

use async_trait::async_trait;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::events::ProviderHooks;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::WebauthnError;
use crate::api::types::CombinedExtensionState;
use crate::types::WebauthnApi;

/// Hook that subscribes the webauthn extension to inter-provider events.
pub struct WebauthnHook {
    state: CombinedExtensionState,
}

impl WebauthnHook {
    /// Create a new hook bound to the given extension state.
    pub fn new(state: CombinedExtensionState) -> Self {
        Self { state }
    }
}

/// Remove every passkey and pending ceremony state of the user.
///
/// A missing ceremony state is not an error: most users have none pending.
/// A failure on one record does not stop the others from being removed; the
/// first error is returned once every record has been tried.
async fn purge_user(
    provider: &dyn WebauthnApi,
    ctx: &ExecutionContext<'_>,
    user_id: &str,
) -> Result<(), WebauthnError> {
    let mut first_error = None;
    for credential in provider
        .list_user_webauthn_credentials(ctx, user_id)
        .await?
    {
        if let Err(e) = provider
            .delete_user_webauthn_credential(ctx, user_id, &credential.credential_id)
            .await
        {
            first_error.get_or_insert(e);
        }
    }
    for result in [
        provider
            .delete_user_webauthn_credential_authentication_state(ctx, user_id)
            .await,
        provider
            .delete_user_webauthn_credential_registration_state(ctx, user_id)
            .await,
    ] {
        match result {
            Ok(()) | Err(WebauthnError::StateNotFound) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[async_trait]
impl ProviderHooks for WebauthnHook {
    async fn on_event(&self, event: &Event) {
        if let (Operation::Delete, EventPayload::User { id }) = (&event.operation, &event.payload) {
            let ctx = ExecutionContext::internal(&self.state.core);
            if let Err(e) = purge_user(self.state.extension.provider.as_ref(), &ctx, id).await {
                tracing::warn!(
                    user_id = %id,
                    error = %e,
                    "failed to purge passkeys of deleted user"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core::tests::get_mocked_state;

    use super::*;
    use crate::driver::sql::credential::tests::get_fake_passkey;
    use crate::types::{CredentialType, MockWebauthnApi, WebauthnCredentialBuilder};

    #[tokio::test]
    async fn test_purge_user_tolerates_missing_ceremony_state() {
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);
        let mut mock = MockWebauthnApi::default();
        mock.expect_list_user_webauthn_credentials()
            .withf(|_, user_id| user_id == "uid")
            .returning(|_, _| Ok(Vec::new()));
        mock.expect_delete_user_webauthn_credential_authentication_state()
            .withf(|_, user_id| user_id == "uid")
            .times(1)
            .returning(|_, _| Err(WebauthnError::StateNotFound));
        mock.expect_delete_user_webauthn_credential_registration_state()
            .withf(|_, user_id| user_id == "uid")
            .times(1)
            .returning(|_, _| Ok(()));

        purge_user(&mock, &ctx, "uid").await.unwrap();
    }

    #[tokio::test]
    async fn test_purge_user_continues_after_credential_delete_failure() {
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);
        let credential = |id: &str| {
            WebauthnCredentialBuilder::default()
                .counter(0u32)
                .created_at(chrono::Utc::now())
                .credential_id(id)
                .data(get_fake_passkey())
                .description("fake")
                .last_used_at(chrono::Utc::now())
                .updated_at(chrono::Utc::now())
                .r#type(CredentialType::CrossPlatform)
                .user_id("uid")
                .build()
                .unwrap()
        };
        let mut mock = MockWebauthnApi::default();
        mock.expect_list_user_webauthn_credentials()
            .returning(move |_, _| Ok(vec![credential("c1"), credential("c2")]));
        mock.expect_delete_user_webauthn_credential()
            .withf(|_, _, id| id == "c1")
            .times(1)
            .returning(|_, _, _| Err(WebauthnError::RaftNotAvailable));
        mock.expect_delete_user_webauthn_credential()
            .withf(|_, _, id| id == "c2")
            .times(1)
            .returning(|_, _, _| Ok(()));
        mock.expect_delete_user_webauthn_credential_authentication_state()
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_delete_user_webauthn_credential_registration_state()
            .times(1)
            .returning(|_, _| Ok(()));

        assert!(matches!(
            purge_user(&mock, &ctx, "uid").await,
            Err(WebauthnError::RaftNotAvailable)
        ));
    }

    #[tokio::test]
    async fn test_purge_user_propagates_state_deletion_failure() {
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);
        let mut mock = MockWebauthnApi::default();
        mock.expect_list_user_webauthn_credentials()
            .returning(|_, _| Ok(Vec::new()));
        mock.expect_delete_user_webauthn_credential_authentication_state()
            .returning(|_, _| Err(WebauthnError::RaftNotAvailable));
        mock.expect_delete_user_webauthn_credential_registration_state()
            .returning(|_, _| Ok(()));

        assert!(matches!(
            purge_user(&mock, &ctx, "uid").await,
            Err(WebauthnError::RaftNotAvailable)
        ));
    }
}
