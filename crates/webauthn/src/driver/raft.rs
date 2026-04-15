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

use async_trait::async_trait;
use chrono::Utc;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_distributed_storage::app::Storage;

use crate::{
    WebauthnError,
    types::{WebauthnApi, WebauthnCredential},
};

static DATA_KEYSPACE: &str = "webauthn:data";
static META_KEYSPACE: &str = "webauthn:meta";
static KEY_CURRENT_STATE: &str = "webauthn:state:current";

/// Raft driver for the WebAuthN extension.
#[derive(Default)]
pub struct RaftDriver {}

impl RaftDriver {
    /// Generate the keyspace name for storing temporary states using the last_log_index.
    fn generate_state_keyspace_name(&self, storage: &Storage) -> String {
        if let Some(val) = storage.last_log_index() {
            format!("webauth_state_{}", val)
        } else {
            format!("webauth_state_{}", Utc::now().timestamp())
        }
    }

    /// Get the name of the keyspace containing current (not expired) states.
    async fn get_current_state_keyspace_name(
        &self,
        storage: &Storage,
    ) -> Result<String, WebauthnError> {
        let res = match storage
            .get_by_key(KEY_CURRENT_STATE, Some(META_KEYSPACE))
            .await?
        {
            Some(val) => {
                // Use the current value
                val
            }
            None => {
                // Write the new value and use the result as the name
                let ks_name = self.generate_state_keyspace_name(&storage);
                storage
                    .set_value(KEY_CURRENT_STATE, &ks_name, Some(META_KEYSPACE))
                    .await?;
                ks_name
            }
        };
        Ok(res)
    }

    /// Get the key name for the credential registration.
    fn get_user_cred_registration_state_key_name<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:registration", user_id.as_ref())
    }

    /// Get the key name for the credential authentication.
    fn get_user_cred_auth_state_key_name<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:auth", user_id.as_ref())
    }

    /// Get the key name for the credential.
    fn get_cred_key_name<S: AsRef<str>>(&self, user_id: S, credential_id: S) -> String {
        format!("{}:cred:{}", user_id.as_ref(), credential_id.as_ref())
    }

    /// Get user credential listing prefix
    fn get_user_cred_list_prefix<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:cred", user_id.as_ref())
    }
}

#[async_trait]
impl WebauthnApi for RaftDriver {
    /// Cleanup expired Webauthn states.
    #[tracing::instrument(level = "debug", skip_all())]
    async fn cleanup(&self, _state: &ServiceState) -> Result<(), WebauthnError> {
        Ok(())
    }

    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential(
        &self,
        state: &ServiceState,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.set_value(
            self.get_cred_key_name(&credential.user_id, &credential.credential_id),
            &credential,
            Some(DATA_KEYSPACE),
        )
        .await?;
        Ok(credential.clone())
    }

    /// Get webauthn credential of the user by the credential_id.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        Ok(raft
            .get_by_key(
                self.get_cred_key_name(user_id, credential_id),
                Some(DATA_KEYSPACE),
            )
            .await?)
    }

    /// Delete credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<(), WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.remove(
            self.get_cred_key_name(user_id, credential_id),
            Some(DATA_KEYSPACE),
        )
        .await?;
        Ok(())
    }

    /// Delete webauthn credential auth state for a user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.remove(
            self.get_user_cred_auth_state_key_name(user_id),
            Some(self.get_current_state_keyspace_name(&raft).await?),
        )
        .await?;
        Ok(())
    }

    /// Delete webauthn credential registration state for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.remove(
            self.get_user_cred_registration_state_key_name(user_id),
            Some(self.get_current_state_keyspace_name(&raft).await?),
        )
        .await?;
        Ok(())
    }

    /// Get webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        Ok(raft
            .get_by_key(
                self.get_user_cred_auth_state_key_name(user_id),
                Some(self.get_current_state_keyspace_name(&raft).await?),
            )
            .await?)
    }

    /// Get webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        Ok(raft
            .get_by_key(
                self.get_user_cred_registration_state_key_name(user_id),
                Some(self.get_current_state_keyspace_name(&raft).await?),
            )
            .await?)
    }

    /// List user webauthn credentials.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<WebauthnCredential>, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        Ok(raft
            .prefix(self.get_user_cred_list_prefix(user_id), Some(DATA_KEYSPACE))
            .await?
            .into_iter()
            .map(|(_, v)| v)
            .collect())
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth_state: &PasskeyAuthentication,
    ) -> Result<(), WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.set_value(
            self.get_user_cred_auth_state_key_name(user_id),
            &auth_state,
            Some(self.get_current_state_keyspace_name(&raft).await?),
        )
        .await?;
        Ok(())
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.set_value(
            self.get_user_cred_registration_state_key_name(user_id),
            &reg_state,
            Some(self.get_current_state_keyspace_name(&raft).await?),
        )
        .await?;
        Ok(())
    }

    /// Update credential data.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        raft.set_value(
            self.get_cred_key_name(user_id, credential_id),
            &credential,
            Some(DATA_KEYSPACE),
        )
        .await?;
        Ok(credential.clone())
    }
}
