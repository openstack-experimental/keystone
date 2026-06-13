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
//! # Raft driver for the K8s Auth module
use async_trait::async_trait;
use chrono::Utc;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, StoreError, app::Storage,
};

use crate::{
    WebauthnError,
    types::{WebauthnApi, WebauthnCredential},
};

static DATA_KEYSPACE: &str = "data";
static KEY_CURRENT_STATE: &str = "webauthn:state:current";

/// Raft driver for the K8s Auth module.
#[derive(Default)]
pub struct RaftDriver {}

impl RaftDriver {
    /// Generate the keyspace name for storing temporary states using the
    /// last_log_index.
    ///
    /// # Parameters
    /// - `storage`: The storage instance.
    ///
    /// # Returns
    /// The generated keyspace name.
    fn generate_state_keyspace_name(&self, storage: &Storage) -> String {
        if let Some(val) = storage.last_log_index() {
            format!("webauth_state_{}", val)
        } else {
            format!("webauth_state_{}", Utc::now().timestamp())
        }
    }

    /// Get the name of the keyspace containing current (not expired) states.
    ///
    /// # Parameters
    /// - `storage`: The storage instance.
    ///
    /// # Returns
    /// A `Result` containing the keyspace name, or an `Error`.
    async fn get_current_state_keyspace_name(
        &self,
        storage: &Storage,
    ) -> Result<String, WebauthnError> {
        let res = match storage
            .get_by_key(KEY_CURRENT_STATE, Some(DATA_KEYSPACE))
            .await?
        {
            Some(val) => {
                // Use the current value
                val.data
            }
            None => {
                // Write the new value and use the result as the name
                let ks_name = self.generate_state_keyspace_name(storage);
                storage
                    .set_value(
                        KEY_CURRENT_STATE,
                        StoreDataEnvelope {
                            metadata: Metadata::new(),
                            data: ks_name.clone(),
                        },
                        Some(DATA_KEYSPACE),
                        None,
                    )
                    .await?;
                ks_name
            }
        };
        Ok(res)
    }

    /// Get the key name for the credential registration.
    ///
    /// # Parameters
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// The credential registration key name.
    fn get_user_cred_registration_state_key_name<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:registration", user_id.as_ref())
    }

    /// Get the key name for the credential authentication.
    ///
    /// # Parameters
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// The credential authentication key name.
    fn get_user_cred_auth_state_key_name<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:auth", user_id.as_ref())
    }

    /// Get the key name for the credential.
    ///
    /// # Parameters
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    ///
    /// # Returns
    /// The credential key name.
    fn get_cred_key_name<S: AsRef<str>>(&self, user_id: S, credential_id: S) -> String {
        format!("{}:cred:{}", user_id.as_ref(), credential_id.as_ref())
    }

    /// Get user credential listing prefix.
    ///
    /// # Parameters
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// The user credential listing prefix.
    fn get_user_cred_list_prefix<S: AsRef<str>>(&self, user_id: S) -> String {
        format!("{}:cred", user_id.as_ref())
    }

    async fn create_user_webauthn_credential_impl(
        &self,
        storage: &impl StorageApi,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, StoreError> {
        storage
            .set_value(
                self.get_cred_key_name(&credential.user_id, &credential.credential_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: credential.clone(),
                },
                Some(DATA_KEYSPACE),
                None,
            )
            .await?;
        Ok(credential.clone())
    }

    async fn get_user_webauthn_credential_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<Option<WebauthnCredential>, StoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        Ok(storage
            .get_by_key(key, Some(DATA_KEYSPACE))
            .await?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<(), StoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        storage.remove(key, Some(DATA_KEYSPACE)).await?;
        Ok(())
    }

    async fn list_user_webauthn_credentials_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
    ) -> Result<Vec<WebauthnCredential>, StoreError> {
        let prefix = self.get_user_cred_list_prefix(user_id);
        Ok(storage
            .prefix(prefix, Some(DATA_KEYSPACE))
            .await?
            .into_iter()
            .map(|(_, v)| v.data)
            .collect())
    }

    async fn update_user_webauthn_credential_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        credential_id: &'a str,
        credential: &WebauthnCredential,
    ) -> Result<Option<WebauthnCredential>, StoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        if let Some(curr) = storage
            .get_by_key::<WebauthnCredential, String, &str>(key, Some(DATA_KEYSPACE))
            .await?
        {
            let new_meta = curr.metadata.new_revision();
            let curr_revision = curr.metadata.revision;
            storage
                .set_value(
                    self.get_cred_key_name(user_id, credential_id),
                    StoreDataEnvelope {
                        metadata: new_meta,
                        data: credential,
                    },
                    Some(DATA_KEYSPACE),
                    Some(curr_revision),
                )
                .await?;
            Ok(Some(credential.clone()))
        } else {
            Ok(None)
        }
    }

    async fn save_user_webauthn_credential_authentication_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        auth_state: &PasskeyAuthentication,
        state_keysapce: &str,
    ) -> Result<(), StoreError> {
        storage
            .set_value(
                self.get_user_cred_auth_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: auth_state,
                },
                Some(state_keysapce),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_authentication_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        state_keysapce: &str,
    ) -> Result<Option<PasskeyAuthentication>, StoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        Ok(storage
            .get_by_key(key, Some(state_keysapce))
            .await?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_authentication_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        state_keysapce: &str,
    ) -> Result<(), StoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        storage.remove(key, Some(state_keysapce)).await?;
        Ok(())
    }

    async fn save_user_webauthn_credential_registration_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        reg_state: &PasskeyRegistration,
        state_keysapce: &str,
    ) -> Result<(), StoreError> {
        storage
            .set_value(
                self.get_user_cred_registration_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: reg_state,
                },
                Some(state_keysapce),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_registration_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        state_keysapce: &str,
    ) -> Result<Option<PasskeyRegistration>, StoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        Ok(storage
            .get_by_key(key, Some(state_keysapce))
            .await?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_registration_state_impl<'a>(
        &self,
        storage: &impl StorageApi,
        user_id: &'a str,
        state_keysapce: &str,
    ) -> Result<(), StoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        storage.remove(key, Some(state_keysapce)).await?;
        Ok(())
    }
}

#[async_trait]
impl WebauthnApi for RaftDriver {
    /// Cleanup expired Webauthn states.
    ///
    /// # Parameters
    /// - `_state`: The service state.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    #[tracing::instrument(level = "debug", skip_all())]
    async fn cleanup(&self, _state: &ServiceState) -> Result<(), WebauthnError> {
        Ok(())
    }

    /// Create webauthn credential for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `credential`: The credential to create.
    ///
    /// # Returns
    /// A `Result` containing the created credential, or an `Error`.
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
        self.create_user_webauthn_credential_impl(raft, credential)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential of the user by the credential_id.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the WebauthnCredential if found,
    /// or an `Error`.
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
        self.get_user_webauthn_credential_impl(raft, user_id, credential_id)
            .await
            .map_err(|e| e.into())
    }

    /// Delete credential for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
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
        self.delete_user_webauthn_credential_impl(raft, user_id, credential_id)
            .await
            .map_err(|e| e.into())
    }

    /// Delete webauthn credential auth state for a user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.delete_user_webauthn_credential_authentication_state_impl(
            raft,
            user_id,
            &state_keysapce,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Delete webauthn credential registration state for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.delete_user_webauthn_credential_registration_state_impl(raft, user_id, &state_keysapce)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the PasskeyAuthentication if
    /// found, or an `Error`.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.get_user_webauthn_credential_authentication_state_impl(raft, user_id, &state_keysapce)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential registration state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the PasskeyRegistration if found,
    /// or an `Error`.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.get_user_webauthn_credential_registration_state_impl(raft, user_id, &state_keysapce)
            .await
            .map_err(|e| e.into())
    }

    /// List user webauthn credentials.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing a list of credentials, or an `Error`.
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
        self.list_user_webauthn_credentials_impl(raft, user_id)
            .await
            .map_err(|e| e.into())
    }

    /// Save webauthn credential auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    /// - `auth_state`: The authentication state to save.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.save_user_webauthn_credential_authentication_state_impl(
            raft,
            user_id,
            auth_state,
            &state_keysapce,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Save webauthn credential registration state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    /// - `reg_state`: The registration state to save.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
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
        let state_keysapce = self.get_current_state_keyspace_name(raft).await?;
        self.save_user_webauthn_credential_registration_state_impl(
            raft,
            user_id,
            reg_state,
            &state_keysapce,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Update credential data.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    /// - `credential`: The credential data to update.
    ///
    /// # Returns
    /// A `Result` containing the updated credential, or an `Error`.
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
        match self
            .update_user_webauthn_credential_impl(raft, user_id, credential_id, credential)
            .await
        {
            Ok(Some(c)) => Ok(c),
            Ok(None) => Err(WebauthnError::CredentialNotFound(credential_id.to_string())),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;
    use openstack_keystone_distributed_storage::{Metadata, StoreDataEnvelope};

    const DATA_KEYSPACE_TEST: &str = "data";
    const STATE_KEYSPACE: &str = "webauth_state_test";

    #[tokio::test]
    async fn test_credential_storage() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let cred_key = driver.get_cred_key_name("user-1", "cred-1");
        let cred_value: String = "test-credential-data".to_string();

        storage
            .set_value(
                &cred_key,
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: cred_value.clone(),
                },
                Some(DATA_KEYSPACE_TEST),
                None,
            )
            .await
            .unwrap();

        let found = storage
            .get_by_key::<String, &str, &str>(&cred_key, Some(DATA_KEYSPACE_TEST))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.data, "test-credential-data");
    }

    #[tokio::test]
    async fn test_credential_keys() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_cred_key_name("user-1", "cred-1"),
            "user-1:cred:cred-1"
        );
        assert_eq!(driver.get_user_cred_list_prefix("user-1"), "user-1:cred");
    }

    #[tokio::test]
    async fn test_state_auth_key() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_user_cred_auth_state_key_name("user-1"),
            "user-1:auth"
        );
    }

    #[tokio::test]
    async fn test_state_reg_key() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_user_cred_registration_state_key_name("user-1"),
            "user-1:registration"
        );
    }

    #[tokio::test]
    async fn test_auth_state_save_and_get() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let auth_value: String = "auth-state-data".to_string();
        let key = driver.get_user_cred_auth_state_key_name("user-1");

        storage
            .set_value(
                &key,
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: auth_value.clone(),
                },
                Some(STATE_KEYSPACE),
                None,
            )
            .await
            .unwrap();

        let found = storage
            .get_by_key::<String, &str, &str>(&key, Some(STATE_KEYSPACE))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.data, "auth-state-data");
    }

    #[tokio::test]
    async fn test_reg_state_save_and_get() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let reg_value: String = "reg-state-data".to_string();
        let key = driver.get_user_cred_registration_state_key_name("user-1");

        storage
            .set_value(
                &key,
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: reg_value.clone(),
                },
                Some(STATE_KEYSPACE),
                None,
            )
            .await
            .unwrap();

        let found = storage
            .get_by_key::<String, &str, &str>(&key, Some(STATE_KEYSPACE))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.data, "reg-state-data");
    }

    #[tokio::test]
    async fn test_credential_deletion() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let cred_key = driver.get_cred_key_name("user-1", "cred-1");
        storage
            .set_value(
                &cred_key,
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "test".to_string(),
                },
                Some(DATA_KEYSPACE_TEST),
                None,
            )
            .await
            .unwrap();

        storage
            .remove(cred_key.clone(), Some(DATA_KEYSPACE_TEST))
            .await
            .unwrap();

        let found = storage
            .get_by_key::<String, &str, &str>(&cred_key, Some(DATA_KEYSPACE_TEST))
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_state_deletion() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let key = driver.get_user_cred_auth_state_key_name("user-1");
        storage
            .set_value(
                &key,
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "test".to_string(),
                },
                Some(STATE_KEYSPACE),
                None,
            )
            .await
            .unwrap();

        storage
            .remove(key.clone(), Some(STATE_KEYSPACE))
            .await
            .unwrap();

        let found = storage
            .get_by_key::<String, &str, &str>(&key, Some(STATE_KEYSPACE))
            .await
            .unwrap();
        assert!(found.is_none());
    }
}
