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

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_distributed_storage::{
    ApiStoreError, Metadata, StorageApi, StoreDataEnvelope,
};
use rmp_serde;

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
    fn generate_state_keyspace_name(&self) -> String {
        format!("webauth_state_{}", Utc::now().timestamp())
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
        storage: &dyn StorageApi,
    ) -> Result<String, ApiStoreError> {
        let res = match storage
            .get_by_key(KEY_CURRENT_STATE.as_bytes(), Some(DATA_KEYSPACE))
            .await?
        {
            Some(val) => rmp_serde::from_slice(&val.data)?,
            None => {
                let ks_name = self.generate_state_keyspace_name();
                storage
                    .set_value(
                        KEY_CURRENT_STATE.to_string(),
                        StoreDataEnvelope {
                            metadata: Metadata::new(),
                            data: rmp_serde::to_vec(&ks_name)?,
                        },
                        Some(DATA_KEYSPACE.to_string()),
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
        storage: &dyn StorageApi,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, ApiStoreError> {
        storage
            .set_value(
                self.get_cred_key_name(&credential.user_id, &credential.credential_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(credential)?,
                },
                Some(DATA_KEYSPACE.to_string()),
                None,
            )
            .await?;
        Ok(credential.clone())
    }

    async fn get_user_webauthn_credential_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, ApiStoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        Ok(storage
            .get_by_key(key.as_bytes(), Some(DATA_KEYSPACE))
            .await?
            .map(|env| env.try_deserialize())
            .transpose()?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), ApiStoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        storage.remove(key, Some(DATA_KEYSPACE.to_string())).await?;
        Ok(())
    }

    async fn list_user_webauthn_credentials_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<Vec<WebauthnCredential>, ApiStoreError> {
        let prefix = self.get_user_cred_list_prefix(user_id);
        storage
            .prefix(prefix.as_bytes(), Some(DATA_KEYSPACE))
            .await?
            .into_iter()
            .map(|(_, env)| env.try_deserialize().map(|x| x.data))
            .collect::<Result<Vec<_>, _>>()
    }

    async fn update_user_webauthn_credential_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        credential_id: &str,
        credential: &WebauthnCredential,
    ) -> Result<Option<WebauthnCredential>, ApiStoreError> {
        let key = self.get_cred_key_name(user_id, credential_id);
        if let Some(curr) = storage
            .get_by_key(key.as_bytes(), Some(DATA_KEYSPACE))
            .await?
            .map(|env| env.try_deserialize::<WebauthnCredential>())
            .transpose()?
        {
            let new_meta = curr.metadata.new_revision();
            let curr_revision = curr.metadata.revision;
            storage
                .set_value(
                    self.get_cred_key_name(user_id, credential_id),
                    StoreDataEnvelope {
                        metadata: new_meta,
                        data: rmp_serde::to_vec(credential)?,
                    },
                    Some(DATA_KEYSPACE.to_string()),
                    Some(curr_revision),
                )
                .await?;
            Ok(Some(credential.clone()))
        } else {
            Ok(None)
        }
    }

    async fn save_user_webauthn_credential_authentication_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        auth_state: &PasskeyAuthentication,
        state_keyspace: &str,
    ) -> Result<(), ApiStoreError> {
        storage
            .set_value(
                self.get_user_cred_auth_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(auth_state)?,
                },
                Some(state_keyspace.to_string()),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_authentication_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        state_keyspace: &str,
    ) -> Result<Option<PasskeyAuthentication>, ApiStoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        Ok(storage
            .get_by_key(key.as_bytes(), Some(state_keyspace))
            .await?
            .map(|env| env.try_deserialize())
            .transpose()?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_authentication_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        state_keyspace: &str,
    ) -> Result<(), ApiStoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        storage
            .remove(key, Some(state_keyspace.to_string()))
            .await?;
        Ok(())
    }

    async fn save_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        reg_state: &PasskeyRegistration,
        state_keyspace: &str,
    ) -> Result<(), ApiStoreError> {
        storage
            .set_value(
                self.get_user_cred_registration_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(reg_state)?,
                },
                Some(state_keyspace.to_string()),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        state_keyspace: &str,
    ) -> Result<Option<PasskeyRegistration>, ApiStoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        Ok(storage
            .get_by_key(key.as_bytes(), Some(state_keyspace))
            .await?
            .map(|env| env.try_deserialize())
            .transpose()?
            .map(|x| x.data))
    }

    async fn delete_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        state_keyspace: &str,
    ) -> Result<(), ApiStoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        storage
            .remove(key, Some(state_keyspace.to_string()))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl WebauthnApi for RaftDriver {
    #[tracing::instrument(level = "debug", skip_all())]
    async fn cleanup<'a>(&self, _exec: &ExecutionContext<'a>) -> Result<(), WebauthnError> {
        Ok(())
    }

    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn create_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        self.create_user_webauthn_credential_impl(raft, credential)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential of the user by the credential_id.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        self.get_user_webauthn_credential_impl(raft, user_id, credential_id)
            .await
            .map_err(|e| e.into())
    }

    /// Delete credential for the user.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        self.delete_user_webauthn_credential_impl(raft, user_id, credential_id)
            .await
            .map_err(|e| e.into())
    }

    /// Delete webauthn credential auth state for a user.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.delete_user_webauthn_credential_authentication_state_impl(
            raft,
            user_id,
            &state_keyspace,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Delete webauthn credential registration state for the user.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.delete_user_webauthn_credential_registration_state_impl(raft, user_id, &state_keyspace)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.get_user_webauthn_credential_authentication_state_impl(raft, user_id, &state_keyspace)
            .await
            .map_err(|e| e.into())
    }

    /// Get webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.get_user_webauthn_credential_registration_state_impl(raft, user_id, &state_keyspace)
            .await
            .map_err(|e| e.into())
    }

    /// List user webauthn credentials.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Vec<WebauthnCredential>, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        self.list_user_webauthn_credentials_impl(raft, user_id)
            .await
            .map_err(|e| e.into())
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        auth_state: &PasskeyAuthentication,
    ) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.save_user_webauthn_credential_authentication_state_impl(
            raft,
            user_id,
            auth_state,
            &state_keyspace,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        let state_keyspace = self.get_current_state_keyspace_name(raft).await?;
        self.save_user_webauthn_credential_registration_state_impl(
            raft,
            user_id,
            reg_state,
            &state_keyspace,
        )
        .await
        .map_err(|e| e.into())
    }

    /// Update credential data.
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn update_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
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
    async fn test_credential_storage<'a>() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let cred_key = driver.get_cred_key_name("user-1", "cred-1");
        let cred_value: String = "test-credential-data".to_string();

        storage
            .set_value(
                cred_key.clone(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&cred_value).unwrap(),
                },
                Some(DATA_KEYSPACE_TEST.to_string()),
                None,
            )
            .await
            .unwrap();

        let found: StoreDataEnvelope<String> = storage
            .get_by_key(cred_key.as_bytes(), Some(DATA_KEYSPACE_TEST))
            .await
            .unwrap()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(found.data, "test-credential-data");
    }

    #[tokio::test]
    async fn test_credential_keys<'a>() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_cred_key_name("user-1", "cred-1"),
            "user-1:cred:cred-1"
        );
        assert_eq!(driver.get_user_cred_list_prefix("user-1"), "user-1:cred");
    }

    #[tokio::test]
    async fn test_state_auth_key<'a>() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_user_cred_auth_state_key_name("user-1"),
            "user-1:auth"
        );
    }

    #[tokio::test]
    async fn test_state_reg_key<'a>() {
        let driver = RaftDriver::default();
        assert_eq!(
            driver.get_user_cred_registration_state_key_name("user-1"),
            "user-1:registration"
        );
    }

    #[tokio::test]
    async fn test_auth_state_save_and_get<'a>() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let auth_value: String = "auth-state-data".to_string();
        let key = driver.get_user_cred_auth_state_key_name("user-1");

        storage
            .set_value(
                key.clone(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&auth_value).unwrap(),
                },
                Some(STATE_KEYSPACE.to_string()),
                None,
            )
            .await
            .unwrap();

        let found: StoreDataEnvelope<String> = storage
            .get_by_key(key.as_bytes(), Some(STATE_KEYSPACE))
            .await
            .unwrap()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(found.data, "auth-state-data");
    }

    #[tokio::test]
    async fn test_reg_state_save_and_get<'a>() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let reg_value: String = "reg-state-data".to_string();
        let key = driver.get_user_cred_registration_state_key_name("user-1");

        storage
            .set_value(
                key.clone(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&reg_value).unwrap(),
                },
                Some(STATE_KEYSPACE.to_string()),
                None,
            )
            .await
            .unwrap();

        let found: StoreDataEnvelope<String> = storage
            .get_by_key(key.as_bytes(), Some(STATE_KEYSPACE))
            .await
            .unwrap()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(found.data, "reg-state-data");
    }

    #[tokio::test]
    async fn test_credential_deletion<'a>() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let cred_key = driver.get_cred_key_name("user-1", "cred-1");
        storage
            .set_value(
                cred_key.clone(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec("test").unwrap(),
                },
                Some(DATA_KEYSPACE_TEST.to_string()),
                None,
            )
            .await
            .unwrap();

        storage
            .remove(cred_key.clone(), Some(DATA_KEYSPACE_TEST.to_string()))
            .await
            .unwrap();

        let found = storage
            .get_by_key(cred_key.as_bytes(), Some(DATA_KEYSPACE_TEST))
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_state_deletion<'a>() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let key = driver.get_user_cred_auth_state_key_name("user-1");
        storage
            .set_value(
                key.clone(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec("test").unwrap(),
                },
                Some(STATE_KEYSPACE.to_string()),
                None,
            )
            .await
            .unwrap();

        storage
            .remove(key.clone(), Some(STATE_KEYSPACE.to_string()))
            .await
            .unwrap();

        let found = storage
            .get_by_key(key.as_bytes(), Some(STATE_KEYSPACE))
            .await
            .unwrap();
        assert!(found.is_none());
    }
}
