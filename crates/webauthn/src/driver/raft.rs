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

/// Prefix for the rotating, time-bucketed keyspaces that hold in-flight
/// WebAuthn ceremony state (registration/authentication challenges).
///
/// Ceremony state is inherently short-lived — a browser has only a few
/// minutes to complete a passkey ceremony before the challenge goes stale —
/// but a naive implementation that keeps writing to a single, never-rotated
/// keyspace lets abandoned ceremonies accumulate forever, interleaved on
/// disk with fresh writes (the classic segmentation problem for an
/// LSM-backed store: live keys and long-dead tombstones end up mixed in the
/// same compaction unit, and compaction can never fully reclaim the dead
/// space because it keeps getting new neighbors). Bucketing writes by a
/// coarse wall-clock window instead confines each ceremony's data to one of
/// a small, bounded set of keyspaces that age out together and can be
/// reclaimed as a whole once expired (see `cleanup`).
static STATE_KEYSPACE_PREFIX: &str = "webauthn_state";

/// Width of a single rotating state-keyspace time bucket, in seconds.
///
/// Matches the SQL driver's ceremony TTL (`driver::sql::state::delete_expired`,
/// 5 minutes) so ceremony-state lifetime is consistent across backends.
const STATE_BUCKET_WIDTH_SECS: i64 = 300;

/// Number of buckets *before* the current one that reads/deletes still
/// consult, so a ceremony started just before a bucket boundary is not
/// orphaned when it completes just after it.
const STATE_BUCKET_LOOKBACK: i64 = 1;

/// Number of already-expired buckets (past the lookback window) that
/// `cleanup` inspects on every tick.
///
/// This bounds GC cost to a handful of cheap `keyspace_exists` checks per
/// tick regardless of how long the process has been running: most of those
/// checks are `false` (nothing was ever written there, or the bucket was
/// already reclaimed on an earlier tick) and complete without touching
/// storage. A bucket found non-empty is drained via ordinary Raft-replicated
/// removes; the now-empty partition is physically reclaimed on a later tick
/// once every node has applied those removes.
const STATE_BUCKET_GC_HORIZON: i64 = 6;

/// Raft driver for the K8s Auth module.
#[derive(Default)]
pub struct RaftDriver {}

impl RaftDriver {
    /// The rotating state-keyspace time bucket for `now`.
    ///
    /// A pure function of wall-clock time: every cluster node derives the
    /// same "current" bucket independently, with no persisted pointer or
    /// coordination required (unlike the previous scheme, which cached a
    /// single keyspace name on first use and then reused it forever).
    fn state_bucket_for(&self, timestamp: i64) -> i64 {
        timestamp.div_euclid(STATE_BUCKET_WIDTH_SECS)
    }

    /// The current rotating state-keyspace time bucket.
    fn current_state_bucket(&self) -> i64 {
        self.state_bucket_for(Utc::now().timestamp())
    }

    /// Keyspace name for a given time bucket.
    fn state_keyspace_name(&self, bucket: i64) -> String {
        format!("{STATE_KEYSPACE_PREFIX}_{bucket}")
    }

    /// Candidate keyspaces for a state read/delete, most-recent first: the
    /// current bucket followed by `STATE_BUCKET_LOOKBACK` older ones.
    fn state_keyspace_read_candidates(&self) -> Vec<String> {
        let current = self.current_state_bucket();
        (0..=STATE_BUCKET_LOOKBACK)
            .map(|back| self.state_keyspace_name(current - back))
            .collect()
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
    ) -> Result<(), ApiStoreError> {
        let keyspace = self.state_keyspace_name(self.current_state_bucket());
        storage
            .set_value(
                self.get_user_cred_auth_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(auth_state)?,
                },
                Some(keyspace),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_authentication_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<Option<PasskeyAuthentication>, ApiStoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        for keyspace in self.state_keyspace_read_candidates() {
            if let Some(env) = storage.get_by_key(key.as_bytes(), Some(&keyspace)).await? {
                return Ok(Some(env.try_deserialize()?.data));
            }
        }
        Ok(None)
    }

    async fn delete_user_webauthn_credential_authentication_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<(), ApiStoreError> {
        let key = self.get_user_cred_auth_state_key_name(user_id);
        for keyspace in self.state_keyspace_read_candidates() {
            // Skip keyspaces that were never written to: `remove()` against
            // a nonexistent keyspace auto-creates an empty partition as a
            // side effect on the real backend, which would defeat the
            // point of rotating (every ceremony completion would otherwise
            // vivify the lookback bucket even when it was never used).
            if storage.keyspace_exists(&keyspace).await? {
                storage.remove(key.clone(), Some(keyspace)).await?;
            }
        }
        Ok(())
    }

    async fn save_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), ApiStoreError> {
        let keyspace = self.state_keyspace_name(self.current_state_bucket());
        storage
            .set_value(
                self.get_user_cred_registration_state_key_name(user_id),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(reg_state)?,
                },
                Some(keyspace),
                None,
            )
            .await?;
        Ok(())
    }

    async fn get_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<Option<PasskeyRegistration>, ApiStoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        for keyspace in self.state_keyspace_read_candidates() {
            if let Some(env) = storage.get_by_key(key.as_bytes(), Some(&keyspace)).await? {
                return Ok(Some(env.try_deserialize()?.data));
            }
        }
        Ok(None)
    }

    async fn delete_user_webauthn_credential_registration_state_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<(), ApiStoreError> {
        let key = self.get_user_cred_registration_state_key_name(user_id);
        for keyspace in self.state_keyspace_read_candidates() {
            // See the auth-state variant above: skip keyspaces that were
            // never created to avoid vivifying an empty lookback-bucket
            // partition on every ceremony completion.
            if storage.keyspace_exists(&keyspace).await? {
                storage.remove(key.clone(), Some(keyspace)).await?;
            }
        }
        Ok(())
    }

    /// Reclaims rotating state keyspaces that have aged out of the read
    /// lookback window (`STATE_BUCKET_LOOKBACK`).
    ///
    /// For each candidate bucket (checked oldest-affected-first, bounded by
    /// `STATE_BUCKET_GC_HORIZON`): skip it cheaply if it was never created;
    /// otherwise drain any leftover keys via ordinary Raft-replicated
    /// removes (abandoned ceremonies that never called the corresponding
    /// `delete_*` method), then reclaim the partition itself once empty.
    /// Draining and dropping are split across ticks on purpose — a bucket
    /// found non-empty this tick is guaranteed empty on read the next tick,
    /// once every node has applied the removes — so this never races a
    /// write against a delete.
    async fn cleanup_expired_state_keyspaces_impl(
        &self,
        storage: &dyn StorageApi,
    ) -> Result<(), ApiStoreError> {
        let oldest_readable = self.current_state_bucket() - STATE_BUCKET_LOOKBACK;
        for bucket in (oldest_readable - STATE_BUCKET_GC_HORIZON)..oldest_readable {
            let keyspace = self.state_keyspace_name(bucket);
            if !storage.keyspace_exists(&keyspace).await? {
                continue;
            }
            let stale = storage.prefix(b"", Some(&keyspace)).await?;
            if stale.is_empty() {
                storage.drop_keyspace(&keyspace).await?;
            } else {
                for (key, _) in stale {
                    storage.remove(key, Some(keyspace.clone())).await?;
                }
            }
        }
        Ok(())
    }

    /// Whether this node is the current Raft leader.
    ///
    /// `cleanup_expired_state_keyspaces_impl` decides which buckets are
    /// expired from this node's own wall clock, then calls `drop_keyspace`
    /// directly — not through Raft. Calling it from every node
    /// independently would let a fast-clocked node drop a bucket a
    /// correctly-clocked peer still needs. Gating on leadership bounds the
    /// sweep to one node at a time.
    async fn is_current_leader(&self, storage: &dyn StorageApi) -> bool {
        storage.current_leader().await == Some(storage.node_id().await)
    }
}

#[async_trait]
impl WebauthnApi for RaftDriver {
    #[tracing::instrument(level = "debug", skip_all())]
    async fn cleanup<'a>(&self, exec: &ExecutionContext<'a>) -> Result<(), WebauthnError> {
        let raft = exec
            .state()
            .storage
            .as_deref()
            .ok_or(WebauthnError::RaftNotAvailable)?;
        if !self.is_current_leader(raft).await {
            return Ok(());
        }
        self.cleanup_expired_state_keyspaces_impl(raft)
            .await
            .map_err(|e| e.into())
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
        self.delete_user_webauthn_credential_authentication_state_impl(raft, user_id)
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
        self.delete_user_webauthn_credential_registration_state_impl(raft, user_id)
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
        self.get_user_webauthn_credential_authentication_state_impl(raft, user_id)
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
        self.get_user_webauthn_credential_registration_state_impl(raft, user_id)
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
        self.save_user_webauthn_credential_authentication_state_impl(raft, user_id, auth_state)
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
        self.save_user_webauthn_credential_registration_state_impl(raft, user_id, reg_state)
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

    /// Wraps `MockStorage`, recording every keyspace passed to `remove()`.
    ///
    /// Used to prove `delete_*_impl` skips `remove()` entirely for
    /// candidate keyspaces that were never written to — on the real Fjall
    /// backend, calling `remove()` against a nonexistent keyspace silently
    /// creates it, which `MockStorage` alone does not reproduce.
    #[derive(Default)]
    struct RecordingStorage {
        inner: MockStorage,
        removed_keyspaces: std::sync::Mutex<Vec<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl StorageApi for RecordingStorage {
        async fn contains_key(
            &self,
            key: &[u8],
            keyspace: Option<&str>,
        ) -> Result<bool, ApiStoreError> {
            self.inner.contains_key(key, keyspace).await
        }

        async fn get_by_key(
            &self,
            key: &[u8],
            keyspace: Option<&str>,
        ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
            self.inner.get_by_key(key, keyspace).await
        }

        async fn prefix(
            &self,
            prefix: &[u8],
            keyspace: Option<&str>,
        ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
            self.inner.prefix(prefix, keyspace).await
        }

        async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, ApiStoreError> {
            self.inner.prefix_index(prefix).await
        }

        async fn remove(
            &self,
            key: String,
            keyspace: Option<String>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.removed_keyspaces
                .lock()
                .unwrap()
                .push(keyspace.clone());
            self.inner.remove(key, keyspace).await
        }

        async fn remove_index(
            &self,
            key: String,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.remove_index(key).await
        }

        async fn set_value(
            &self,
            key: String,
            value: StoreDataEnvelope<Vec<u8>>,
            keyspace: Option<String>,
            expected_revision: Option<u64>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner
                .set_value(key, value, keyspace, expected_revision)
                .await
        }

        async fn set_index_key(
            &self,
            key: String,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.set_index_key(key).await
        }

        async fn transaction(
            &self,
            mutations: Vec<openstack_keystone_distributed_storage::Mutation>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.transaction(mutations).await
        }

        async fn is_initialized(&self) -> Result<bool, ApiStoreError> {
            self.inner.is_initialized().await
        }

        async fn initialize(
            &self,
            nodes: std::collections::HashMap<u64, openstack_keystone_distributed_storage::Node>,
        ) -> Result<(), ApiStoreError> {
            self.inner.initialize(nodes).await
        }

        async fn current_leader(&self) -> Option<u64> {
            self.inner.current_leader().await
        }

        async fn keyspace_exists(&self, keyspace: &str) -> Result<bool, ApiStoreError> {
            self.inner.keyspace_exists(keyspace).await
        }

        async fn drop_keyspace(&self, keyspace: &str) -> Result<(), ApiStoreError> {
            self.inner.drop_keyspace(keyspace).await
        }

        async fn node_id(&self) -> u64 {
            self.inner.node_id().await
        }
    }

    #[tokio::test]
    async fn test_credential_storage() {
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
    async fn test_reg_state_save_and_get() {
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
    async fn test_credential_deletion() {
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
    async fn test_state_deletion() {
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

    // PasskeyAuthentication wraps AuthenticationState under "ast"; same
    // fixture shape used by the SQL driver's state tests.
    fn sample_auth_state() -> PasskeyAuthentication {
        serde_json::from_str(
            r#"{"ast": {"credentials": [], "policy": "preferred", "challenge": "dGVzdC1jaGFsbGVuZ2U", "appid": null, "allow_backup_eligible_upgrade": false}}"#,
        )
        .unwrap()
    }

    #[test]
    fn test_state_bucket_is_pure_function_of_time() {
        let driver = RaftDriver::default();
        assert_eq!(driver.state_bucket_for(0), 0);
        assert_eq!(driver.state_bucket_for(STATE_BUCKET_WIDTH_SECS - 1), 0);
        assert_eq!(driver.state_bucket_for(STATE_BUCKET_WIDTH_SECS), 1);
        assert_eq!(
            driver.state_keyspace_name(42),
            format!("{STATE_KEYSPACE_PREFIX}_42")
        );
        // Two independent calls agree — no persisted pointer is consulted.
        assert_eq!(driver.current_state_bucket(), driver.current_state_bucket());
    }

    #[tokio::test]
    async fn test_auth_state_roundtrip_via_impl_rotates_into_current_bucket() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        let auth_state = sample_auth_state();

        driver
            .save_user_webauthn_credential_authentication_state_impl(
                &storage,
                "user-1",
                &auth_state,
            )
            .await
            .unwrap();

        // Written straight into the current bucket's keyspace, not a
        // cached/static one.
        let current_ks = driver.state_keyspace_name(driver.current_state_bucket());
        assert!(
            storage
                .get_by_key(
                    driver
                        .get_user_cred_auth_state_key_name("user-1")
                        .as_bytes(),
                    Some(&current_ks)
                )
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            driver
                .get_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
                .await
                .unwrap()
                .is_some()
        );

        driver
            .delete_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
            .await
            .unwrap();
        assert!(
            driver
                .get_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_auth_state_skips_remove_on_never_written_lookback_bucket() {
        let driver = RaftDriver::default();
        let storage = RecordingStorage::default();
        let auth_state = sample_auth_state();

        // Only the current bucket ever receives a write; the previous
        // (lookback) bucket's keyspace was never created.
        driver
            .save_user_webauthn_credential_authentication_state_impl(
                &storage,
                "user-1",
                &auth_state,
            )
            .await
            .unwrap();

        driver
            .delete_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
            .await
            .unwrap();

        // `remove()` must only be issued for the bucket that actually
        // exists — calling it against the never-written lookback bucket
        // would auto-vivify an empty partition on the real backend.
        let removed = storage.removed_keyspaces.lock().unwrap();
        let current_ks = driver.state_keyspace_name(driver.current_state_bucket());
        assert_eq!(removed.as_slice(), [Some(current_ks)]);
    }

    #[tokio::test]
    async fn test_get_auth_state_falls_back_to_previous_bucket() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        let auth_state = sample_auth_state();

        // Simulate a ceremony that started just before a bucket boundary:
        // its state lives in the *previous* bucket's keyspace, not the
        // current one.
        let previous_ks = driver.state_keyspace_name(driver.current_state_bucket() - 1);
        storage
            .set_value(
                driver.get_user_cred_auth_state_key_name("user-1"),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&auth_state).unwrap(),
                },
                Some(previous_ks),
                None,
            )
            .await
            .unwrap();

        let found = driver
            .get_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
            .await
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_get_auth_state_beyond_lookback_is_not_found() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        let auth_state = sample_auth_state();

        // A bucket older than the lookback window is treated as expired,
        // even if a stale entry still physically exists there.
        let ancient_ks =
            driver.state_keyspace_name(driver.current_state_bucket() - STATE_BUCKET_LOOKBACK - 1);
        storage
            .set_value(
                driver.get_user_cred_auth_state_key_name("user-1"),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&auth_state).unwrap(),
                },
                Some(ancient_ks),
                None,
            )
            .await
            .unwrap();

        let found = driver
            .get_user_webauthn_credential_authentication_state_impl(&storage, "user-1")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_is_a_noop_when_nothing_ever_written() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        driver
            .cleanup_expired_state_keyspaces_impl(&storage)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_is_current_leader_true_when_leader_matches_self() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        storage.set_node_id(7);
        storage.set_current_leader(Some(7));
        assert!(driver.is_current_leader(&storage).await);
    }

    #[tokio::test]
    async fn test_is_current_leader_false_when_another_node_leads() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        storage.set_node_id(7);
        storage.set_current_leader(Some(3));
        assert!(!driver.is_current_leader(&storage).await);
    }

    #[tokio::test]
    async fn test_is_current_leader_false_when_no_leader_elected() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();
        storage.set_node_id(7);
        assert!(!driver.is_current_leader(&storage).await);
    }

    #[tokio::test]
    async fn test_cleanup_drains_then_drops_expired_keyspace() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        // Well past the read lookback window and inside the GC horizon:
        // eligible for reclamation this tick.
        let stale_bucket = driver.current_state_bucket() - STATE_BUCKET_LOOKBACK - 2;
        let stale_ks = driver.state_keyspace_name(stale_bucket);
        storage
            .set_value(
                "abandoned-user:auth".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&sample_auth_state()).unwrap(),
                },
                Some(stale_ks.clone()),
                None,
            )
            .await
            .unwrap();
        assert!(storage.keyspace_exists(&stale_ks).await.unwrap());

        // First tick: drains the leftover key but leaves the (now empty)
        // partition in place.
        driver
            .cleanup_expired_state_keyspaces_impl(&storage)
            .await
            .unwrap();
        assert!(
            storage
                .get_by_key(b"abandoned-user:auth", Some(&stale_ks))
                .await
                .unwrap()
                .is_none()
        );
        assert!(storage.keyspace_exists(&stale_ks).await.unwrap());

        // Second tick: finds it empty and reclaims the partition itself.
        driver
            .cleanup_expired_state_keyspaces_impl(&storage)
            .await
            .unwrap();
        assert!(!storage.keyspace_exists(&stale_ks).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_does_not_touch_buckets_still_within_lookback() {
        let driver = RaftDriver::default();
        let storage = MockStorage::default();

        let live_ks =
            driver.state_keyspace_name(driver.current_state_bucket() - STATE_BUCKET_LOOKBACK);
        storage
            .set_value(
                "active-user:auth".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: rmp_serde::to_vec(&sample_auth_state()).unwrap(),
                },
                Some(live_ks.clone()),
                None,
            )
            .await
            .unwrap();

        driver
            .cleanup_expired_state_keyspaces_impl(&storage)
            .await
            .unwrap();

        // Still readable — a ceremony started at the edge of the lookback
        // window must not be garbage collected out from under it.
        assert!(
            storage
                .get_by_key(b"active-user:auth", Some(&live_ks))
                .await
                .unwrap()
                .is_some()
        );
    }
}
