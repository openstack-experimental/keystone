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
//! # OpenStack Keystone Raft driver for the dynamic plugin identity-binding
//! index provider (ADR 0025 §4).
use async_trait::async_trait;

use openstack_keystone_core::dynamic_plugin_identity::backend::DynamicPluginIdentityBackend;
use openstack_keystone_core::dynamic_plugin_identity::error::DynamicPluginIdentityProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreError, store_command::Mutation,
};

/// Raft KV-backed `(plugin_name, external_id) -> user_id` identity-binding
/// index (ADR 0025 §4).
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Primary storage key:
    /// `dynamic_plugin_identity:v1:<plugin_name>:<external_id>`
    /// -> `user_id`.
    fn primary_key<P: AsRef<str>, E: AsRef<str>>(plugin_name: P, external_id: E) -> String {
        format!(
            "dynamic_plugin_identity:v1:{}:{}",
            plugin_name.as_ref(),
            external_id.as_ref()
        )
    }

    /// Reverse lookup key: `dynamic_plugin_identity:by_user:v1:<user_id>:
    /// <plugin_name>:<external_id>` -> marker, letting
    /// [`RaftBackend::purge_by_user_impl`] find every mapping for a
    /// hard-deleted user without a full scan.
    fn reverse_key<U: AsRef<str>, P: AsRef<str>, E: AsRef<str>>(
        user_id: U,
        plugin_name: P,
        external_id: E,
    ) -> String {
        format!(
            "dynamic_plugin_identity:by_user:v1:{}:{}:{}",
            user_id.as_ref(),
            plugin_name.as_ref(),
            external_id.as_ref()
        )
    }

    /// Prefix covering every reverse-index entry for `user_id`.
    fn reverse_prefix<U: AsRef<str>>(user_id: U) -> String {
        format!("dynamic_plugin_identity:by_user:v1:{}:", user_id.as_ref())
    }

    async fn create_or_resolve_impl(
        &self,
        storage: &dyn StorageApi,
        plugin_name: &str,
        external_id: &str,
        user_id: &str,
    ) -> Result<String, StoreError> {
        let key = Self::primary_key(plugin_name, external_id);
        let response = storage
            .transaction(vec![Mutation::create_if_absent(
                key.clone(),
                user_id.to_string(),
                Metadata::new(),
                None::<&str>,
            )?])
            .await?;

        if response.violations.is_empty() {
            // Won the race: best-effort write the reverse index. A missing
            // reverse entry only degrades `purge_by_user` (proactive
            // cleanup) to the lazy self-heal path in `find_user_inner` -
            // never causes an incorrect lookup.
            let rkey = Self::reverse_key(user_id, plugin_name, external_id);
            if let Err(e) = storage
                .transaction(vec![Mutation::set(
                    rkey.clone(),
                    key.clone(),
                    Metadata::new(),
                    None::<&str>,
                    None,
                )?])
                .await
            {
                tracing::warn!(
                    reverse_key = %rkey,
                    error = %e,
                    "failed to write dynamic plugin identity reverse index entry"
                );
            }
            Ok(user_id.to_string())
        } else {
            // Lost the race: resolve to the canonical winner already
            // persisted under this key.
            let env = storage
                .get_by_key(key.as_bytes(), None)
                .await?
                .ok_or_else(|| StoreError::IO {
                    source: std::io::Error::other(
                        "dynamic plugin identity mapping missing immediately after conflict",
                    ),
                })?;
            Ok(env.try_deserialize::<String>()?.data)
        }
    }

    async fn find_impl(
        &self,
        storage: &dyn StorageApi,
        plugin_name: &str,
        external_id: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(storage
            .get_by_key(Self::primary_key(plugin_name, external_id).as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize::<String>())
            .transpose()?
            .map(|x| x.data))
    }

    async fn purge_impl(
        &self,
        storage: &dyn StorageApi,
        plugin_name: &str,
        external_id: &str,
    ) -> Result<(), StoreError> {
        let key = Self::primary_key(plugin_name, external_id);
        let Some(env) = storage.get_by_key(key.as_bytes(), None).await? else {
            return Ok(());
        };
        let user_id = env.try_deserialize::<String>()?.data;
        let rkey = Self::reverse_key(&user_id, plugin_name, external_id);
        storage
            .transaction(vec![
                Mutation::remove(key, None::<&str>, None),
                Mutation::remove(rkey, None::<&str>, None),
            ])
            .await?;
        Ok(())
    }

    async fn purge_by_user_impl(
        &self,
        storage: &dyn StorageApi,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let prefix = Self::reverse_prefix(user_id);
        let entries = storage.prefix(prefix.as_bytes(), None).await?;
        let mut mutations = Vec::new();
        for (key, envelope) in entries {
            // The reverse entry's value is the exact primary key it points
            // at (written verbatim in `create_or_resolve_impl`) - reused
            // directly rather than re-derived by splitting the reverse key
            // string, which would mis-parse if `plugin_name` ever contained
            // a `:`.
            if let Ok(primary_key) = envelope.try_deserialize::<String>() {
                mutations.push(Mutation::remove(primary_key.data, None::<&str>, None));
            }
            mutations.push(Mutation::remove(key, None::<&str>, None));
        }
        if !mutations.is_empty() {
            storage.transaction(mutations).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl DynamicPluginIdentityBackend for RaftBackend {
    async fn create_or_resolve<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
        user_id: &'a str,
    ) -> Result<String, DynamicPluginIdentityProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(DynamicPluginIdentityProviderError::RaftNotAvailable)?;
        self.create_or_resolve_impl(raft, plugin_name, external_id, user_id)
            .await
            .map_err(DynamicPluginIdentityProviderError::raft)
    }

    async fn find<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<Option<String>, DynamicPluginIdentityProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(DynamicPluginIdentityProviderError::RaftNotAvailable)?;
        self.find_impl(raft, plugin_name, external_id)
            .await
            .map_err(DynamicPluginIdentityProviderError::raft)
    }

    async fn purge<'a>(
        &self,
        state: &ServiceState,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(DynamicPluginIdentityProviderError::RaftNotAvailable)?;
        self.purge_impl(raft, plugin_name, external_id)
            .await
            .map_err(DynamicPluginIdentityProviderError::raft)
    }

    async fn purge_by_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), DynamicPluginIdentityProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(DynamicPluginIdentityProviderError::RaftNotAvailable)?;
        self.purge_by_user_impl(raft, user_id)
            .await
            .map_err(DynamicPluginIdentityProviderError::raft)
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    #[tokio::test]
    async fn test_create_or_resolve_new_mapping() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let resolved = backend
            .create_or_resolve_impl(&storage, "acme", "ext-1", "u1")
            .await
            .unwrap();
        assert_eq!(resolved, "u1");

        let found = backend.find_impl(&storage, "acme", "ext-1").await.unwrap();
        assert_eq!(found.as_deref(), Some("u1"));
    }

    #[tokio::test]
    async fn test_create_or_resolve_race_lost_resolves_to_winner() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let winner = backend
            .create_or_resolve_impl(&storage, "acme", "ext-1", "winner")
            .await
            .unwrap();
        assert_eq!(winner, "winner");

        // A second, concurrent call for the same (plugin_name, external_id)
        // must resolve to the winner, not create a second mapping.
        let resolved = backend
            .create_or_resolve_impl(&storage, "acme", "ext-1", "loser")
            .await
            .unwrap();
        assert_eq!(resolved, "winner");
    }

    #[tokio::test]
    async fn test_find_missing_returns_none() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let found = backend
            .find_impl(&storage, "acme", "nonexistent")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_purge_removes_mapping() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_or_resolve_impl(&storage, "acme", "ext-1", "u1")
            .await
            .unwrap();
        backend.purge_impl(&storage, "acme", "ext-1").await.unwrap();

        let found = backend.find_impl(&storage, "acme", "ext-1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_purge_missing_is_a_noop() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .purge_impl(&storage, "acme", "nonexistent")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_purge_by_user_removes_all_entries_for_that_user_only() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_or_resolve_impl(&storage, "acme", "ext-1", "u1")
            .await
            .unwrap();
        backend
            .create_or_resolve_impl(&storage, "beta", "ext-2", "u1")
            .await
            .unwrap();
        backend
            .create_or_resolve_impl(&storage, "acme", "ext-3", "u2")
            .await
            .unwrap();

        backend.purge_by_user_impl(&storage, "u1").await.unwrap();

        assert!(
            backend
                .find_impl(&storage, "acme", "ext-1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .find_impl(&storage, "beta", "ext-2")
                .await
                .unwrap()
                .is_none()
        );
        // Unrelated user's mapping must survive.
        assert_eq!(
            backend
                .find_impl(&storage, "acme", "ext-3")
                .await
                .unwrap()
                .as_deref(),
            Some("u2")
        );
    }

    #[tokio::test]
    async fn test_purge_by_user_with_no_entries_is_a_noop() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .purge_by_user_impl(&storage, "nonexistent")
            .await
            .unwrap();
    }
}
