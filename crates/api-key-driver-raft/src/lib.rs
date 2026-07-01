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
//! # OpenStack Keystone Raft driver for API Key (SCIM ingress) machine
//! identities (ADR 0021).
use async_trait::async_trait;
use chrono::Utc;

use openstack_keystone_core::api_key::backend::ApiKeyBackend;
use openstack_keystone_core::api_key::error::ApiKeyProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::api_key::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, StoreError, store_command::Mutation,
};

/// Raft Database API Key backend.
///
/// Primary records are indexed by `lookup_hash` (ADR 0021 §2.A), the fast
/// non-secret SHA-256 digest of the token entropy, to serve the O(1)
/// authentication hot path. The public `client_id` UUID used by
/// administrative CRUD is resolved through a secondary index whose key
/// embeds the target `lookup_hash` as a suffix.
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Primary storage key: `api_client:v1:<domain_id>:<lookup_hash>`.
    fn get_resource_key_name<D: AsRef<str>, H: AsRef<str>>(
        &self,
        domain_id: D,
        lookup_hash: H,
    ) -> String {
        format!(
            "api_client:v1:{}:{}",
            domain_id.as_ref(),
            lookup_hash.as_ref()
        )
    }

    /// Prefix covering all keys for a domain (used for listing).
    fn get_resource_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("api_client:v1:{}:", domain_id.as_ref())
    }

    /// Secondary index key resolving `client_id` to `lookup_hash`:
    /// `api_client:client_id_idx:v1:<domain_id>:<client_id>:<lookup_hash>`.
    fn get_client_id_idx_key_name<D: AsRef<str>, C: AsRef<str>, H: AsRef<str>>(
        &self,
        domain_id: D,
        client_id: C,
        lookup_hash: H,
    ) -> String {
        format!(
            "api_client:client_id_idx:v1:{}:{}:{}",
            domain_id.as_ref(),
            client_id.as_ref(),
            lookup_hash.as_ref()
        )
    }

    /// Prefix resolving all index entries for a given `client_id`. Exactly
    /// one entry is expected to exist at a time.
    fn get_client_id_idx_prefix<D: AsRef<str>, C: AsRef<str>>(
        &self,
        domain_id: D,
        client_id: C,
    ) -> String {
        format!(
            "api_client:client_id_idx:v1:{}:{}:",
            domain_id.as_ref(),
            client_id.as_ref()
        )
    }

    /// Resolve `client_id` to its current `lookup_hash` via the secondary
    /// index.
    async fn resolve_lookup_hash(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        client_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let prefix = self.get_client_id_idx_prefix(domain_id, client_id);
        let entries = storage.prefix_index(prefix.as_bytes()).await?;
        Ok(entries
            .into_iter()
            .next()
            .map(|key| key[prefix.len()..].to_string()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn create_impl(
        &self,
        storage: &dyn StorageApi,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, StoreError> {
        let obj = ApiClientResource {
            domain_id: data.domain_id,
            provider_id: data.provider_id,
            client_id: data.client_id,
            lookup_hash: data.lookup_hash,
            secret_hash: data.secret_hash,
            allowed_ips: data.allowed_ips,
            description: data.description,
            enabled: true,
            created_at: Utc::now().timestamp(),
            expires_at: data.expires_at,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        };
        let mutations = vec![
            Mutation::set(
                self.get_resource_key_name(&obj.domain_id, &obj.lookup_hash),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?,
            Mutation::set_index(self.get_client_id_idx_key_name(
                &obj.domain_id,
                &obj.client_id,
                &obj.lookup_hash,
            )),
        ];
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_by_lookup_hash_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        lookup_hash: &str,
    ) -> Result<Option<ApiClientResource>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_resource_key_name(domain_id, lookup_hash)
                    .as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<ApiClientResource>())
            .transpose()?
            .map(|x| x.data))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_by_client_id_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        client_id: &str,
    ) -> Result<Option<ApiClientResource>, StoreError> {
        let Some(lookup_hash) = self
            .resolve_lookup_hash(storage, domain_id, client_id)
            .await?
        else {
            return Ok(None);
        };
        self.get_by_lookup_hash_impl(storage, domain_id, &lookup_hash)
            .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_impl(
        &self,
        storage: &dyn StorageApi,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, StoreError> {
        let prefix = self.get_resource_by_domain_prefix(&params.domain_id);
        let mut res: Vec<ApiClientResource> = Vec::new();
        for (_, envelope) in storage.prefix(prefix.as_bytes(), None).await? {
            let candidate = envelope.try_deserialize::<ApiClientResource>()?.data;
            if let Some(provider_id) = &params.provider_id
                && &candidate.provider_id != provider_id
            {
                continue;
            }
            if let Some(enabled) = params.enabled
                && candidate.enabled != enabled
            {
                continue;
            }
            res.push(candidate);
        }
        Ok(res)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        client_id: &str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, StoreError> {
        let Some(lookup_hash) = self
            .resolve_lookup_hash(storage, domain_id, client_id)
            .await?
        else {
            return Err(StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            });
        };
        let key = self.get_resource_key_name(domain_id, &lookup_hash);
        let curr: StoreDataEnvelope<ApiClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn revoke_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        client_id: &str,
        revoked_by: &str,
    ) -> Result<ApiClientResource, StoreError> {
        let Some(lookup_hash) = self
            .resolve_lookup_hash(storage, domain_id, client_id)
            .await?
        else {
            return Err(StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            });
        };
        let key = self.get_resource_key_name(domain_id, &lookup_hash);
        let curr: StoreDataEnvelope<ApiClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.revoke(revoked_by, Utc::now().timestamp());
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_last_used_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        lookup_hash: &str,
        last_used_at: i64,
    ) -> Result<(), StoreError> {
        let key = self.get_resource_key_name(domain_id, lookup_hash);
        let Some(curr): Option<StoreDataEnvelope<ApiClientResource>> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize())
            .transpose()?
        else {
            return Ok(());
        };
        let mut new = curr.data;
        new.last_used_at = Some(last_used_at);
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_secret_hash_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        lookup_hash: &str,
        secret_hash: String,
    ) -> Result<(), StoreError> {
        let key = self.get_resource_key_name(domain_id, lookup_hash);
        let Some(curr): Option<StoreDataEnvelope<ApiClientResource>> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize())
            .transpose()?
        else {
            return Ok(());
        };
        let mut new = curr.data;
        new.secret_hash = secret_hash;
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ApiKeyBackend for RaftBackend {
    async fn create(
        &self,
        state: &ServiceState,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.create_impl(raft, data)
            .await
            .map_err(ApiKeyProviderError::raft)
    }

    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.get_by_client_id_impl(raft, domain_id, client_id)
            .await
            .map_err(ApiKeyProviderError::raft)
    }

    async fn get_by_lookup_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.get_by_lookup_hash_impl(raft, domain_id, lookup_hash)
            .await
            .map_err(ApiKeyProviderError::raft)
    }

    async fn list(
        &self,
        state: &ServiceState,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.list_impl(raft, params)
            .await
            .map_err(ApiKeyProviderError::raft)
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        match self.update_impl(raft, domain_id, client_id, data).await {
            Ok(obj) => Ok(obj),
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Err(ApiKeyProviderError::NotFound(client_id.to_string()))
                } else {
                    Err(ApiKeyProviderError::raft(e))
                }
            }
        }
    }

    async fn revoke<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        match self
            .revoke_impl(raft, domain_id, client_id, revoked_by)
            .await
        {
            Ok(obj) => Ok(obj),
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Err(ApiKeyProviderError::NotFound(client_id.to_string()))
                } else {
                    Err(ApiKeyProviderError::raft(e))
                }
            }
        }
    }

    async fn update_last_used<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        last_used_at: i64,
    ) -> Result<(), ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.update_last_used_impl(raft, domain_id, lookup_hash, last_used_at)
            .await
            .map_err(ApiKeyProviderError::raft)
    }

    async fn update_secret_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        secret_hash: String,
    ) -> Result<(), ApiKeyProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ApiKeyProviderError::RaftNotAvailable)?;
        self.update_secret_hash_impl(raft, domain_id, lookup_hash, secret_hash)
            .await
            .map_err(ApiKeyProviderError::raft)
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

    fn make_create(client_id: &str, domain_id: &str, lookup_hash: &str) -> ApiClientResourceCreate {
        ApiClientResourceCreate {
            domain_id: domain_id.to_string(),
            provider_id: "provider-1".to_string(),
            client_id: client_id.to_string(),
            lookup_hash: lookup_hash.to_string(),
            secret_hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_string(),
            allowed_ips: None,
            description: None,
            expires_at: Utc::now().timestamp() + 3600,
        }
    }

    #[tokio::test]
    async fn test_create_and_get_by_lookup_hash() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();
        assert_eq!(created.client_id, "client-1");
        assert!(created.enabled);

        let fetched = backend
            .get_by_lookup_hash_impl(&storage, "domain-1", "hash-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().client_id, "client-1");
    }

    #[tokio::test]
    async fn test_get_by_client_id() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();

        let fetched = backend
            .get_by_client_id_impl(&storage, "domain-1", "client-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().lookup_hash, "hash-1");

        let missing = backend
            .get_by_client_id_impl(&storage, "domain-1", "nonexistent")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_list_by_domain_and_provider_filter() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("client-2", "domain-1", "hash-2"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("client-3", "domain-2", "hash-3"))
            .await
            .unwrap();

        let params = ApiClientResourceListParameters {
            domain_id: "domain-1".to_string(),
            provider_id: None,
            enabled: None,
        };
        let listed = backend.list_impl(&storage, &params).await.unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn test_update_allowed_ips_semantics() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();

        let update = ApiClientResourceUpdate {
            allowed_ips: Some(Some(vec!["10.0.0.0/8".to_string()])),
            description: None,
            enabled: None,
        };
        let updated = backend
            .update_impl(&storage, "domain-1", "client-1", update)
            .await
            .unwrap();
        assert_eq!(updated.allowed_ips, Some(vec!["10.0.0.0/8".to_string()]));

        // Explicitly clear back to unrestricted.
        let clear_update = ApiClientResourceUpdate {
            allowed_ips: Some(None),
            description: None,
            enabled: None,
        };
        let cleared = backend
            .update_impl(&storage, "domain-1", "client-1", clear_update)
            .await
            .unwrap();
        assert_eq!(cleared.allowed_ips, None);
    }

    #[tokio::test]
    async fn test_revoke_sets_tombstone_without_deleting() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();

        let revoked = backend
            .revoke_impl(&storage, "domain-1", "client-1", "operator-1")
            .await
            .unwrap();
        assert!(!revoked.enabled);
        assert_eq!(revoked.revoked_by, Some("operator-1".to_string()));
        assert!(revoked.revoked_at.is_some());

        // Still resolvable by lookup_hash — no hard delete (ADR 0021 §5.C).
        let fetched = backend
            .get_by_lookup_hash_impl(&storage, "domain-1", "hash-1")
            .await
            .unwrap();
        assert!(fetched.is_some());
    }

    #[tokio::test]
    async fn test_update_last_used() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("client-1", "domain-1", "hash-1"))
            .await
            .unwrap();

        backend
            .update_last_used_impl(&storage, "domain-1", "hash-1", 12345)
            .await
            .unwrap();

        let fetched = backend
            .get_by_lookup_hash_impl(&storage, "domain-1", "hash-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.last_used_at, Some(12345));
    }
}
