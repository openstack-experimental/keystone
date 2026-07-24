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
//! # OpenStack Keystone Raft driver for OAuth2 client (relying party)
//! registration (ADR 0026 §5).
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_client::Oauth2ClientProviderError;
use openstack_keystone_core::oauth2_client::backend::Oauth2ClientBackend;
use openstack_keystone_core_types::oauth2_client::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError, Metadata, StorageApi, StoreDataEnvelope, StoreError, StoreResponse,
    store_command::Mutation,
};

/// Bridges two different backend behaviors for the same semantic event: the
/// real Raft-backed [`StorageApi`] converts the first `Violation` on a
/// `transaction` call into an immediate `Err(ApiStoreError::Conflict)`;
/// `MockStorage`, used by this crate's own unit tests, instead returns every
/// violation as data on an `Ok` response's `violations` field. Both call
/// sites need conflict detection to behave identically against either
/// backend (mirrors `scim-driver-raft`'s helper of the same name).
fn require_no_conflict(
    result: Result<StoreResponse, ApiStoreError>,
    conflict: impl FnOnce() -> StoreError,
) -> Result<StoreResponse, StoreError> {
    match result {
        Ok(response) if response.violations.is_empty() => Ok(response),
        Ok(_) => Err(conflict()),
        Err(ApiStoreError::Conflict { .. }) => Err(conflict()),
        Err(e) => Err(e.into()),
    }
}

/// Global `client_id` index value payload: resolves to the owning
/// `(domain_id, provider_id)` coordinate. Stored as a
/// `Mutation::create_if_absent` data key (not `set_index`, which carries no
/// payload) since `client_id` is unique cluster-wide, not domain-scoped --
/// looking it up needs to recover which domain owns it.
#[derive(Clone, Deserialize, Serialize)]
struct ClientIdIndexEntry {
    domain_id: String,
    provider_id: String,
}

/// Raft Database OAuth2 client backend.
///
/// Primary records are indexed by `(domain_id, provider_id)` (`provider_id`
/// unique within `domain_id`). The public `client_id` UUID is resolved
/// cluster-wide (not domain-scoped, ADR 0026 §5) through a secondary index.
#[derive(Default)]
pub struct RaftOauth2ClientBackend {}

impl RaftOauth2ClientBackend {
    /// Primary storage key: `oauth2:client:v1:<domain_id>:<provider_id>`.
    fn get_resource_key_name<D: AsRef<str>, P: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
    ) -> String {
        format!(
            "oauth2:client:v1:{}:{}",
            domain_id.as_ref(),
            provider_id.as_ref()
        )
    }

    /// Prefix covering all keys for a domain (used for listing).
    fn get_resource_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("oauth2:client:v1:{}:", domain_id.as_ref())
    }

    /// Global `client_id` index key:
    /// `oauth2:client:client_id_idx:v1:<client_id>`.
    fn get_client_id_idx_key_name<C: AsRef<str>>(&self, client_id: C) -> String {
        format!("oauth2:client:client_id_idx:v1:{}", client_id.as_ref())
    }

    async fn create_impl(
        &self,
        storage: &dyn StorageApi,
        data: OAuth2ClientResourceCreate,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let now = Utc::now().timestamp();
        let obj = OAuth2ClientResource {
            client_id: data.client_id,
            provider_id: data.provider_id,
            domain_id: data.domain_id,
            client_secret_hash: data.client_secret_hash,
            redirect_uris: data.redirect_uris,
            token_endpoint_auth_method: data.token_endpoint_auth_method,
            grant_types: data.grant_types,
            require_pkce: data.require_pkce,
            allowed_scopes: data.allowed_scopes,
            pre_authorized: data.pre_authorized,
            enabled: true,
            claims_template: data.claims_template,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let primary_key = self.get_resource_key_name(&obj.domain_id, &obj.provider_id);
        let index_key = self.get_client_id_idx_key_name(&obj.client_id);

        // The atomic `create_if_absent` transaction below only reports "some
        // violation happened", not which of the two keys it was. Check both
        // up front to name the actual offender in the conflict message --
        // this is a best-effort read (TOCTOU-racy against a concurrent
        // create) that only affects the error *text*, never correctness:
        // the transaction itself is still the sole source of truth for
        // whether the create succeeds.
        let primary_exists = storage
            .get_by_key(primary_key.as_bytes(), None)
            .await?
            .is_some();
        let index_exists = storage
            .get_by_key(index_key.as_bytes(), None)
            .await?
            .is_some();
        let conflict_description = match (primary_exists, index_exists) {
            (true, _) => format!(
                "provider_id `{}` already registered in domain `{}`",
                obj.provider_id, obj.domain_id
            ),
            (false, true) => format!("client_id `{}` already in use", obj.client_id),
            (false, false) => format!(
                "provider_id `{}` or client_id `{}` already in use",
                obj.provider_id, obj.client_id
            ),
        };

        let mutations = vec![
            Mutation::create_if_absent(
                primary_key.clone(),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
            )?,
            Mutation::create_if_absent(
                index_key,
                ClientIdIndexEntry {
                    domain_id: obj.domain_id.clone(),
                    provider_id: obj.provider_id.clone(),
                },
                Metadata::new(),
                None::<&str>,
            )?,
        ];
        require_no_conflict(storage.transaction(mutations).await, move || {
            StoreError::Conflict {
                subject: primary_key.clone(),
                description: conflict_description,
            }
        })?;
        Ok(obj)
    }

    /// Soft-delete: disables the client and stamps the tombstone. The
    /// `client_id_idx` entry is deliberately left in place (unlike
    /// `api-key-driver-raft`'s hard-delete `purge_impl`, which removes both)
    /// -- `get_by_client_id` must keep resolving a soft-deleted client so
    /// the disabled record stays reachable, which is the entire point of
    /// choosing soft- over hard-delete here (Phase 4's refresh-token
    /// family-tree invalidation walk needs it, and callers can still tell
    /// it's revoked via `enabled`/`deleted_at`). There is currently no
    /// physical-reclamation sweep for either the primary record or this
    /// index entry; add one (mirroring `api_key`'s janitor,
    /// ADR 0021 §6.F) if unbounded growth becomes a concern.
    async fn delete_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.soft_delete(Utc::now().timestamp());
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

    async fn get_by_client_id_impl(
        &self,
        storage: &dyn StorageApi,
        client_id: &str,
    ) -> Result<Option<OAuth2ClientResource>, StoreError> {
        let Some(entry) = storage
            .get_by_key(self.get_client_id_idx_key_name(client_id).as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize::<ClientIdIndexEntry>())
            .transpose()?
            .map(|x| x.data)
        else {
            return Ok(None);
        };
        self.get_impl(storage, &entry.domain_id, &entry.provider_id)
            .await
    }

    async fn get_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
    ) -> Result<Option<OAuth2ClientResource>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_resource_key_name(domain_id, provider_id)
                    .as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<OAuth2ClientResource>())
            .transpose()?
            .map(|x| x.data))
    }

    async fn list_impl(
        &self,
        storage: &dyn StorageApi,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, StoreError> {
        let prefix = self.get_resource_by_domain_prefix(&params.domain_id);
        let mut res: Vec<OAuth2ClientResource> = Vec::new();
        for (_, envelope) in storage.prefix(prefix.as_bytes(), None).await? {
            let candidate = envelope.try_deserialize::<OAuth2ClientResource>()?.data;
            if let Some(enabled) = params.enabled
                && candidate.enabled != enabled
            {
                continue;
            }
            res.push(candidate);
        }

        res.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
        if let Some(marker) = &params.pagination.marker {
            if params.pagination.page_reverse {
                res.retain(|x| x.provider_id.as_str() < marker.as_str());
            } else {
                res.retain(|x| x.provider_id.as_str() > marker.as_str());
            }
        }
        if let Some(limit) = params.pagination.limit {
            let limit = (limit + 1) as usize;
            if params.pagination.page_reverse {
                if res.len() > limit {
                    res = res.split_off(res.len() - limit);
                }
            } else {
                res.truncate(limit);
            }
        }
        Ok(res)
    }

    async fn rotate_secret_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        client_secret_hash: String,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let mut new = curr.data;
        new.client_secret_hash = Some(client_secret_hash);
        new.updated_at = Utc::now().timestamp();
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

    async fn update_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.with_update(data, Utc::now().timestamp());
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
}

/// Maps the `StoreError::IO { source }` sentinel used by `update_impl`/
/// `rotate_secret_impl`/`delete_impl` for "no such record" (constructed via
/// `std::io::Error::new(std::io::ErrorKind::NotFound, ...)`) to
/// `Oauth2ClientProviderError::NotFound`. Matches on the `io::ErrorKind`
/// directly rather than the error's `Display` string, so it can't silently
/// break if `StoreError`'s `Display` impl changes.
fn map_not_found(e: StoreError, provider_id: &str) -> Oauth2ClientProviderError {
    match e {
        StoreError::IO { source } if source.kind() == std::io::ErrorKind::NotFound => {
            Oauth2ClientProviderError::NotFound(provider_id.to_string())
        }
        e => Oauth2ClientProviderError::raft(e),
    }
}

#[async_trait]
impl Oauth2ClientBackend for RaftOauth2ClientBackend {
    async fn create(
        &self,
        state: &ServiceState,
        data: OAuth2ClientResourceCreate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        match self.create_impl(raft, data).await {
            Ok(obj) => Ok(obj),
            Err(StoreError::Conflict { description, .. }) => {
                Err(Oauth2ClientProviderError::Conflict(description))
            }
            Err(e) => Err(Oauth2ClientProviderError::raft(e)),
        }
    }

    async fn delete<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.delete_impl(raft, domain_id, provider_id)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }

    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.get_impl(raft, domain_id, provider_id)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.get_by_client_id_impl(raft, client_id)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    async fn list(
        &self,
        state: &ServiceState,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.list_impl(raft, params)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    async fn rotate_secret<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        client_secret_hash: String,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.rotate_secret_impl(raft, domain_id, provider_id, client_secret_hash)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.update_impl(raft, domain_id, provider_id, data)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }
}

/// Linkage anchor -- see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;
    use std::collections::HashMap;

    fn make_create(
        provider_id: &str,
        domain_id: &str,
        client_id: &str,
    ) -> OAuth2ClientResourceCreate {
        OAuth2ClientResourceCreate {
            client_id: client_id.to_string(),
            provider_id: provider_id.to_string(),
            domain_id: domain_id.to_string(),
            client_secret_hash: Some("$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".to_string()),
            redirect_uris: vec!["https://rp.example.com/callback".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: false,
            allowed_scopes: vec!["openid".to_string()],
            pre_authorized: false,
            claims_template: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        assert!(created.enabled);

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().client_id, "client-1");
    }

    #[tokio::test]
    async fn test_create_duplicate_provider_id_conflicts() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        let result = backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-2"))
            .await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_create_duplicate_client_id_conflicts() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        let result = backend
            .create_impl(&storage, make_create("provider-2", "domain-1", "client-1"))
            .await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_get_by_client_id_cross_domain() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-2", "client-1"))
            .await
            .unwrap();

        let fetched = backend
            .get_by_client_id_impl(&storage, "client-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().domain_id, "domain-2");

        let missing = backend
            .get_by_client_id_impl(&storage, "nonexistent")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_list_by_domain_and_enabled_filter() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("provider-2", "domain-1", "client-2"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("provider-3", "domain-2", "client-3"))
            .await
            .unwrap();

        let params = OAuth2ClientResourceListParameters {
            domain_id: "domain-1".to_string(),
            enabled: None,
            ..Default::default()
        };
        let listed = backend.list_impl(&storage, &params).await.unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn test_update() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let update = OAuth2ClientResourceUpdate {
            enabled: Some(false),
            ..Default::default()
        };
        let updated = backend
            .update_impl(&storage, "domain-1", "provider-1", update)
            .await
            .unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_rotate_secret() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let updated = backend
            .rotate_secret_impl(&storage, "domain-1", "provider-1", "new-hash".to_string())
            .await
            .unwrap();
        assert_eq!(updated.client_secret_hash, Some("new-hash".to_string()));
    }

    #[tokio::test]
    async fn test_soft_delete_leaves_record_gettable_disabled() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let deleted = backend
            .delete_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert!(!deleted.enabled);
        assert!(deleted.deleted_at.is_some());

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert!(fetched.is_some());
        assert!(!fetched.unwrap().enabled);
    }
}
