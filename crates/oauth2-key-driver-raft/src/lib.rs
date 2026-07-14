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
//! # OpenStack Keystone Raft driver for OAuth2 per-domain signing keys
//! (ADR 0026 §3, §10 Phase 1).
use std::collections::BTreeMap;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_key::backend::Oauth2KeyBackend;
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_distributed_storage::{
    ApiStoreError as StoreError, Metadata, StorageApi, StoreDataEnvelope, store_command::Mutation,
};
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, AsymmetricKeyRepository, AsymmetricKeySource, KeyMaterial, KeyRole,
    SigningAlgorithm,
};

/// Wire representation of [`KeyMaterial`] (which itself does not implement
/// `Serialize`/`Deserialize` since its private key is wrapped in a
/// [`SecretBox`] for zeroize-on-drop).
#[derive(Serialize, Deserialize)]
struct StoredKeyMaterial {
    algorithm: WireSigningAlgorithm,
    private_key_der: Vec<u8>,
    public_key_der: Vec<u8>,
    kid: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
enum WireSigningAlgorithm {
    Es256,
    Rs256,
}

impl From<SigningAlgorithm> for WireSigningAlgorithm {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::Es256 => Self::Es256,
            SigningAlgorithm::Rs256 => Self::Rs256,
        }
    }
}

impl From<WireSigningAlgorithm> for SigningAlgorithm {
    fn from(value: WireSigningAlgorithm) -> Self {
        match value {
            WireSigningAlgorithm::Es256 => Self::Es256,
            WireSigningAlgorithm::Rs256 => Self::Rs256,
        }
    }
}

impl From<&KeyMaterial> for StoredKeyMaterial {
    fn from(value: &KeyMaterial) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            private_key_der: value.private_key_der.expose_secret().clone(),
            public_key_der: value.public_key_der.clone(),
            kid: value.kid.clone(),
            created_at: value.created_at,
        }
    }
}

impl From<StoredKeyMaterial> for KeyMaterial {
    fn from(value: StoredKeyMaterial) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            private_key_der: SecretBox::new(Box::new(value.private_key_der)),
            public_key_der: value.public_key_der,
            kid: value.kid,
            created_at: value.created_at,
        }
    }
}

fn role_str(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Primary => "primary",
        KeyRole::Previous => "previous",
        KeyRole::Pending => "pending",
    }
}

fn key_name(domain_id: &str, role: KeyRole) -> String {
    format!("oauth2:signing_key:v1:{domain_id}:{}", role_str(role))
}

fn key_prefix(domain_id: &str) -> String {
    format!("oauth2:signing_key:v1:{domain_id}:")
}

fn role_from_key(key: &str, prefix: &str) -> Option<KeyRole> {
    match &key[prefix.len()..] {
        "primary" => Some(KeyRole::Primary),
        "previous" => Some(KeyRole::Previous),
        "pending" => Some(KeyRole::Pending),
        _ => None,
    }
}

/// A per-domain, Raft-backed [`AsymmetricKeySource`].
///
/// Short-lived: constructed for the duration of a single provider call
/// (mirrors `RaftBackend` in `api-key-driver-raft`, which pulls `storage`
/// from [`ServiceState`] per call rather than holding it long-term).
pub struct RaftAsymmetricKeySource<'a> {
    domain_id: String,
    storage: &'a dyn StorageApi,
}

impl<'a> RaftAsymmetricKeySource<'a> {
    pub fn new(domain_id: impl Into<String>, storage: &'a dyn StorageApi) -> Self {
        Self {
            domain_id: domain_id.into(),
            storage,
        }
    }
}

#[async_trait]
impl AsymmetricKeySource for RaftAsymmetricKeySource<'_> {
    async fn load(
        &self,
    ) -> Result<
        BTreeMap<KeyRole, KeyMaterial>,
        openstack_keystone_key_repository::error::KeyRepositoryError,
    > {
        let prefix = key_prefix(&self.domain_id);
        let entries = self
            .storage
            .prefix(prefix.as_bytes(), None)
            .await
            .map_err(store_err_to_key_repo_err)?;
        let mut out = BTreeMap::new();
        for (key, envelope) in entries {
            let Some(role) = role_from_key(&key, &prefix) else {
                continue;
            };
            let stored: StoreDataEnvelope<StoredKeyMaterial> = envelope
                .try_deserialize()
                .map_err(store_err_to_key_repo_err)?;
            out.insert(role, KeyMaterial::from(stored.data));
        }
        Ok(out)
    }

    async fn write(
        &self,
        role: KeyRole,
        material: &KeyMaterial,
    ) -> Result<(), openstack_keystone_key_repository::error::KeyRepositoryError> {
        let key = key_name(&self.domain_id, role);
        let stored = StoredKeyMaterial::from(material);
        let envelope = StoreDataEnvelope {
            data: rmp_serde::to_vec(&stored).map_err(|e| {
                openstack_keystone_key_repository::error::KeyRepositoryError::Persist(e.to_string())
            })?,
            metadata: Metadata::new(),
        };
        self.storage
            .set_value(key, envelope, None, None)
            .await
            .map_err(store_err_to_key_repo_err)?;
        Ok(())
    }

    async fn remove(
        &self,
        role: KeyRole,
    ) -> Result<(), openstack_keystone_key_repository::error::KeyRepositoryError> {
        let key = key_name(&self.domain_id, role);
        self.storage
            .remove(key, None)
            .await
            .map_err(store_err_to_key_repo_err)?;
        Ok(())
    }

    async fn promote_pending_to_primary(
        &self,
    ) -> Result<(), openstack_keystone_key_repository::error::KeyRepositoryError> {
        let current = self.load().await?;
        let pending = current.get(&KeyRole::Pending).cloned().ok_or(
            openstack_keystone_key_repository::error::KeyRepositoryError::RoleMissing(
                KeyRole::Pending,
            ),
        )?;
        let mut mutations = vec![
            key_set_mutation(&self.domain_id, KeyRole::Primary, &pending)
                .map_err(store_err_to_key_repo_err)?,
            Mutation::remove(
                key_name(&self.domain_id, KeyRole::Pending),
                None::<&str>,
                None,
            ),
        ];
        if let Some(old_primary) = current.get(&KeyRole::Primary) {
            mutations.push(
                key_set_mutation(&self.domain_id, KeyRole::Previous, old_primary)
                    .map_err(store_err_to_key_repo_err)?,
            );
        }
        self.storage
            .transaction(mutations)
            .await
            .map_err(store_err_to_key_repo_err)?;
        Ok(())
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<()> {
        // No Raft-native watch primitive exists yet (ADR 0026 Phase 1
        // scope): every call re-reads via `load()`, so there is no
        // in-process cache to invalidate.
        tokio::sync::broadcast::channel(1).1
    }
}

fn key_set_mutation(
    domain_id: &str,
    role: KeyRole,
    material: &KeyMaterial,
) -> Result<Mutation, StoreError> {
    Mutation::set(
        key_name(domain_id, role),
        StoredKeyMaterial::from(material),
        Metadata::new(),
        None::<&str>,
        None,
    )
}

fn store_err_to_key_repo_err(
    e: StoreError,
) -> openstack_keystone_key_repository::error::KeyRepositoryError {
    openstack_keystone_key_repository::error::KeyRepositoryError::Persist(e.to_string())
}

/// Raft-backed [`Oauth2KeyBackend`]: one [`RaftAsymmetricKeySource`] per
/// call, scoped to the requested domain.
#[derive(Default)]
pub struct RaftOauth2KeyBackend {}

impl RaftOauth2KeyBackend {
    async fn ensure_domain_keys_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let repo = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new(domain_id, storage));
        repo.setup(algorithm)
            .await
            .map_err(Oauth2KeyProviderError::crypto)
    }

    async fn active_keys_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<ActiveKeys, Oauth2KeyProviderError> {
        let repo = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new(domain_id, storage));
        repo.load_active().await.map_err(|e| match e {
            openstack_keystone_key_repository::error::KeyRepositoryError::KeysMissing => {
                Oauth2KeyProviderError::NotFound(domain_id.to_string())
            }
            other => Oauth2KeyProviderError::crypto(other),
        })
    }
}

#[async_trait]
impl Oauth2KeyBackend for RaftOauth2KeyBackend {
    async fn ensure_domain_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.ensure_domain_keys_impl(storage, domain_id, algorithm)
            .await
    }

    async fn active_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<ActiveKeys, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.active_keys_impl(storage, domain_id).await
    }
}

/// Linkage anchor — see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    #[tokio::test]
    async fn test_setup_generates_and_load_active_round_trips() {
        let storage = MockStorage::default();
        let source = RaftAsymmetricKeySource::new("domain-1", &storage);
        let repo = AsymmetricKeyRepository::new(source);

        let key = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        let active = repo.load_active().await.unwrap();
        assert_eq!(active.primary.kid, key.kid);
        assert!(active.previous.is_none());
    }

    #[tokio::test]
    async fn test_setup_is_idempotent() {
        let storage = MockStorage::default();
        let source = RaftAsymmetricKeySource::new("domain-1", &storage);
        let repo = AsymmetricKeyRepository::new(source);

        let first = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        let second = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        assert_eq!(first.kid, second.kid);
    }

    #[tokio::test]
    async fn test_domains_are_isolated() {
        let storage = MockStorage::default();
        let a = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new("domain-a", &storage));
        let b = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new("domain-b", &storage));

        let key_a = a.setup(SigningAlgorithm::Es256).await.unwrap();
        let key_b = b.setup(SigningAlgorithm::Es256).await.unwrap();
        assert_ne!(key_a.kid, key_b.kid);

        let active_a = a.load_active().await.unwrap();
        assert_eq!(active_a.primary.kid, key_a.kid);
    }

    #[tokio::test]
    async fn test_promote_pending_to_primary_is_atomic() {
        let storage = MockStorage::default();
        let source = RaftAsymmetricKeySource::new("domain-1", &storage);
        let repo = AsymmetricKeyRepository::new(source);

        let old_primary = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        let pending = repo.generate_keypair(SigningAlgorithm::Es256).unwrap();
        repo.source()
            .write(KeyRole::Pending, &pending)
            .await
            .unwrap();

        repo.source().promote_pending_to_primary().await.unwrap();

        let active = repo.load_active().await.unwrap();
        assert_eq!(active.primary.kid, pending.kid);
        assert_eq!(active.previous.unwrap().kid, old_primary.kid);

        let loaded = repo.source().load().await.unwrap();
        assert!(!loaded.contains_key(&KeyRole::Pending));
    }

    #[tokio::test]
    async fn test_backend_ensure_domain_keys_and_active_keys() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();
        let active = backend
            .active_keys_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert_eq!(active.primary.kid, created.kid);
    }

    #[tokio::test]
    async fn test_backend_active_keys_not_found_for_unknown_domain() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();

        let err = backend
            .active_keys_impl(&storage, "domain-unknown")
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2KeyProviderError::NotFound(_)));
    }
}
