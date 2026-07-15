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
//! (ADR 0026 §3, §10 Phase 1, §10 Phase 6).
use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_key::backend::Oauth2KeyBackend;
use openstack_keystone_core_types::oauth2_key::{Oauth2KeyProviderError, PendingRotationInfo};
use openstack_keystone_distributed_storage::{
    ApiStoreError as StoreError, Metadata, StorageApi, StoreDataEnvelope, store_command::Mutation,
};
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, AsymmetricKeyRepository, AsymmetricKeySource, KeyMaterial, KeyRole,
    SigningAlgorithm,
};

/// Dual-control confirmation window for an emergency rotation (ADR 0026 §3):
/// longer than DEK emergency rotation's 5 minutes, to accommodate
/// after-hours incident response.
const EMERGENCY_ROTATION_CONFIRM_WINDOW_SECS: i64 = 15 * 60;

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
    #[serde(default)]
    demoted_at: Option<chrono::DateTime<chrono::Utc>>,
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
            demoted_at: value.demoted_at,
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
            demoted_at: value.demoted_at,
        }
    }
}

/// Prefix shared by every domain's signing-key entries, for the cross-domain
/// janitor scan (`list_all_active_keys_impl`). Assumes domain IDs never
/// contain `:` (true for identity domain IDs, which are opaque UUIDs/slugs),
/// so the tail of a full key unambiguously splits into `<domain_id>:<role>`.
const ALL_SIGNING_KEYS_PREFIX: &str = "oauth2:signing_key:v1:";

fn role_str(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Primary => "primary",
        KeyRole::Previous => "previous",
        KeyRole::Pending => "pending",
    }
}

fn key_name(domain_id: &str, role: KeyRole) -> String {
    format!("{ALL_SIGNING_KEYS_PREFIX}{domain_id}:{}", role_str(role))
}

fn key_prefix(domain_id: &str) -> String {
    format!("{ALL_SIGNING_KEYS_PREFIX}{domain_id}:")
}

fn role_from_key(key: &str, prefix: &str) -> Option<KeyRole> {
    match &key[prefix.len()..] {
        "primary" => Some(KeyRole::Primary),
        "previous" => Some(KeyRole::Previous),
        "pending" => Some(KeyRole::Pending),
        _ => None,
    }
}

fn parse_domain_and_role(key: &str) -> Option<(String, KeyRole)> {
    let rest = key.strip_prefix(ALL_SIGNING_KEYS_PREFIX)?;
    let (domain_id, role_str) = rest.rsplit_once(':')?;
    let role = match role_str {
        "primary" => KeyRole::Primary,
        "previous" => KeyRole::Previous,
        "pending" => KeyRole::Pending,
        _ => return None,
    };
    Some((domain_id.to_string(), role))
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

/// Wire record for a staged emergency rotation (ADR 0026 §3). Stored
/// separately from the normal-rotation `Pending` role so the two rotation
/// flows never collide over the same storage slot.
#[derive(Serialize, Deserialize)]
struct StoredPendingRotation {
    rotation_id: String,
    key: StoredKeyMaterial,
    initiator: String,
    expires_at: i64,
}

fn pending_emergency_key_name(domain_id: &str) -> String {
    format!("oauth2:pending_emergency_rotation:v1:{domain_id}")
}

fn jti_revocation_key_name(domain_id: &str) -> String {
    format!("oauth2:jti_revocation:v1:{domain_id}")
}

fn now_epoch_secs() -> i64 {
    chrono::Utc::now().timestamp()
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

    /// Normal rotation: generate a fresh keypair and promote it directly to
    /// `Primary` (demoting the current `Primary` to `Previous`) in a single
    /// Raft transaction -- ADR 0026 §3 "Normal Rotation Flow" describes the
    /// pending-then-promote sequence as landing "in the same Raft proposal",
    /// which a separate `write(Pending)` call followed by a separate
    /// `promote_pending_to_primary()` call does not guarantee: two
    /// concurrent rotations could otherwise interleave so that one caller's
    /// freshly generated key is silently overwritten in the shared
    /// `Pending` slot before it's ever promoted, and that caller's response
    /// would report a `kid` that never actually became `Primary`. Uses the
    /// operator-configured `algorithm` rather than the outgoing key's own
    /// algorithm, so a `[oauth2] signing_algorithm` change takes effect on
    /// the domain's next rotation.
    async fn rotate_signing_key_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let repo = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new(domain_id, storage));
        // Rotation requires an existing Primary; this is also how the
        // caller learns the domain has no keys yet.
        let active = self.active_keys_impl(storage, domain_id).await?;
        let fresh = repo
            .generate_keypair(algorithm)
            .map_err(Oauth2KeyProviderError::crypto)?;
        let demoted_primary = KeyMaterial {
            demoted_at: Some(chrono::Utc::now()),
            ..active.primary
        };

        let mutations = vec![
            key_set_mutation(domain_id, KeyRole::Primary, &fresh)
                .map_err(store_err_to_key_repo_err)
                .map_err(Oauth2KeyProviderError::crypto)?,
            key_set_mutation(domain_id, KeyRole::Previous, &demoted_primary)
                .map_err(store_err_to_key_repo_err)
                .map_err(Oauth2KeyProviderError::crypto)?,
        ];
        storage
            .transaction(mutations)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;

        Ok(fresh)
    }

    /// Emergency rotation stage 1: generate the replacement keypair now
    /// (mirroring the DEK emergency flow's own stage-1 generation) and
    /// persist it as a pending record, not yet active.
    ///
    /// Rejects outright (rather than silently overwriting) if a pending
    /// rotation for this domain already exists and hasn't expired: two
    /// operators staging concurrently during an incident must not let the
    /// second stage silently orphan the first's `rotation_id`, which would
    /// otherwise fail confirmation with a confusing `NoPendingRotation` in
    /// the middle of a security incident.
    async fn stage_emergency_rotation_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        algorithm: SigningAlgorithm,
        initiator: &str,
    ) -> Result<PendingRotationInfo, Oauth2KeyProviderError> {
        if let Some(existing) = self.load_pending_rotation(storage, domain_id).await?
            && existing.expires_at > now_epoch_secs()
        {
            return Err(Oauth2KeyProviderError::EmergencyRotationAlreadyPending(
                existing.rotation_id,
            ));
        }

        let repo = AsymmetricKeyRepository::new(RaftAsymmetricKeySource::new(domain_id, storage));
        let fresh = repo
            .generate_keypair(algorithm)
            .map_err(Oauth2KeyProviderError::crypto)?;
        let rotation_id = uuid::Uuid::new_v4().to_string();
        let expires_at = now_epoch_secs() + EMERGENCY_ROTATION_CONFIRM_WINDOW_SECS;

        let record = StoredPendingRotation {
            rotation_id: rotation_id.clone(),
            key: StoredKeyMaterial::from(&fresh),
            initiator: initiator.to_string(),
            expires_at,
        };
        let envelope = StoreDataEnvelope {
            data: rmp_serde::to_vec(&record)
                .map_err(|e| Oauth2KeyProviderError::Crypto(e.to_string()))?,
            metadata: Metadata::new(),
        };
        storage
            .set_value(pending_emergency_key_name(domain_id), envelope, None, None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;

        Ok(PendingRotationInfo {
            rotation_id,
            expires_at,
        })
    }

    /// Load the pending emergency rotation record for `domain_id`, if any
    /// (regardless of expiry -- callers decide how to treat an expired
    /// record). Shared by [`Self::stage_emergency_rotation_impl`]'s
    /// already-pending check and [`Self::confirm_emergency_rotation_impl`].
    async fn load_pending_rotation(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<Option<StoredPendingRotation>, Oauth2KeyProviderError> {
        let key = pending_emergency_key_name(domain_id);
        let Some(envelope) = storage
            .get_by_key(key.as_bytes(), None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?
        else {
            return Ok(None);
        };
        let stored: StoreDataEnvelope<StoredPendingRotation> = envelope
            .try_deserialize()
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;
        Ok(Some(stored.data))
    }

    /// Emergency rotation stage 2: validate, promote, revoke.
    ///
    /// Promotes the staged key to `Primary` (demoting the current `Primary`
    /// to `Previous`) and removes the pending-rotation record in a single
    /// Raft transaction, for the same reason `rotate_signing_key_impl` does:
    /// no observable intermediate state, and no window where a concurrent
    /// caller could interleave with a separate write(Pending) +
    /// promote_pending_to_primary() pair.
    async fn confirm_emergency_rotation_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        rotation_id: &str,
        confirmer: &str,
        revoke_jtis: Vec<String>,
        jti_ttl_secs: i64,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let record = self
            .load_pending_rotation(storage, domain_id)
            .await?
            .ok_or_else(|| Oauth2KeyProviderError::NoPendingRotation(rotation_id.to_string()))?;

        if record.rotation_id != rotation_id {
            return Err(Oauth2KeyProviderError::NoPendingRotation(
                rotation_id.to_string(),
            ));
        }
        if record.expires_at <= now_epoch_secs() {
            return Err(Oauth2KeyProviderError::RotationExpired(
                rotation_id.to_string(),
            ));
        }
        if record.initiator == confirmer {
            return Err(Oauth2KeyProviderError::DualControlViolation);
        }

        let new_primary = KeyMaterial::from(record.key);
        let active = self.active_keys_impl(storage, domain_id).await?;
        let demoted_primary = KeyMaterial {
            demoted_at: Some(chrono::Utc::now()),
            ..active.primary
        };

        let mutations = vec![
            key_set_mutation(domain_id, KeyRole::Primary, &new_primary)
                .map_err(store_err_to_key_repo_err)
                .map_err(Oauth2KeyProviderError::crypto)?,
            key_set_mutation(domain_id, KeyRole::Previous, &demoted_primary)
                .map_err(store_err_to_key_repo_err)
                .map_err(Oauth2KeyProviderError::crypto)?,
            Mutation::remove(pending_emergency_key_name(domain_id), None::<&str>, None),
        ];
        storage
            .transaction(mutations)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;

        if !revoke_jtis.is_empty() {
            self.add_revoked_jtis_impl(storage, domain_id, revoke_jtis, jti_ttl_secs)
                .await?;
        }

        Ok(new_primary)
    }

    async fn load_jti_revocations(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<HashMap<String, i64>, Oauth2KeyProviderError> {
        let key = jti_revocation_key_name(domain_id);
        let Some(envelope) = storage
            .get_by_key(key.as_bytes(), None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?
        else {
            return Ok(HashMap::new());
        };
        let stored: StoreDataEnvelope<HashMap<String, i64>> = envelope
            .try_deserialize()
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;
        Ok(stored.data)
    }

    async fn add_revoked_jtis_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        new_jtis: Vec<String>,
        ttl_secs: i64,
    ) -> Result<(), Oauth2KeyProviderError> {
        let mut current = self.load_jti_revocations(storage, domain_id).await?;
        let now = now_epoch_secs();
        // Lazy-sweep expired entries (ADR 0020 §4.A posture) on every write,
        // so the list never grows unbounded even without a dedicated
        // janitor task.
        current.retain(|_, expires_at| *expires_at > now);
        let expires_at = now + ttl_secs;
        for jti in new_jtis {
            current.insert(jti, expires_at);
        }

        let envelope = StoreDataEnvelope {
            data: rmp_serde::to_vec(&current)
                .map_err(|e| Oauth2KeyProviderError::Crypto(e.to_string()))?,
            metadata: Metadata::new(),
        };
        storage
            .set_value(jti_revocation_key_name(domain_id), envelope, None, None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;
        Ok(())
    }

    async fn revoked_jtis_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<HashSet<String>, Oauth2KeyProviderError> {
        let current = self.load_jti_revocations(storage, domain_id).await?;
        let now = now_epoch_secs();
        Ok(current
            .into_iter()
            .filter(|(_, expires_at)| *expires_at > now)
            .map(|(jti, _)| jti)
            .collect())
    }

    /// Cross-domain scan for the previous-key/JTI janitor: every domain
    /// that currently has a `Primary` signing key, with its `Previous` (if
    /// any). Mirrors `api-key-driver-raft`'s `list_all_impl` cross-domain
    /// prefix scan.
    async fn list_all_active_keys_impl(
        &self,
        storage: &dyn StorageApi,
    ) -> Result<Vec<(String, ActiveKeys)>, Oauth2KeyProviderError> {
        let entries = storage
            .prefix(ALL_SIGNING_KEYS_PREFIX.as_bytes(), None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;

        let mut by_domain: BTreeMap<String, BTreeMap<KeyRole, KeyMaterial>> = BTreeMap::new();
        for (key, envelope) in entries {
            let Some((domain_id, role)) = parse_domain_and_role(&key) else {
                continue;
            };
            let stored: StoreDataEnvelope<StoredKeyMaterial> = envelope
                .try_deserialize()
                .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;
            by_domain
                .entry(domain_id)
                .or_default()
                .insert(role, KeyMaterial::from(stored.data));
        }

        Ok(by_domain
            .into_iter()
            .filter_map(|(domain_id, mut roles)| {
                let primary = roles.remove(&KeyRole::Primary)?;
                let previous = roles.remove(&KeyRole::Previous);
                Some((domain_id, ActiveKeys { primary, previous }))
            })
            .collect())
    }

    /// Remove `domain_id`'s `Previous` signing key, if present. Idempotent:
    /// returns `false` (not an error) when there was nothing to remove, so
    /// the janitor can safely call this every sweep without tracking state
    /// across passes.
    async fn retire_previous_key_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<bool, Oauth2KeyProviderError> {
        let key = key_name(domain_id, KeyRole::Previous);
        let existed = storage
            .get_by_key(key.as_bytes(), None)
            .await
            .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?
            .is_some();
        if existed {
            storage
                .remove(key, None)
                .await
                .map_err(|e| Oauth2KeyProviderError::raft(store_err_to_key_repo_err(e)))?;
        }
        Ok(existed)
    }

    /// Proactively sweep `domain_id`'s JTI revocation list for expired
    /// entries. `add_revoked_jtis_impl` already lazy-sweeps on every write
    /// (ADR 0020 §4.A posture); this just triggers that same rewrite with no
    /// new entries, for domains that see no emergency rotations to trigger
    /// it otherwise.
    async fn prune_expired_jtis_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        jti_ttl_secs: i64,
    ) -> Result<(), Oauth2KeyProviderError> {
        self.add_revoked_jtis_impl(storage, domain_id, vec![], jti_ttl_secs)
            .await
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

    async fn rotate_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.rotate_signing_key_impl(storage, domain_id, algorithm)
            .await
    }

    async fn stage_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
        initiator: &str,
    ) -> Result<PendingRotationInfo, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.stage_emergency_rotation_impl(storage, domain_id, algorithm, initiator)
            .await
    }

    async fn confirm_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        rotation_id: &str,
        confirmer: &str,
        revoke_jtis: Vec<String>,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        let jti_ttl_secs = i64::from(
            state
                .config_manager
                .config
                .read()
                .await
                .oauth2
                .access_token_lifetime_minutes,
        ) * 60;
        self.confirm_emergency_rotation_impl(
            storage,
            domain_id,
            rotation_id,
            confirmer,
            revoke_jtis,
            jti_ttl_secs,
        )
        .await
    }

    async fn revoked_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<HashSet<String>, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.revoked_jtis_impl(storage, domain_id).await
    }

    async fn list_all_active_keys(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<(String, ActiveKeys)>, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.list_all_active_keys_impl(storage).await
    }

    async fn retire_previous_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<bool, Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        self.retire_previous_key_impl(storage, domain_id).await
    }

    async fn prune_expired_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<(), Oauth2KeyProviderError> {
        let storage = state
            .storage
            .as_deref()
            .ok_or(Oauth2KeyProviderError::RaftNotAvailable)?;
        let jti_ttl_secs = i64::from(
            state
                .config_manager
                .config
                .read()
                .await
                .oauth2
                .access_token_lifetime_minutes,
        ) * 60;
        self.prune_expired_jtis_impl(storage, domain_id, jti_ttl_secs)
            .await
    }
}

/// Linkage anchor — see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;
    use openstack_keystone_key_repository::asymmetric::generate_keypair;

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

    #[tokio::test]
    async fn test_rotate_signing_key_promotes_fresh_key_and_demotes_old_primary() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        let original = backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();

        let rotated = backend
            .rotate_signing_key_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();
        assert_ne!(rotated.kid, original.kid);

        let active = backend
            .active_keys_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert_eq!(active.primary.kid, rotated.kid);
        assert_eq!(active.previous.unwrap().kid, original.kid);
    }

    #[tokio::test]
    async fn test_rotate_signing_key_fails_without_existing_domain_keys() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();

        let err = backend
            .rotate_signing_key_impl(&storage, "domain-unknown", SigningAlgorithm::Es256)
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2KeyProviderError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_emergency_rotation_full_dual_control_flow() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        let original = backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();

        let pending = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-a",
            )
            .await
            .unwrap();

        let rotated = backend
            .confirm_emergency_rotation_impl(
                &storage,
                "domain-1",
                &pending.rotation_id,
                "operator-b",
                vec!["compromised-jti-1".to_string()],
                900,
            )
            .await
            .unwrap();
        assert_ne!(rotated.kid, original.kid);

        let active = backend
            .active_keys_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert_eq!(active.primary.kid, rotated.kid);
        assert_eq!(active.previous.unwrap().kid, original.kid);

        let revoked = backend
            .revoked_jtis_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert!(revoked.contains("compromised-jti-1"));
    }

    #[tokio::test]
    async fn test_stage_emergency_rotation_rejects_when_already_pending() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();

        let first = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-a",
            )
            .await
            .unwrap();

        // A second operator staging concurrently must not silently overwrite
        // the first's still-valid pending rotation.
        let err = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-b",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Oauth2KeyProviderError::EmergencyRotationAlreadyPending(id) if id == first.rotation_id
        ));
    }

    #[tokio::test]
    async fn test_stage_emergency_rotation_allowed_after_expiry() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();
        let first = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-a",
            )
            .await
            .unwrap();

        // Simulate the first pending rotation having already expired.
        let expired_record = StoredPendingRotation {
            rotation_id: first.rotation_id.clone(),
            key: StoredKeyMaterial::from(&generate_keypair(SigningAlgorithm::Es256).unwrap()),
            initiator: "operator-a".to_string(),
            expires_at: now_epoch_secs() - 1,
        };
        let envelope = StoreDataEnvelope {
            data: rmp_serde::to_vec(&expired_record).unwrap(),
            metadata: Metadata::new(),
        };
        storage
            .set_value(pending_emergency_key_name("domain-1"), envelope, None, None)
            .await
            .unwrap();

        // A fresh stage must succeed once the prior one has expired.
        let second = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-b",
            )
            .await
            .unwrap();
        assert_ne!(second.rotation_id, first.rotation_id);
    }

    #[tokio::test]
    async fn test_confirm_emergency_rotation_rejects_same_operator() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();
        let pending = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-a",
            )
            .await
            .unwrap();

        let err = backend
            .confirm_emergency_rotation_impl(
                &storage,
                "domain-1",
                &pending.rotation_id,
                "operator-a",
                vec![],
                900,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2KeyProviderError::DualControlViolation));
    }

    #[tokio::test]
    async fn test_confirm_emergency_rotation_rejects_unknown_rotation_id() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();

        let err = backend
            .confirm_emergency_rotation_impl(
                &storage,
                "domain-1",
                "not-a-real-rotation-id",
                "operator-b",
                vec![],
                900,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2KeyProviderError::NoPendingRotation(_)));
    }

    #[tokio::test]
    async fn test_confirm_emergency_rotation_rejects_expired_window() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();
        backend
            .ensure_domain_keys_impl(&storage, "domain-1", SigningAlgorithm::Es256)
            .await
            .unwrap();
        let pending = backend
            .stage_emergency_rotation_impl(
                &storage,
                "domain-1",
                SigningAlgorithm::Es256,
                "operator-a",
            )
            .await
            .unwrap();

        // Simulate the 15-minute window having already elapsed by staging
        // a record with an already-past `expires_at` directly.
        let expired_record = StoredPendingRotation {
            rotation_id: pending.rotation_id.clone(),
            key: StoredKeyMaterial::from(&generate_keypair(SigningAlgorithm::Es256).unwrap()),
            initiator: "operator-a".to_string(),
            expires_at: now_epoch_secs() - 1,
        };
        let envelope = StoreDataEnvelope {
            data: rmp_serde::to_vec(&expired_record).unwrap(),
            metadata: Metadata::new(),
        };
        storage
            .set_value(pending_emergency_key_name("domain-1"), envelope, None, None)
            .await
            .unwrap();

        let err = backend
            .confirm_emergency_rotation_impl(
                &storage,
                "domain-1",
                &pending.rotation_id,
                "operator-b",
                vec![],
                900,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2KeyProviderError::RotationExpired(_)));
    }

    #[tokio::test]
    async fn test_revoked_jtis_excludes_expired_entries() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();

        backend
            .add_revoked_jtis_impl(&storage, "domain-1", vec!["fresh-jti".to_string()], 900)
            .await
            .unwrap();
        // A TTL of -1 second is already expired the instant it's written.
        backend
            .add_revoked_jtis_impl(&storage, "domain-1", vec!["stale-jti".to_string()], -1)
            .await
            .unwrap();

        let revoked = backend
            .revoked_jtis_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert!(revoked.contains("fresh-jti"));
        assert!(!revoked.contains("stale-jti"));
    }

    #[tokio::test]
    async fn test_jti_revocation_lists_are_isolated_per_domain() {
        let backend = RaftOauth2KeyBackend::default();
        let storage = MockStorage::default();

        backend
            .add_revoked_jtis_impl(&storage, "domain-a", vec!["jti-a".to_string()], 900)
            .await
            .unwrap();

        let revoked_a = backend
            .revoked_jtis_impl(&storage, "domain-a")
            .await
            .unwrap();
        let revoked_b = backend
            .revoked_jtis_impl(&storage, "domain-b")
            .await
            .unwrap();
        assert!(revoked_a.contains("jti-a"));
        assert!(revoked_b.is_empty());
    }
}
