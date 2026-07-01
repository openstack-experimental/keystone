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
//! # Keystone distributed storage.
//!
//! A distributed storage for OpenStack Keystone backed by Raft and Fjall KV
//! database.

#![deny(clippy::mem_forget)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use fjall::Database;
use openraft::RaftTypeConfig;
use openstack_keystone_storage_crypto::{DekEpoch, KekProvider, LockedKey, generate_dek};

pub mod api;
pub mod app;
pub mod audit;
pub mod grpc;
#[cfg(feature = "mock")]
pub mod mock;
pub mod network;
pub mod preflight;
mod proto_impl;
mod types;
pub mod store {
    pub mod log_store;
    pub mod state_machine;
}
mod error;
pub mod store_command;

// Re-export lightweight types from storage-api crate.
pub use openstack_keystone_storage_api::{
    DataTier, Metadata, Mutation, Node, StorageApi, StoreDataEnvelope, StoreError as ApiStoreError,
    StoreResponse, Violation,
};

pub use error::StoreError;
pub use store::log_store::FjallLogStore;
pub use store::state_machine::FjallStateMachine;

/// DEK meta key used to persist the wrapped DEK in Fjall.
const META_DEK_CURRENT: &[u8] = b"_meta:dek:current";

/// Convert the heavy storage error type to the lightweight API error type.
impl From<StoreError> for ApiStoreError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::ConfigMissing => Self::ConfigMissing,
            StoreError::Conflict {
                subject,
                description,
            } => Self::Conflict {
                subject,
                description,
            },
            StoreError::KeyPresent => Self::KeyPresent,
            StoreError::Quarantined(partition) => Self::Conflict {
                subject: partition,
                description: "partition quarantined due to repeated GCM tag failures".to_string(),
            },
            StoreError::WriteRateExceeded(key, version) => Self::Conflict {
                subject: key,
                description: format!(
                    "write rate exceeded at version {version}; DEK rotation required"
                ),
            },
            _ => Self::Other(Box::new(e)),
        }
    }
}

pub mod protobuf {
    pub mod api {
        use serde::{Deserialize, Serialize};
        tonic::include_proto!("keystone.api");
    }
    pub mod raft {
        use serde::{Deserialize, Serialize};
        tonic::include_proto!("keystone.raft");
    }
}
pub use crate::protobuf as pb;

openraft::declare_raft_types!(
    /// Declare the type configuration for example K/V store.
    pub TypeConfig:
        D = pb::api::CommandRequest,
        R = pb::api::Response,
        LeaderId = pb::raft::LeaderId,
        Vote = pb::raft::Vote,
        Entry = pb::raft::Entry,
        Node = pb::raft::Node,
        SnapshotData = Vec<u8>,
);

/// Create a pair of `FjallLogStore` and `FjallStateMachine` sharing a Fjall DB.
///
/// Bootstraps the DEK on first boot (generates a fresh key, wraps it under the
/// KEK, persists it to `_meta:dek:current`) or loads it on subsequent boots.
///
/// Returns the pair of stores plus the shared `current_dek` handle (for use by
/// the `rotate_dek` gRPC handler and other admin operations that need to know
/// the current DEK epoch version).
///
/// # Parameters
/// - `db_path`: Path to the Fjall database directory.
/// - `node_id`: Raft node ID; used as the high 8 bytes of log nonces.
/// - `kek`: Key Encryption Key provider for wrapping/unwrapping the DEK.
///
/// # Returns
/// `(FjallLogStore, FjallStateMachine, Arc<RwLock<Arc<DekEpoch>>>,
/// Arc<Mutex<HashSet<u32>>>, Arc<Mutex<HashMap<String, PendingRotation>>>,
/// Receiver<(u64, String)>)`. The receiver yields `(node_id, partition)`
/// quarantine events that the caller should propose via Raft once it has a
/// handle to the `Raft` instance (see `app::init_storage`).
pub async fn new<C, P: AsRef<Path>>(
    db_path: P,
    node_id: u64,
    kek: Arc<dyn KekProvider>,
) -> Result<
    (
        FjallLogStore<C>,
        FjallStateMachine,
        Arc<RwLock<Arc<DekEpoch>>>,
        Arc<Mutex<HashSet<u32>>>,
        Arc<Mutex<HashMap<String, store_command::PendingRotation>>>,
        tokio::sync::mpsc::Receiver<(u64, String)>,
    ),
    io::Error,
>
where
    C: RaftTypeConfig,
{
    let db_path = db_path.as_ref();
    let snapshot_dir = db_path.join("snapshots");
    let db = Arc::new(
        Database::builder(db_path)
            .open()
            .map_err(|e| io::Error::other(e.to_string()))?,
    );

    // Bootstrap or load the DEK from the meta keyspace.
    let initial_epoch =
        bootstrap_dek(&db, kek.as_ref()).map_err(|e| io::Error::other(e.to_string()))?;
    let current_dek: Arc<RwLock<Arc<DekEpoch>>> = Arc::new(RwLock::new(initial_epoch));
    // Load retired DEK epochs from Fjall so pre-rotation ciphertext remains
    // readable across restarts (C3: old_deks must survive process restarts).
    let retired_map =
        load_retired_deks(&db, kek.as_ref()).map_err(|e| io::Error::other(e.to_string()))?;
    let old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>> = Arc::new(Mutex::new(retired_map));
    // Load revoked DEK versions from Fjall so an emergency rotation's
    // containment guarantee survives a restart (ADR 0016-v2 §6.2 step 5).
    let revoked_set = load_revoked_deks(&db).map_err(|e| io::Error::other(e.to_string()))?;
    let revoked_deks: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(revoked_set));

    // Load any pending emergency rotations that were staged before a restart.
    let meta_ks = db
        .keyspace("meta", fjall::KeyspaceCreateOptions::default)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let pending_map = crate::store::state_machine::load_pending_rotations(&meta_ks)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let pending_rotations: Arc<Mutex<HashMap<String, store_command::PendingRotation>>> =
        Arc::new(Mutex::new(pending_map));

    let (reencrypt_tx, mut reencrypt_rx) = tokio::sync::mpsc::channel::<Arc<DekEpoch>>(16);
    // Stub re-encryption task: drains the channel and logs.
    // Full background re-encryption of state entries is deferred to Phase 5.2.
    tokio::spawn(async move {
        while let Some(old_epoch) = reencrypt_rx.recv().await {
            tracing::info!(
                version = old_epoch.version,
                "DEK rotation: old epoch registered (re-encryption deferred to Phase 5.2)"
            );
        }
    });

    let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel::<(u64, String)>(16);

    let log_store = FjallLogStore::new(
        db.clone(),
        node_id,
        current_dek.clone(),
        old_deks.clone(),
        revoked_deks.clone(),
    )
    .map_err(|e| io::Error::other(e.to_string()))?;

    let sm = FjallStateMachine::new(
        db,
        snapshot_dir,
        node_id,
        current_dek.clone(),
        old_deks,
        revoked_deks.clone(),
        kek,
        reencrypt_tx,
        quarantine_tx,
        pending_rotations.clone(),
    )
    .map_err(|e| io::Error::other(e.to_string()))?;

    Ok((
        log_store,
        sm,
        current_dek,
        revoked_deks,
        pending_rotations,
        quarantine_rx,
    ))
}

/// Fjall meta key prefix for retired DEK epochs (mirrors the constant in
/// state_machine).
const DEK_RETIRED_PREFIX: &str = "_meta:dek:retired:";

/// Load retired DEK epochs from Fjall meta for post-rotation read fallback.
///
/// Retired epochs are stored under `_meta:dek:retired:VERSION` with the
/// wrapped DEK bytes as the value.  Any epoch that cannot be unwrapped or
/// parsed is skipped with a `WARN` log — startup proceeds so the node
/// remains available.
fn load_retired_deks(
    db: &Database,
    kek: &dyn KekProvider,
) -> Result<BTreeMap<u32, Arc<DekEpoch>>, StoreError> {
    let meta = db.keyspace("meta", fjall::KeyspaceCreateOptions::default)?;
    let mut map = BTreeMap::new();
    for item in meta.prefix(DEK_RETIRED_PREFIX.as_bytes()) {
        let (key_bytes, wrapped_bytes) = item.into_inner()?;
        let key_str = match std::str::from_utf8(&key_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => continue,
        };
        let version_str = match key_str.strip_prefix(DEK_RETIRED_PREFIX) {
            Some(s) => s,
            None => continue,
        };
        let version: u32 = match version_str.parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    key = key_str,
                    "retired DEK key has non-numeric version suffix"
                );
                continue;
            }
        };
        match kek.unwrap_dek(&wrapped_bytes) {
            Ok(raw) => {
                let epoch_dek = LockedKey::from_raw(*raw);
                match DekEpoch::from_raw(epoch_dek, version) {
                    Ok(epoch) => {
                        tracing::info!(version, "loaded retired DEK epoch for read fallback");
                        map.insert(version, Arc::new(epoch));
                    }
                    Err(e) => {
                        tracing::warn!(version, error = %e, "failed to construct retired DEK epoch");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(version, error = %e, "failed to unwrap retired DEK — skipping");
            }
        }
    }
    Ok(map)
}

/// Fjall meta key prefix for revoked DEK epochs (mirrors the constant in
/// state_machine).
const DEK_REVOKED_PREFIX: &str = crate::store::state_machine::DEK_REVOKED_PREFIX;

/// Load revoked DEK versions from Fjall meta so an emergency rotation's
/// containment guarantee survives a restart (ADR 0016-v2 §6.2 step 5).
///
/// Only the version is recovered — the stored value is a revocation
/// timestamp, never key material, since revoked DEKs are discarded
/// immediately and must never be reconstructable.
fn load_revoked_deks(db: &Database) -> Result<HashSet<u32>, StoreError> {
    let meta = db.keyspace("meta", fjall::KeyspaceCreateOptions::default)?;
    let mut set = HashSet::new();
    for item in meta.prefix(DEK_REVOKED_PREFIX.as_bytes()) {
        let (key_bytes, _) = item.into_inner()?;
        let key_str = match std::str::from_utf8(&key_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => continue,
        };
        let version_str = match key_str.strip_prefix(DEK_REVOKED_PREFIX) {
            Some(s) => s,
            None => continue,
        };
        match version_str.parse::<u32>() {
            Ok(version) => {
                tracing::info!(version, "loaded revoked DEK marker");
                set.insert(version);
            }
            Err(_) => {
                tracing::warn!(
                    key = key_str,
                    "revoked DEK key has non-numeric version suffix"
                );
            }
        }
    }
    Ok(set)
}

/// Load the current DEK epoch from Fjall, or generate and persist a new one.
///
/// On-disk format for `_meta:dek:current`:
/// `[version_u32_BE; 4] ++ [nonce_12] ++ [ciphertext_32] ++ [tag_16]` (64 bytes
/// total). Legacy format (60 bytes, no version prefix) is migrated to version 1
/// on first load.
fn bootstrap_dek(db: &Database, kek: &dyn KekProvider) -> Result<Arc<DekEpoch>, StoreError> {
    let meta = db.keyspace("meta", fjall::KeyspaceCreateOptions::default)?;

    if let Some(stored) = meta.get(META_DEK_CURRENT)? {
        let stored = stored.as_ref();
        let (version, wrapped) = if stored.len() >= 64 {
            // New format: [version_u32_BE; 4] ++ wrapped_bytes.
            let version = u32::from_be_bytes(
                stored[..4]
                    .try_into()
                    .map_err(|_| StoreError::Other(eyre::eyre!("invalid DEK version prefix")))?,
            );
            (version, &stored[4..])
        } else if stored.len() == 60 {
            // Legacy format (no version prefix): treat as version 1 and migrate.
            tracing::warn!(
                "DEK stored in legacy format (no version prefix); treating as version 1"
            );
            let wrapped = stored;
            let raw = kek.unwrap_dek(wrapped)?;
            let raw_bytes = *raw;
            let mut migrated = 1u32.to_be_bytes().to_vec();
            migrated.extend_from_slice(&kek.wrap_dek(&raw_bytes)?);
            meta.insert(META_DEK_CURRENT, &migrated)?;
            db.persist(fjall::PersistMode::SyncAll)?;
            let epoch_dek = LockedKey::from_raw(raw_bytes);
            return Ok(Arc::new(DekEpoch::from_raw(epoch_dek, 1)?));
        } else {
            return Err(StoreError::Other(eyre::eyre!(
                "invalid DEK stored size: {} bytes",
                stored.len()
            )));
        };
        let raw = kek.unwrap_dek(wrapped)?;
        let epoch_dek = LockedKey::from_raw(*raw);
        Ok(Arc::new(DekEpoch::from_raw(epoch_dek, version)?))
    } else {
        // First boot: generate fresh DEK at version 1, wrap under KEK, persist.
        let dek = generate_dek();
        let wrapped = kek.wrap_dek(dek.as_bytes())?;
        let version = 1u32;
        let mut persisted = version.to_be_bytes().to_vec();
        persisted.extend_from_slice(&wrapped);
        meta.insert(META_DEK_CURRENT, &persisted)?;
        db.persist(fjall::PersistMode::SyncAll)?;
        // Pass the mlock'd key directly — no copy through bypass allocation.
        Ok(Arc::new(DekEpoch::from_raw(dek, version)?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openraft::StorageError;
    use openraft::testing::log::StoreBuilder;
    use openraft::testing::log::Suite;
    use openraft::type_config::TypeConfigExt;
    use openstack_keystone_storage_crypto::EnvKek;
    use tempfile::TempDir;
    use tracing_test::traced_test;

    use super::TypeConfig;
    use super::store::log_store::FjallLogStore;
    use super::store::state_machine::FjallStateMachine;

    struct FjallBuilder {}

    impl StoreBuilder<TypeConfig, FjallLogStore<TypeConfig>, Arc<FjallStateMachine>, TempDir>
        for FjallBuilder
    {
        async fn build(
            &self,
        ) -> Result<
            (TempDir, FjallLogStore<TypeConfig>, Arc<FjallStateMachine>),
            StorageError<TypeConfig>,
        > {
            let td =
                TempDir::new().map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))?;
            let kek: Arc<dyn openstack_keystone_storage_crypto::KekProvider> =
                Arc::new(EnvKek::from_bytes([0x42u8; 32]));
            let (log_store, sm, _current_dek, _revoked, _pending_rotations, _quarantine_rx) =
                crate::new(td.path(), 1, kek)
                    .await
                    .map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))?;
            Ok((td, log_store, Arc::new(sm)))
        }
    }

    #[test]
    #[traced_test]
    pub fn test_fjall_store() {
        TypeConfig::run(async {
            Suite::test_all(FjallBuilder {}).await.unwrap();
        });
    }

    /// Revoked DEK markers persisted to Fjall meta must be picked back up by
    /// `load_revoked_deks` after a restart (ADR 0016-v2 §6.2 step 5).
    #[test]
    #[traced_test]
    fn revoked_dek_marker_survives_restart() {
        TypeConfig::run(async {
            let td = TempDir::new().expect("tempdir");
            let db = Arc::new(fjall::Database::builder(td.path()).open().expect("open db"));
            let meta = db
                .keyspace("meta", fjall::KeyspaceCreateOptions::default)
                .expect("meta keyspace");

            // Simulate what the InstallDek apply path writes for an emergency
            // rotation: version + revocation timestamp, never key material.
            let revoked_key = format!("{}{}", super::DEK_REVOKED_PREFIX, 3u32);
            meta.insert(revoked_key.as_bytes(), 1_700_000_000u64.to_be_bytes())
                .expect("insert revoked marker");
            db.persist(fjall::PersistMode::SyncAll).expect("persist");

            let loaded = super::load_revoked_deks(&db).expect("load revoked deks");
            assert!(loaded.contains(&3u32));
            assert_eq!(loaded.len(), 1);
        });
    }
}
