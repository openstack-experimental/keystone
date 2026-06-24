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

use std::io;
use std::path::Path;
use std::sync::Arc;

use fjall::Database;
use openraft::RaftTypeConfig;
use openstack_keystone_storage_crypto::{DekEpoch, KekProvider, generate_dek};

pub mod api;
pub mod app;
pub mod grpc;
#[cfg(feature = "mock")]
pub mod mock;
pub mod network;
mod proto_impl;
pub mod preflight;
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
/// # Parameters
/// - `db_path`: Path to the Fjall database directory.
/// - `node_id`: Raft node ID; used as the high 8 bytes of log nonces.
/// - `kek`: Key Encryption Key provider for wrapping/unwrapping the DEK.
///
/// # Returns
/// `(FjallLogStore, FjallStateMachine)` sharing the same database handle.
pub async fn new<C, P: AsRef<Path>>(
    db_path: P,
    node_id: u64,
    kek: &dyn KekProvider,
) -> Result<(FjallLogStore<C>, FjallStateMachine), io::Error>
where
    C: RaftTypeConfig,
{
    let db_path = db_path.as_ref();
    let snapshot_dir = db_path.join("snapshots");
    let db = Database::builder(db_path)
        .open()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let db = Arc::new(db);

    // Bootstrap or load the DEK from the meta keyspace.
    let dek = bootstrap_dek(&db, kek).map_err(|e| io::Error::other(e.to_string()))?;
    let dek = Arc::new(dek);

    Ok((
        FjallLogStore::new(db.clone(), node_id, dek.clone())
            .map_err(|e| io::Error::other(e.to_string()))?,
        FjallStateMachine::new(db, snapshot_dir, dek)
            .map_err(|e| io::Error::other(e.to_string()))?,
    ))
}

/// Load the current DEK epoch from Fjall, or generate and persist a new one.
fn bootstrap_dek(
    db: &Database,
    kek: &dyn KekProvider,
) -> Result<DekEpoch, StoreError> {
    let meta = db.keyspace("meta", fjall::KeyspaceCreateOptions::default)?;

    if let Some(wrapped_bytes) = meta.get(META_DEK_CURRENT)? {
        // Existing DEK: unwrap and derive sub-keys.
        let raw = kek.unwrap_dek(wrapped_bytes.as_ref())?;
        let epoch = DekEpoch::from_raw(&raw, 0)?;
        Ok(epoch)
    } else {
        // First boot: generate fresh DEK, wrap under KEK, persist.
        let raw = generate_dek();
        let wrapped = kek.wrap_dek(&raw)?;
        meta.insert(META_DEK_CURRENT, &wrapped)?;
        db.persist(fjall::PersistMode::SyncAll)?;
        let epoch = DekEpoch::from_raw(&raw, 0)?;
        Ok(epoch)
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
            let kek = EnvKek::from_bytes([0x42u8; 32]);
            let (log_store, sm) = crate::new(td.path(), 1, &kek)
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
}
