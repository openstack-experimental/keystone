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

use std::sync::Arc;

use fjall::{Database, Keyspace, PersistMode};
use openstack_keystone_storage_crypto::CryptoError;
use openstack_keystone_storage_crypto::NoncePersistence;

pub use crate::TypeConfig;

// Re-export Metadata and StoreDataEnvelope from storage-api.
pub use crate::Metadata;
pub use crate::StoreDataEnvelope;

pub type NodeId = u64;
pub type StateMachineStore = crate::store::state_machine::FjallStateMachine;
pub type Raft = openraft::Raft<TypeConfig, std::sync::Arc<StateMachineStore>>;

pub type Membership = openraft::membership::Membership<
    <TypeConfig as openraft::RaftTypeConfig>::NodeId,
    <TypeConfig as openraft::RaftTypeConfig>::Node,
>;

pub type Vote = <TypeConfig as openraft::RaftTypeConfig>::Vote;
pub type LeaderId = <TypeConfig as openraft::RaftTypeConfig>::LeaderId;
pub type LogId = openraft::alias::LogIdOf<TypeConfig>;
pub type StoredMembership = openraft::alias::StoredMembershipOf<TypeConfig>;

pub type Node = <TypeConfig as openraft::RaftTypeConfig>::Node;

pub type SnapshotMeta = openraft::alias::SnapshotMetaOf<TypeConfig>;
pub type Snapshot = openraft::alias::SnapshotOf<TypeConfig>;
pub type RPCError<E = openraft::errors::Infallible> = openraft::error::RPCError<TypeConfig, E>;
pub type StreamingError = openraft::errors::StreamingError<TypeConfig>;
pub type ClientWriteError = openraft::errors::ClientWriteError<TypeConfig>;
pub type RaftMetrics = openraft::RaftMetrics<TypeConfig>;

pub type VoteRequest = openraft::raft::VoteRequest<TypeConfig>;
pub type VoteResponse = openraft::raft::VoteResponse<TypeConfig>;
pub type AppendEntriesRequest = openraft::raft::AppendEntriesRequest<TypeConfig>;
pub type AppendEntriesResponse = openraft::raft::AppendEntriesResponse<TypeConfig>;
pub type SnapshotResponse = openraft::raft::SnapshotResponse<TypeConfig>;
pub type ClientWriteResponse = openraft::raft::ClientWriteResponse<TypeConfig>;
pub type StreamAppendResult = openraft::raft::StreamAppendResult<TypeConfig>;

/// Fjall-backed persistence for the nonce counter manager.
///
/// Stores nonce counter and HWM as 8-byte big-endian values in the Raft
/// meta keyspace.  `flush` calls `Database::persist(SyncAll)` to guarantee
/// durability before returning.
pub struct FjallNoncePersistence {
    pub(crate) keyspace: Keyspace,
    pub(crate) db: Arc<Database>,
}

impl NoncePersistence for FjallNoncePersistence {
    fn read_u64(&self, key: &str) -> Result<Option<u64>, CryptoError> {
        let v = self
            .keyspace
            .get(key.as_bytes())
            .map_err(|e| CryptoError::NoncePersistence(e.to_string()))?;
        match v {
            None => Ok(None),
            Some(bytes) => {
                let arr: [u8; 8] = bytes.as_ref().try_into().map_err(|_| {
                    CryptoError::NoncePersistence("nonce value has unexpected length".into())
                })?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
        }
    }

    fn write_u64(&self, key: &str, value: u64) -> Result<(), CryptoError> {
        self.keyspace
            .insert(key.as_bytes(), value.to_be_bytes())
            .map_err(|e| CryptoError::NoncePersistence(e.to_string()))
    }

    fn flush(&self) -> Result<(), CryptoError> {
        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| CryptoError::NoncePersistence(e.to_string()))
    }
}
