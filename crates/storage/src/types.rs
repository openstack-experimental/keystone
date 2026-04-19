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

// Declare the Raft type with the TypeConfig.
// Reference the containing module's type config and re-export it.
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::TypeConfig;
use crate::error::StoreError;

pub type NodeId = u64;
//pub type LogStore = crate::store::log_store::FjallLogStore<TypeConfig>;
// pub type LogStore =
// crate::store::log_store::FjallLogStore<crate::TypeConfig>;
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

/// The metadata of the stored data.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Metadata {
    /// The resource revision.
    pub revision: u64,
    /// The timestamp when the resource was created.
    pub created_at: i64,
}

impl Metadata {
    pub fn new() -> Self {
        Self {
            revision: 0,
            created_at: Utc::now().timestamp(),
        }
    }

    pub fn increment_revision(&mut self) {
        self.revision = self.revision + 1;
    }

    /// Pack the metadata for storing in the db.
    ///
    /// Serialize the metadata into the bytes using the MsgPack format.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Bytes vector.
    /// * `Err(StoreError)` - Error.
    pub(crate) fn pack(&self) -> Result<Vec<u8>, StoreError> {
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Unpack the metadata stored in the storage.
    ///
    /// Unpack the data from the bytes array with the metadata
    ///
    /// # Arguments
    /// * `value` - The binary data.
    ///
    /// # Returns
    /// * `Ok(StoreDataResponse)` - Success response with the deserialized metadata.
    /// * `Err(StoreError)` - Error if the operation fails.
    pub(crate) fn unpack(value: &[u8]) -> Result<Self, StoreError> {
        Ok(rmp_serde::from_slice(value)?)
    }
}

/// The nonce used as an authentication for the data encryption.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Nonce(u64, u64);

impl Nonce {
    pub fn new(term: u64, last_applied_index: u64) -> Self {
        Self(term, last_applied_index)
    }
}

/// The envelope of the storage data.
///
/// The data wrapped in the envelope for storing encrypted at-rest in the database.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct StoreDataInnerEnvelope {
    /// The resource itself.
    #[serde(with = "serde_bytes")]
    pub(crate) cipher: Vec<u8>,
    /// The encryption nonce.
    pub(crate) nonce: Nonce,
}

impl StoreDataInnerEnvelope {
    /// Pack the data together with the associated metadata for storing in the db.
    ///
    /// Serialize the data into the bytes using the MsgPack format.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Bytes vector.
    /// * `Err(StoreError)` - Error.
    pub(crate) fn pack(&self) -> Result<Vec<u8>, StoreError> {
        // TODO: data should be encrypted here before packaging
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Unpack the data stored in the storage.
    ///
    /// Unpack the data from the bytes array with the metadata
    ///
    /// # Arguments
    /// * `value` - The binary data.
    ///
    /// # Returns
    /// * `Ok(StoreDataResponse)` - Success response with the deserialized data and the associated
    /// metadata.
    /// * `Err(StoreError)` - Error if the operation fails.
    pub(crate) fn unpack<T: DeserializeOwned>(value: &[u8]) -> Result<T, StoreError> {
        let raw_envelope: StoreDataInnerEnvelope = rmp_serde::from_slice(value)?;
        // TODO: decrypt the data.
        let data: T = rmp_serde::from_slice(&raw_envelope.cipher)?;
        Ok(data)
    }
}

#[cfg(feature = "bench_internals")]
pub fn bench_pack(payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    StoreDataInnerEnvelope {
        cipher: payload.to_vec(),
        nonce: Nonce::default(),
    }
    .pack()
}

#[cfg(feature = "bench_internals")]
pub fn bench_unpack(payload: &[u8]) -> Result<StoreDataEnvelope<String>, StoreError> {
    StoreDataInnerEnvelope::unpack(payload)
}

/// The store data object with the associated metadata.
///
/// An envelope for transferring the store data with the associated metadata unencrypted over the wire.
#[derive(Debug, Deserialize, PartialEq)]
pub struct StoreDataEnvelope<T> {
    /// The resource metadata.
    pub metadata: Metadata,
    /// The resource itself.
    //#[serde(with = "serde_bytes")]
    pub data: T,
}

impl From<&str> for StoreDataEnvelope<String> {
    fn from(value: &str) -> Self {
        Self {
            metadata: Metadata::new(),
            data: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_serde() {
        let data = StoreDataInnerEnvelope {
            cipher: rmp_serde::to_vec("foo").unwrap(),
            nonce: Nonce::default(),
        };
        let packed = data.pack().unwrap();
        let unpacked = StoreDataInnerEnvelope::unpack::<String>(&packed).unwrap();
        assert_eq!("foo", unpacked);
    }
}
