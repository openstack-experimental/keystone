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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::TypeConfig;

// Re-export Metadata and StoreDataEnvelope from storage-api.
pub use crate::Metadata;
pub use crate::StoreDataEnvelope;

use crate::StoreError;

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

/// The nonce used as an authentication for the data encryption.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Nonce(u64, u64);

impl Nonce {
    /// Create a new `Nonce`.
    ///
    /// # Parameters
    /// - `term`: The Raft term.
    /// - `last_applied_index`: The last applied index.
    ///
    /// # Returns
    /// A new `Nonce` instance.
    pub fn new(term: u64, last_applied_index: u64) -> Self {
        Self(term, last_applied_index)
    }
}

/// The envelope of the storage data.
///
/// The data wrapped in the envelope for storing encrypted at-rest in the
/// database.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct StoreDataInnerEnvelope {
    /// The resource itself.
    #[serde(with = "serde_bytes")]
    pub(crate) cipher: Vec<u8>,
    /// The encryption nonce.
    pub(crate) nonce: Nonce,
}

impl StoreDataInnerEnvelope {
    /// Pack the data together with the associated metadata for storing in the
    /// db.
    ///
    /// Serialize the data into the bytes using the MsgPack format.
    ///
    /// # Returns
    /// A `Result` containing the serialized bytes, or a `StoreError`.
    pub(crate) fn pack(&self) -> Result<Vec<u8>, StoreError> {
        // TODO: data should be encrypted here before packaging
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Unpack the data stored in the storage.
    ///
    /// Unpack the data from the bytes array with the metadata.
    ///
    /// # Parameters
    /// - `value`: The binary data.
    ///
    /// # Returns
    /// A `Result` containing the unpacked value of type `T`, or a `StoreError`.
    #[allow(dead_code)]
    pub(crate) fn unpack<T: DeserializeOwned>(value: &[u8]) -> Result<T, StoreError> {
        let raw_envelope: StoreDataInnerEnvelope = rmp_serde::from_slice(value)?;
        // TODO: decrypt the data.
        let data: T = rmp_serde::from_slice(&raw_envelope.cipher)?;
        Ok(data)
    }

    /// Unpack the stored data and return the raw cipher bytes without
    /// deserialization.
    ///
    /// This is used by the object-safe [`crate::StorageApi::get_by_key`] which
    /// returns `StoreDataEnvelope<Vec<u8>>`. The caller is responsible for
    /// deserializing the bytes into the expected type.
    ///
    /// # Parameters
    /// - `value`: The binary data.
    ///
    /// # Returns
    /// A `Result` containing the raw cipher bytes, or a `StoreError`.
    pub(crate) fn unpack_bytes(value: &[u8]) -> Result<Vec<u8>, StoreError> {
        let raw_envelope: StoreDataInnerEnvelope = rmp_serde::from_slice(value)?;
        // TODO: decrypt the data.
        Ok(raw_envelope.cipher)
    }
}

/// Benchmark packing of data.
///
/// # Parameters
/// - `payload`: The payload to pack.
///
/// # Returns
/// A `Result` containing the packed bytes, or a `StoreError`.
#[cfg(feature = "bench_internals")]
pub fn bench_pack(payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    StoreDataInnerEnvelope {
        cipher: payload.to_vec(),
        nonce: Nonce::default(),
    }
    .pack()
}

/// Benchmark unpacking of data.
///
/// # Parameters
/// - `payload`: The payload to unpack.
///
/// # Returns
/// A `Result` containing the unpacked `StoreDataEnvelope<String>`, or a
/// `StoreError`.
#[cfg(feature = "bench_internals")]
pub fn bench_unpack(payload: &[u8]) -> Result<StoreDataEnvelope<String>, StoreError> {
    StoreDataInnerEnvelope::unpack(payload)
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
