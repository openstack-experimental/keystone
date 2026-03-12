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
use std::io;
use thiserror::Error;

/// Keystone Store error.
#[derive(Error, Debug)]
pub enum StoreError {
    /// Database error.
    #[error(transparent)]
    Fjall {
        #[from]
        source: fjall::Error,
    },

    #[error(transparent)]
    IO {
        #[from]
        source: std::io::Error,
    },

    #[error(transparent)]
    Json {
        #[from]
        source: serde_json::Error,
    },

    /// Raft config error.
    #[error(transparent)]
    RaftConfig {
        #[from]
        source: openraft::ConfigError,
    },

    /// Raft empty membership data error.
    #[error("raft membership information missing")]
    RaftEmptyMembership,

    /// Raft fatal error.
    #[error(transparent)]
    RaftFatal {
        #[from]
        source: openraft::error::Fatal<TypeConfig>,
    },

    /// Raft membership error.
    #[error(transparent)]
    RaftMembership {
        #[from]
        source: openraft::error::MembershipError<TypeConfig>,
    },

    /// Raft empty membership data error.
    #[error("raft required parameter {0} missing")]
    RaftMissingParameter(String),

    #[error(transparent)]
    Storage {
        #[from]
        source: openraft::StorageError<TypeConfig>,
    },
}

impl From<StoreError> for io::Error {
    fn from(value: StoreError) -> Self {
        io::Error::other(value.to_string())
    }
}

// Declare the Raft type with the TypeConfig.
// Reference the containing module's type config and re-export it.
pub use crate::TypeConfig;

pub type NodeId = u64;
// pub type LogStore =
// crate::store::log_store::FjallLogStore<crate::TypeConfig>;
pub type StateMachineStore = crate::store::state_machine::FjallStateMachine;
pub type Raft = openraft::Raft<TypeConfig>;

pub type Vote = <TypeConfig as openraft::RaftTypeConfig>::Vote;
pub type LeaderId = <TypeConfig as openraft::RaftTypeConfig>::LeaderId;
pub type LogId = openraft::LogId<TypeConfig>;
pub type StoredMembership = openraft::StoredMembership<TypeConfig>;

pub type Node = <TypeConfig as openraft::RaftTypeConfig>::Node;

pub type SnapshotMeta = openraft::SnapshotMeta<TypeConfig>;
pub type Snapshot = openraft::Snapshot<TypeConfig>;
pub type RPCError<E = openraft::error::Infallible> = openraft::error::RPCError<TypeConfig, E>;
pub type StreamingError = openraft::error::StreamingError<TypeConfig>;
//pub type RaftMetrics = openraft::RaftMetrics<TypeConfig>;

pub type VoteRequest = openraft::raft::VoteRequest<TypeConfig>;
pub type VoteResponse = openraft::raft::VoteResponse<TypeConfig>;
pub type AppendEntriesRequest = openraft::raft::AppendEntriesRequest<TypeConfig>;
pub type AppendEntriesResponse = openraft::raft::AppendEntriesResponse<TypeConfig>;
pub type SnapshotResponse = openraft::raft::SnapshotResponse<TypeConfig>;
pub type ClientWriteResponse = openraft::raft::ClientWriteResponse<TypeConfig>;
pub type StreamAppendResult = openraft::raft::StreamAppendResult<TypeConfig>;
