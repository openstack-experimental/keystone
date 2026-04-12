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

pub use crate::TypeConfig;

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
