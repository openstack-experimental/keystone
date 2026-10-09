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
//! A replicated, encrypted key/value store for OpenStack Keystone, built on
//! [`openraft`] for consensus and Fjall for local persistence. Keystone
//! drivers use it through the [`StorageApi`] trait; the Raft driver crates
//! (`*-raft`) are its consumers.
//!
//! ## Layout
//!
//! - [`store`]: persistence. [`FjallLogStore`] holds the Raft log and
//!   [`FjallStateMachine`] applies committed entries, owns the encrypted
//!   `data`/`meta`/`index` keyspaces, snapshots, restore, quarantine and DEK
//!   rotation. [`new`] builds both over one shared database.
//! - [`store_command`]: the command types replicated through Raft.
//! - [`app`]: node assembly ([`app::init_storage`]) and the
//!   [`app::Storage`] facade implementing [`StorageApi`].
//! - [`grpc`] / [`network`]: the gRPC services and the Raft transport, both
//!   secured with SPIFFE mutual TLS.
//! - [`config`]: the `[distributed_storage]` configuration section.
//! - [`audit`], [`prometheus_metrics`], [`readiness`]: observability.
//! - [`preflight`], [`spiffe_wait`], [`local_emergency`]: startup checks and
//!   node-local break-glass access.
//! - `mock` (feature `mock`): in-memory [`StorageApi`] for driver tests.
//!
//! ## Encryption
//!
//! All state is AES-256-GCM encrypted at rest under a cluster-wide data
//! encryption key (DEK) wrapped by a per-node key encryption key (KEK, see
//! `openstack_keystone_storage_crypto`). DEK rotation, re-encryption of old
//! epochs, per-partition quarantine after repeated authentication failures,
//! and encrypted backup/restore are specified in ADR 0016-v2.

#![deny(clippy::mem_forget)]

/// Linkage anchor - see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker keeps the
/// `[distributed_storage]` section registration (ADR 0039) in the binary.
#[allow(dead_code)]
pub fn anchor() {}

pub mod api;
pub mod app;
pub mod audit;
pub mod config;
mod error;
pub mod grpc;
pub mod local_emergency;
#[cfg(feature = "mock")]
pub mod mock;
pub mod network;
pub mod preflight;
pub mod prometheus_metrics;
mod proto_impl;
pub mod readiness;
mod response;
pub mod spiffe_wait;
pub mod store;
pub mod store_command;
mod types;
#[cfg(test)]
mod wire_format_tests;

// Re-export lightweight types from storage-api crate.
pub use openstack_keystone_storage_api::{
    DataTier, Metadata, Mutation, Node, StorageApi, StorageReadiness, StoreDataEnvelope,
    StoreError as ApiStoreError, StoreResponse, Violation,
};

pub use error::StoreError;
pub use store::bootstrap::new;
pub use store::log_store::FjallLogStore;
pub use store::state_machine::FjallStateMachine;

/// Largest Raft RPC message a node accepts. openraft ships up to 300 log
/// entries per AppendEntries call; this fits a full batch of live-restore
/// chunks (300 x 256 KiB), well above tonic's 4 MiB default.
pub(crate) const RAFT_MAX_MESSAGE_SIZE: usize = 128 * 1024 * 1024;

pub mod protobuf {
    #![allow(clippy::doc_paragraphs_missing_punctuation)]
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

pub use response::ZeroizingResponse;

openraft::declare_raft_types!(
    /// Declare the type configuration for example K/V store.
    pub TypeConfig:
        D = pb::api::CommandRequest,
        R = ZeroizingResponse,
        LeaderId = pb::raft::LeaderId,
        Vote = pb::raft::Vote,
        Entry = pb::raft::Entry,
        Node = pb::raft::Node,
);
