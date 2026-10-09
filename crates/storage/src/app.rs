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
//! # Storage node assembly and the [`Storage`] facade.
//!
//! [`init_storage`] wires the pieces together: it opens the Fjall-backed log
//! store and state machine ([`crate::new`]), starts the Raft instance with
//! the SPIFFE-secured [`NetworkManager`](crate::network::NetworkManager),
//! and spawns the background tasks (re-encryption sweeper, quarantine
//! propagation, automatic DEK rotation, certificate watchdog).
//! [`get_app_server`] exposes the resulting node over gRPC.
//!
//! [`Storage`] is what the rest of Keystone holds: it implements
//! [`StorageApi`] (reads served locally, writes proposed through Raft and
//! forwarded to the leader when needed) and carries the cluster
//! administration entry points (join, demote, leadership transfer, DEK
//! rotation proposals).
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use eyre::eyre;
use openraft::Config;
use openraft::async_runtime::WatchReceiver;
use openstack_keystone_storage_crypto::{DekEpoch, EnvKek, KekProvider, NonceManager};

use crate::protobuf as pb;
use openraft::ReadPolicy;
use openraft::errors::{ForwardToLeader, LinearizableReadError, RaftError};
use openraft::type_config::TypeConfigExt;
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::Channel;
use tracing::debug;

use openstack_keystone_config::ConfigManager;

use crate::config::{DistributedStorageConfiguration, RaftTlsConfiguration};

use crate::ApiStoreError;
use crate::StorageApi;
use crate::StorageReadiness;
use crate::StoreError;
use crate::StoreResponse;
use crate::Violation;
use crate::audit::{AuditForwarder, AuditRecord, AuditSpoolConfig};
use crate::grpc::authz::PeerAuthz;
use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::grpc::storage_service::StorageServiceImpl;
use crate::local_emergency::FjallLocalEmergencyStore;
use crate::network::{CertExpiryWatchdog, NetworkManager, RaftTlsClient, init_tls_watcher};
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::protobuf::api::storage_service_client::StorageServiceClient;
use crate::protobuf::api::storage_service_server::StorageServiceServer;
use crate::protobuf::raft::AddLearnerRequest;
use crate::protobuf::raft::Node as PbNode;
use crate::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;
use crate::store_command::*;
use crate::types::*;
use openstack_keystone_storage_api::Node;

mod admin;
mod dek_rotation;
mod init;
mod storage_api;

pub use dek_rotation::RotationTrigger;
pub(crate) use init::adopt_cluster_dek;
pub use init::{get_app_server, init_storage, normalize_rpc_addr};

/// gRPC metadata header used to communicate the leader's endpoint to clients.
///
/// When a non-leader node receives a write request, it returns
/// `Status::unavailable` with this header set to the leader's address, so
/// clients can retry against the leader.
pub const LEADER_ENDPOINT_HEADER: &str = "x-openraft-leader-endpoint";
pub const LEADER_ID_HEADER: &str = "x-openraft-leader-id";

/// Distributed storage.
pub struct Storage {
    /// Audit record forwarder (non-blocking, HMAC-signed).
    pub audit_forwarder: AuditForwarder,
    /// Raft cluster nodes connection pool.
    connection_pool: DashMap<u64, Channel>,
    /// Shared current DEK epoch, used by rotate_dek to determine the next
    /// version.
    current_dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// `[distributed_storage] dek_rotation_days`; `0` disables the age
    /// trigger of the automatic DEK rotation.
    dek_rotation_days: u32,
    /// Number of attempts for the `ensure_linearizable` retry loop, from
    /// `[distributed_storage] ensure_linearizable_retries`. See
    /// [`ensure_linearizable_with_retry`](Storage::ensure_linearizable_with_retry).
    pub(crate) ensure_linearizable_retries: u32,
    /// Delay (ms) between `ensure_linearizable` retry attempts, from
    /// `[distributed_storage] ensure_linearizable_retry_delay_ms`.
    pub(crate) ensure_linearizable_retry_delay_ms: u64,
    /// Key Encryption Key for wrapping new DEKs during rotation.
    kek: Arc<dyn KekProvider>,
    /// `[local_emergency]` config, snapshotted at storage init. Config
    /// hot-reload is out of scope for the bypass path (ADR 0028): a node
    /// must be restarted to flip `enabled`, same as other security-critical
    /// distributed-storage settings.
    pub(crate) local_emergency_config: openstack_keystone_config::LocalEmergencyProvider,
    /// ADR 0028 node-local, quorum-bypass emergency write store (Fjall,
    /// never touched by Raft's `apply()`). `pub` (not `pub(crate)`) so the
    /// `keystone` binary can wire it into `core::keystone::Service` at
    /// startup for the OAuth2 `--local-quorum-bypass` path, which shares
    /// this same store with `RotateDekLocalEmergency`.
    pub local_emergency_store:
        Arc<dyn openstack_keystone_local_emergency_store::LocalEmergencyStore>,
    /// The log store's nonce manager, watched by the automatic DEK rotation
    /// and read for the `keystone_raft_log_nonce_*` metrics.
    log_nonce: Arc<Mutex<NonceManager>>,
    /// This node's Raft ID (used to tag audit records for per-node
    /// attribution).
    node_id: u64,
    /// Peer certificate role resolver shared by the gRPC services.
    pub(crate) peer_authz: Arc<PeerAuthz>,
    /// Pending emergency DEK rotations (shared with FjallStateMachine).
    pending_rotations: Arc<Mutex<HashMap<String, crate::store_command::PendingRotation>>>,
    /// Raft instance.
    pub raft: Raft,
    /// The state machine store for direct reads.
    state_machine_store: Arc<StateMachineStore>,
    /// TLS client mode for Raft peer connections.
    pub(crate) tls_client: RaftTlsClient,
}

/// Outcome of the `ensure_linearizable` retry loop.
enum EnsureLinearizableOutcome {
    /// Forward the read to the given leader.
    Forward(NodeId, String),
    /// We are the leader; proceed to local read.
    Leader,
}

impl Storage {
    /// Calls `ensure_linearizable(ReadIndex)` with automatic retry for
    /// transient `QuorumNotEnough` errors that occur during concurrent Raft
    /// activity.
    ///
    /// Returns `Ok(EnsureLinearizableOutcome::Leader)` when this node is
    /// leader, `Ok(EnsureLinearizableOutcome::Forward(addr))` when a leader
    /// should handle the read.
    ///
    /// Returns `Err(ApiStoreError::Unavailable)` when the retry budget is
    /// exhausted without resolving leader status (e.g. during a prolonged
    /// election or `QuorumNotEnough` storm), or for an unrecoverable Raft
    /// error. Per ADR 0016-v2 §3 / security invariant 4 ("no stale reads for
    /// sensitive data"), callers MUST propagate this as a failure — e.g. HTTP
    /// 503 — and MUST NOT substitute a non-linearizable local read: this node
    /// cannot tell whether its local state machine has applied the latest
    /// committed entries.
    async fn ensure_linearizable_with_retry(
        &self,
    ) -> Result<EnsureLinearizableOutcome, ApiStoreError> {
        for attempt in 0..self.ensure_linearizable_retries {
            match self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
                Ok(_) => {
                    return Ok(EnsureLinearizableOutcome::Leader);
                }
                Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(
                    ForwardToLeader {
                        leader_id: Some(id),
                        leader_node: Some(node),
                    },
                ))) => {
                    return Ok(EnsureLinearizableOutcome::Forward(id, node.rpc_addr));
                }
                Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(_))) => {
                    // ForwardToLeader without leader info during election —
                    // retry.
                    debug!(
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                             without leader info (attempt {}); retrying",
                        attempt + 1
                    );
                }
                Err(RaftError::APIError(LinearizableReadError::QuorumNotEnough(_))) => {
                    debug!(
                        "ensure_linearizable (ReadIndex) returned QuorumNotEnough \
                             (attempt {}); retrying",
                        attempt + 1
                    );
                }
                Err(RaftError::Fatal(f)) => {
                    return Err(ApiStoreError::Other(Box::new(StoreError::Other(
                        eyre::eyre!("ensure_linearizable (ReadIndex) fatal: {f:?}"),
                    ))));
                }
            }

            if attempt + 1 < self.ensure_linearizable_retries {
                TypeConfig::sleep(Duration::from_millis(
                    self.ensure_linearizable_retry_delay_ms,
                ))
                .await;
            }
        }

        // Retry budget exhausted without resolving leader status. Per
        // security invariant 4, refuse the read rather than serve a
        // possibly-stale local copy — the caller must retry/fail the
        // request, not silently read local (possibly unreplicated) state.
        Err(ApiStoreError::Unavailable(format!(
            "ensure_linearizable (ReadIndex) did not resolve after {} attempts \
             ({} ms budget); refusing non-linearizable local read",
            self.ensure_linearizable_retries,
            self.ensure_linearizable_retries as u64 * self.ensure_linearizable_retry_delay_ms,
        )))
    }
}

#[cfg(test)]
mod normalize_tests {
    use super::normalize_rpc_addr;

    #[test]
    fn test_bare_address_unchanged() {
        assert_eq!(normalize_rpc_addr("host:8300"), "host:8300");
        assert_eq!(
            normalize_rpc_addr("keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"),
            "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"
        );
    }

    #[test]
    fn test_strips_scheme_and_trailing_slash() {
        assert_eq!(
            normalize_rpc_addr(
                "https://keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300/"
            ),
            "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"
        );
        assert_eq!(normalize_rpc_addr("http://host:8300/"), "host:8300");
    }

    #[test]
    fn test_scheme_only_no_trailing_slash() {
        assert_eq!(normalize_rpc_addr("https://host:8300"), "host:8300");
    }

    #[test]
    fn test_normalization_is_equivalence_check() {
        // Same host:port, different formats → identical
        assert_eq!(
            normalize_rpc_addr("host:8300"),
            normalize_rpc_addr("https://host:8300/")
        );
    }

    #[test]
    fn test_different_hosts_not_equivalent() {
        assert_ne!(
            normalize_rpc_addr("host-a:8300"),
            normalize_rpc_addr("https://host-b:8300/")
        );
    }
}
