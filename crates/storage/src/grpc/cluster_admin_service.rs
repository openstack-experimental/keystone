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
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::sync::{Arc, Mutex, RwLock};

use openraft::RaftSnapshotBuilder;
use openraft::async_runtime::WatchReceiver;
use openstack_keystone_storage_crypto::{DekEpoch, KekProvider, generate_dek};
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tracing::trace;

use crate::StoreError;
use crate::audit::{AuditForwarder, AuditRecord};
use crate::pb;
use crate::protobuf::raft::cluster_admin_service_server::ClusterAdminService;
use crate::store_command::{MutationInner, PendingRotation, StoreCommand};
use crate::types::*;

/// Extract the peer TLS identity from the request: prefers SPIFFE URI SAN,
/// falls back to CN, or returns `"unknown"` if no peer cert is present.
fn extract_peer_identity<T>(request: &tonic::Request<T>) -> String {
    let der_bytes: Option<Vec<u8>> = request
        .peer_certs()
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()));

    der_bytes
        .as_deref()
        .and_then(|der| x509_parser::parse_x509_certificate(der).ok())
        .and_then(|(_, cert)| {
            cert.subject_alternative_name()
                .ok()
                .flatten()
                .and_then(|san| {
                    san.value.general_names.iter().find_map(|n| {
                        if let x509_parser::extensions::GeneralName::URI(uri) = n {
                            Some((*uri).to_owned())
                        } else {
                            None
                        }
                    })
                })
                .or_else(|| {
                    cert.subject()
                        .iter_common_name()
                        .next()
                        .and_then(|a| a.as_str().ok())
                        .map(str::to_owned)
                })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Raft cluster administrative operations.
///
/// # Responsibilities
/// - Manages the Raft cluster
///
/// # Protocol Safety
/// This service implements the client-facing API and should validate all inputs
/// before processing them through the Raft consensus protocol.
pub struct ClusterAdminServiceImpl {
    /// The Raft node instance for consensus operations.
    pub(crate) raft_node: Raft,
    /// This node's Raft ID (used to tag audit records for per-node
    /// attribution).
    node_id: u64,
    /// KEK used to wrap newly-generated DEKs during rotation.
    kek: Arc<dyn KekProvider>,
    /// Shared current DEK epoch — read to determine the next rotation version.
    current_dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// Audit event forwarder (non-blocking, HMAC-signed).
    audit: AuditForwarder,
    /// Pending emergency DEK rotations (shared with FjallStateMachine).
    pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
    /// State machine store — used for backup snapshot building and restore.
    sm: Arc<StateMachineStore>,
}

impl ClusterAdminServiceImpl {
    /// Creates a new instance of the API service.
    ///
    /// # Parameters
    /// - `raft_node`: The Raft node instance this service will use.
    /// - `kek`: Key Encryption Key used to wrap new DEKs during rotation.
    /// - `current_dek`: Shared reference to the active DEK epoch.
    /// - `audit`: Audit forwarder for signed event emission.
    /// - `pending_rotations`: Shared pending rotation map for dual-control.
    ///
    /// # Returns
    /// A new `ClusterAdminServiceImpl` instance.
    pub fn new(
        raft_node: Raft,
        node_id: u64,
        kek: Arc<dyn KekProvider>,
        current_dek: Arc<RwLock<Arc<DekEpoch>>>,
        audit: AuditForwarder,
        pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
        sm: Arc<StateMachineStore>,
    ) -> Self {
        Self {
            raft_node,
            node_id,
            kek,
            current_dek,
            audit,
            pending_rotations,
            sm,
        }
    }

    /// Initializes a new Raft cluster with the specified nodes.
    ///
    /// # Parameters
    /// - `nodes`: Contains the initial set of nodes for the cluster.
    ///
    /// # Returns
    /// A `Result` indicating success, or a `StoreError`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn init_cluster(&self, nodes: Vec<pb::raft::Node>) -> Result<(), StoreError> {
        // Convert nodes into required format
        let nodes_map: BTreeMap<u64, pb::raft::Node> =
            nodes.into_iter().map(|node| (node.node_id, node)).collect();

        // Initialize the cluster
        Ok(self.raft_node.initialize(nodes_map).await?)
    }

    /// Retrieves metrics about the Raft node.
    ///
    /// # Returns
    /// A `Result` containing `RaftMetrics`, or a `StoreError`.
    pub fn get_metrics(&self) -> Result<RaftMetrics, StoreError> {
        Ok(self.raft_node.metrics().borrow_watched().clone())
    }

    /// Retrieves last log index appended to the node's log.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the last log index, or a
    /// `StoreError`.
    pub fn get_last_log_index(&self) -> Result<Option<u64>, StoreError> {
        let metrics = self.get_metrics()?;
        Ok(metrics.last_log_index)
    }
}

#[tonic::async_trait]
impl ClusterAdminService for ClusterAdminServiceImpl {
    /// Initializes a new Raft cluster with the specified nodes.
    ///
    /// # Parameters
    /// - `request`: Contains the initial set of nodes for the cluster.
    ///
    /// # Returns
    /// A `Result` containing a `Response`, or a `Status` error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn init(&self, request: Request<pb::raft::InitRequest>) -> Result<Response<()>, Status> {
        trace!("Initializing Raft cluster");
        let req = request.into_inner();

        // Initialize the cluster
        let result = self
            .init_cluster(req.nodes)
            .await
            .map_err(|e| Status::internal(format!("Failed to initialize cluster: {}", e)))?;

        trace!("Cluster initialization successful");
        Ok(Response::new(result))
    }

    /// Adds a learner node to the Raft cluster.
    ///
    /// # Parameters
    /// - `request`: Contains the node information and blocking preference.
    ///
    /// # Returns
    /// A `Result` containing a `Response` with learner addition details, or a
    /// `Status` error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn add_learner(
        &self,
        request: Request<pb::raft::AddLearnerRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let req = request.into_inner();

        let node = req
            .node
            .ok_or_else(|| Status::internal("Node information is required"))?;

        trace!("Adding learner node {}", node.node_id);

        // Reject if the node_id already exists in committed membership with a
        // different rpc_addr (ADR 0016-v2 §4.3 / F7).
        // Use borrow_watched (synchronous) to avoid introducing a yield point
        // that could expose race conditions between Raft init and add_learner.
        let check_id = node.node_id;
        let check_addr = node.rpc_addr.clone();
        let metrics = self.raft_node.metrics().borrow_watched().clone();
        let conflict =
            metrics
                .membership_config
                .membership()
                .nodes()
                .find_map(|(nid, existing)| {
                    if *nid == check_id && existing.rpc_addr != check_addr {
                        Some(existing.rpc_addr.clone())
                    } else {
                        None
                    }
                });

        if let Some(existing_addr) = conflict {
            return Err(Status::already_exists(format!(
                "node_id {} already registered at {existing_addr}; \
                 cannot re-add with address {}",
                node.node_id, node.rpc_addr
            )));
        }

        let raft_node = Node {
            rpc_addr: node.rpc_addr.clone(),
            node_id: node.node_id,
        };

        let result = self
            .raft_node
            .add_learner(node.node_id, raft_node, true)
            .await
            .map_err(|e| Status::internal(format!("Failed to add learner node: {}", e)))?;

        trace!("Successfully added learner node {}", node.node_id);
        Ok(Response::new(result.into()))
    }

    /// Changes the membership of the Raft cluster.
    ///
    /// # Parameters
    /// - `request`: Contains the new member set and retention policy.
    ///
    /// # Returns
    /// A `Result` containing a `Response` with membership change details, or a
    /// `Status` error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn change_membership(
        &self,
        request: Request<pb::raft::ChangeMembershipRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let req = request.into_inner();

        trace!(
            "Changing membership. Members: {:?}, Retain: {}",
            req.members, req.retain
        );

        let result = self
            .raft_node
            .change_membership(req.members, req.retain)
            .await
            .map_err(|e| Status::internal(format!("Failed to change membership: {}", e)))?;

        trace!("Successfully changed cluster membership");
        Ok(Response::new(result.into()))
    }

    /// Retrieves metrics about the Raft node.
    ///
    /// # Parameters
    /// - `_request`: The request object.
    ///
    /// # Returns
    /// A `Result` containing a `Response` with metrics, or a `Status` error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn metrics(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::raft::MetricsResponse>, Status> {
        trace!("Collecting metrics");
        let metrics = self
            .get_metrics()
            .map_err(|e| Status::internal(format!("Failed to write to store: {}", e)))?;
        let resp = pb::raft::MetricsResponse {
            membership: Some(metrics.membership_config.membership().clone().into()),
            other_metrics: metrics.to_string(),
            current_leader: metrics.current_leader,
        };
        Ok(Response::new(resp))
    }

    /// Clears the read-only quarantine state triggered by repeated GCM tag
    /// verification failures.
    ///
    /// # Parameters
    /// - `request`: Empty request (no additional parameters).
    ///
    /// # Returns
    /// A `Result` containing a `Response`, or a `Status` error.
    ///
    /// # Security
    /// This operation is exposed only on the internal management network.
    /// Access is controlled by network isolation and mTLS authentication
    /// (SPIFFE SVID or operator-managed TLS).
    #[tracing::instrument(level = "trace", skip(self))]
    async fn clear_quarantine(
        &self,
        request: Request<pb::raft::ClearQuarantineRequest>,
    ) -> Result<Response<()>, Status> {
        let actor = extract_peer_identity(&request);
        let partition = request.into_inner().partition;
        if partition.is_empty() {
            return Err(Status::invalid_argument(
                "partition must not be empty — specify the keyspace to un-quarantine (e.g. \"data\")",
            ));
        }

        trace!(partition, actor, "operator clearing quarantine via gRPC");

        let cmd = StoreCommand::Transaction(vec![MutationInner::ClearQuarantine {
            partition: partition.clone(),
        }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;

        self.raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")))?;

        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit.emit(AuditRecord::now(
            "QUARANTINE_CLEARED",
            &actor,
            self.node_id,
            dek_version,
            serde_json::json!({ "partition": partition }),
        ));

        Ok(Response::new(()))
    }

    /// Triggers a Data Encryption Key rotation. When emergency is set, the
    /// current DEK is immediately revoked (not retired).
    ///
    /// # Parameters
    /// - `request`: Contains the `emergency` flag to control rotation type.
    ///
    /// # Returns
    /// A `Result` containing a `Response` with rotation details, or a `Status`
    /// error.
    ///
    /// # Security
    /// This operation is exposed only on the internal management network.
    /// Access is controlled by network isolation and mTLS authentication
    /// (SPIFFE SVID or operator-managed TLS). Emergency rotations require
    /// operator access and produce distinct audit events.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn rotate_dek(
        &self,
        request: Request<pb::raft::RotateDekRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = extract_peer_identity(&request);
        let req = request.into_inner();

        let current_version = {
            self.current_dek
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .version
        };
        let new_version = current_version.checked_add(1).ok_or_else(|| {
            Status::internal("DEK version space exhausted — cannot rotate beyond u32::MAX")
        })?;

        let new_raw = generate_dek();
        let wrapped_dek = self
            .kek
            .wrap_dek(new_raw.as_bytes())
            .map_err(|e| Status::internal(format!("failed to wrap new DEK: {e}")))?;

        if req.emergency {
            // Stage 1 of dual-control: persist the pending entry; the DEK is
            // NOT yet active.  A second operator must call ConfirmRotateDek.
            let rotation_id = uuid::Uuid::new_v4().to_string();
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + crate::store::state_machine::PENDING_ROTATION_TTL_SECS;

            let cmd = StoreCommand::Transaction(vec![MutationInner::CreatePendingRotation {
                rotation_id: rotation_id.clone(),
                wrapped_dek,
                dek_version: new_version,
                expires_at,
                initiator: actor.clone(),
            }]);
            let payload = pb::api::CommandRequest::try_from(cmd)
                .map_err(|e| Status::internal(e.to_string()))?;

            self.audit.emit(AuditRecord::now(
                "DEK_ROTATION_EMERGENCY_STAGED",
                &actor,
                self.node_id,
                current_version,
                serde_json::json!({
                    "rotation_id": rotation_id,
                    "new_version": new_version,
                    "expires_at": expires_at,
                }),
            ));

            self.raft_node
                .client_write(payload)
                .await
                .map_err(|e| Status::internal(format!("Raft write failed: {e}")))?;

            tracing::info!(
                rotation_id,
                new_version,
                initiator = actor,
                "emergency DEK rotation staged; awaiting dual-control confirmation"
            );
            return Ok(Response::new(pb::raft::AdminResponse {
                pending_rotation_id: rotation_id,
                ..Default::default()
            }));
        }

        // Non-emergency: commit InstallDek directly (old DEK is retired, not revoked).
        let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek,
            dek_version: new_version,
            is_emergency: false,
        }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;

        self.audit.emit(AuditRecord::now(
            "DEK_ROTATION",
            &actor,
            self.node_id,
            new_version,
            serde_json::json!({ "previous_version": current_version }),
        ));

        self.raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")))?;

        tracing::info!(new_version, "DEK rotation committed to Raft log");
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    /// Provides dual-control approval for a pending emergency DEK rotation.
    ///
    /// # Parameters
    /// - `request`: Contains the `rotation_id` of the pending emergency
    ///   rotation.
    ///
    /// # Returns
    /// A `Result` containing a `Response` with confirmation details, or a
    /// `Status` error.
    ///
    /// # Security
    /// This operation requires a second `storage-operator` SVID and must be
    /// invoked within 5 minutes of the initial `RotateDekRequest{emergency:
    /// true}`. Both operator identities are recorded in the audit log.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn confirm_rotate_dek(
        &self,
        request: Request<pb::raft::ConfirmRotateDekRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = extract_peer_identity(&request);
        let req = request.into_inner();

        if req.rotation_id.is_empty() {
            return Err(Status::invalid_argument("rotation_id must not be empty"));
        }

        trace!(
            rotation_id = req.rotation_id,
            confirmer = actor,
            "confirming emergency DEK rotation"
        );

        // Fast pre-check on the in-memory map so we can return a clear error
        // before proposing to Raft.  The authoritative check is in the state
        // machine apply handler, but this avoids unnecessary log entries.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pending_version = {
            let map = self
                .pending_rotations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match map.get(&req.rotation_id) {
                None => {
                    return Err(Status::not_found(format!(
                        "no pending emergency rotation with id {}",
                        req.rotation_id
                    )));
                }
                Some(e) if e.expires_at <= now => {
                    return Err(Status::deadline_exceeded(format!(
                        "pending rotation {} has expired",
                        req.rotation_id
                    )));
                }
                Some(e) if e.initiator == actor => {
                    return Err(Status::permission_denied(
                        "the confirming operator must be different from the initiator \
                         (dual-control requirement)",
                    ));
                }
                Some(e) => e.dek_version,
            }
        };

        let cmd = StoreCommand::Transaction(vec![MutationInner::ConfirmPendingRotation {
            rotation_id: req.rotation_id.clone(),
            confirmer: actor.clone(),
        }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;

        self.audit.emit(AuditRecord::now(
            "DEK_ROTATION_EMERGENCY_CONFIRMED",
            &actor,
            self.node_id,
            pending_version,
            serde_json::json!({ "rotation_id": req.rotation_id }),
        ));

        self.raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")))?;

        tracing::warn!(
            rotation_id = req.rotation_id,
            new_version = pending_version,
            confirmer = actor,
            "SECURITY: emergency DEK rotation confirmed via dual-control"
        );
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    type BackupStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<pb::raft::BackupChunk, Status>> + Send>,
    >;

    /// Build a fresh Fjall snapshot and stream the encrypted bytes to the
    /// operator.
    ///
    /// Encryption is performed by `build_snapshot` using the Backup DEK (see
    /// ADR 0016-v2 §7).  Chunks are 256 KiB; the final chunk carries the
    /// snapshot_utc_epoch and dek_version parsed from the on-disk header so
    /// the client can verify the backup envelope without decrypting it.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn backup(
        &self,
        request: Request<pb::raft::BackupRequest>,
    ) -> Result<Response<Self::BackupStream>, Status> {
        let actor = extract_peer_identity(&request);
        trace!(actor, "operator backup requested");

        // Trigger snapshot build via the snapshot builder trait.
        let mut builder = self.sm.clone();
        builder
            .build_snapshot()
            .await
            .map_err(|e| Status::internal(format!("snapshot build failed: {e}")))?;

        // Find latest snapshot file in the snapshot directory.
        let snapshot_dir = self.sm.snapshot_dir().to_owned();
        let latest = fs::read_dir(&snapshot_dir)
            .map_err(|e| Status::internal(format!("cannot read snapshot dir: {e}")))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .max_by_key(|e| e.file_name())
            .ok_or_else(|| Status::not_found("no snapshot available after build"))?;

        let disk_bytes = fs::read(latest.path())
            .map_err(|e| Status::internal(format!("cannot read snapshot file: {e}")))?;

        // Parse header: [dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8]
        if disk_bytes.len() < 12 {
            return Err(Status::internal("snapshot file too short"));
        }
        let dek_version = u32::from_be_bytes(disk_bytes[..4].try_into().unwrap_or_default());
        let utc_epoch = u64::from_be_bytes(disk_bytes[4..12].try_into().unwrap_or_default());

        let dek_ver_for_audit = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit.emit(AuditRecord::now(
            "BACKUP_CREATED",
            &actor,
            self.node_id,
            dek_ver_for_audit,
            serde_json::json!({
                "snapshot_utc_epoch": utc_epoch,
                "dek_version": dek_version,
                "bytes": disk_bytes.len(),
            }),
        ));

        // Stream in 256 KiB chunks; tag the final chunk with the header metadata.
        const CHUNK_SIZE: usize = 256 * 1024;
        let total = disk_bytes.len();
        let chunks: Vec<Result<pb::raft::BackupChunk, Status>> = disk_bytes
            .chunks(CHUNK_SIZE)
            .enumerate()
            .map(|(i, slice)| {
                let offset = i * CHUNK_SIZE;
                let is_last = offset + slice.len() == total;
                Ok(pb::raft::BackupChunk {
                    data: slice.to_vec(),
                    snapshot_utc_epoch: if is_last { Some(utc_epoch) } else { None },
                    dek_version: if is_last { Some(dek_version) } else { None },
                })
            })
            .collect();

        let stream = futures::stream::iter(chunks);
        Ok(Response::new(Box::pin(stream)))
    }

    /// Accept a client-streamed encrypted backup, validate its envelope,
    /// and install it into the Raft state machine via
    /// `Raft::install_full_snapshot`.
    ///
    /// Only call this against a freshly-bootstrapped single-node cluster
    /// before adding learners (see ADR 0016-v2 §7 / doc Restore runbook).
    #[tracing::instrument(level = "trace", skip(self, request))]
    async fn restore(
        &self,
        request: Request<Streaming<pb::raft::RestoreChunk>>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = extract_peer_identity(&request);
        trace!(actor, "operator restore requested");

        let mut stream = request.into_inner();
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.message().await? {
            buf.extend_from_slice(&chunk.data);
        }
        if buf.is_empty() {
            return Err(Status::invalid_argument("restore stream was empty"));
        }

        let (snapshot, utc_epoch, dek_version) = self
            .sm
            .decode_backup_blob(&buf)
            .map_err(|e| Status::invalid_argument(format!("invalid backup blob: {e}")))?;

        // Get the current committed vote to authenticate the install.
        let vote = self.raft_node.metrics().borrow_watched().vote.clone();

        self.raft_node
            .install_full_snapshot(vote, snapshot)
            .await
            .map_err(|e| Status::internal(format!("snapshot install failed: {e}")))?;

        let dek_ver_for_audit = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit.emit(AuditRecord::now(
            "BACKUP_RESTORED",
            &actor,
            self.node_id,
            dek_ver_for_audit,
            serde_json::json!({
                "snapshot_utc_epoch": utc_epoch,
                "backup_dek_version": dek_version,
            }),
        ));

        tracing::info!(actor, utc_epoch, dek_version, "backup restore complete");
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }
}
