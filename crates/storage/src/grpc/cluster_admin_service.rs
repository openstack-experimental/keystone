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
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, RwLock};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use openraft::RaftSnapshotBuilder;
use openraft::async_runtime::WatchReceiver;
use openraft::errors::ClientWriteError;
use openraft::errors::RaftError;
use openraft::vote::RaftLeaderId;
use openraft::vote::RaftVote;
use openstack_keystone_config::LocalEmergencyProvider;
use openstack_keystone_local_emergency_store::{
    EmergencyCandidate, LeaderlessTracker, LocalEmergencyStore, Subsystem,
};
use openstack_keystone_storage_crypto::{DekEpoch, KekProvider, generate_dek};
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tracing::trace;

use crate::StoreError;
use crate::app::normalize_rpc_addr;
use crate::audit::{AuditForwarder, AuditRecord};
use crate::local_emergency::{DEK_SCOPE_ID, DekEmergencyPayload, GuardrailConfig};
use crate::network::{check_svid_ttl_der, now_unix_secs};
use crate::pb;
use crate::protobuf::raft::cluster_admin_service_server::ClusterAdminService;
use crate::store_command::{MutationInner, PendingRotation, StoreCommand};
use crate::types::*;

mod auth;
mod dek;
mod leader;
mod local_emergency;
mod restore;
mod status;

use self::auth::*;
use self::leader::*;
use self::local_emergency::*;

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
    /// Peer certificate role resolver.
    authz: Arc<PeerAuthz>,
    /// Per-identity rate limiter for RotateDek (ADR 0016-v2 §1: 2/hour).
    rotate_dek_limiter: Arc<IdentityLimiter>,
    /// Per-identity rate limiter for ClearQuarantine (ADR 0016-v2 §1: 10/hour).
    clear_quarantine_limiter: Arc<IdentityLimiter>,
    /// ADR 0028 node-local, quorum-bypass emergency write store.
    local_emergency_store: Arc<dyn LocalEmergencyStore>,
    /// `[local_emergency]` config, snapshotted at storage init.
    local_emergency_config: LocalEmergencyProvider,
    /// Tracks how long the Raft leader has been unknown, feeding the
    /// quorum-bypass guardrail (ADR 0028 §2).
    local_emergency_leaderless_tracker: LeaderlessTracker,
    /// Serializes live restores: their staged chunks share one namespace, and
    /// a second restore starting would supersede the first.
    restore_lock: tokio::sync::Mutex<()>,
}

impl ClusterAdminServiceImpl {
    /// Audit the outcome of a state-changing operation, *after* it has been
    /// attempted: `event` on success, `<event>_FAILED` (with the error in
    /// `details.error`) on failure. Callers then propagate the result, so a
    /// failed Raft write never leaves a success record behind.
    fn audit_outcome<T>(
        &self,
        event: &str,
        actor: &str,
        dek_version: u32,
        mut details: serde_json::Value,
        result: &Result<T, Status>,
    ) {
        let event = match result {
            Ok(_) => event.to_string(),
            Err(status) => {
                if let Some(map) = details.as_object_mut() {
                    map.insert(
                        "error".to_string(),
                        serde_json::Value::String(status.message().to_string()),
                    );
                }
                format!("{event}_FAILED")
            }
        };
        self.audit.emit(AuditRecord::now(
            event,
            actor,
            self.node_id,
            dek_version,
            details,
        ));
    }

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        raft_node: Raft,
        node_id: u64,
        kek: Arc<dyn KekProvider>,
        current_dek: Arc<RwLock<Arc<DekEpoch>>>,
        audit: AuditForwarder,
        pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
        sm: Arc<StateMachineStore>,
        authz: Arc<PeerAuthz>,
        local_emergency_store: Arc<dyn LocalEmergencyStore>,
        local_emergency_config: LocalEmergencyProvider,
    ) -> Self {
        Self {
            raft_node,
            node_id,
            kek,
            current_dek,
            audit,
            pending_rotations,
            sm,
            authz,
            rotate_dek_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR))),
            clear_quarantine_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(
                CLEAR_QUARANTINE_PER_HOUR,
            ))),
            local_emergency_store,
            local_emergency_config,
            local_emergency_leaderless_tracker: LeaderlessTracker::new(),
            restore_lock: tokio::sync::Mutex::new(()),
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
        // Convert nodes into required format, storing every address in the
        // canonical `host:port` form (see `normalize_rpc_addr`).
        let nodes_map: BTreeMap<u64, pb::raft::Node> = nodes
            .into_iter()
            .map(|node| {
                let rpc_addr = normalize_rpc_addr(&node.rpc_addr).to_owned();
                (node.node_id, pb::raft::Node { rpc_addr, ..node })
            })
            .collect();

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
        require_peer(&request, &self.authz, &[PeerRole::Operator])?;
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
        require_peer(&request, &self.authz, &[PeerRole::Node, PeerRole::Operator])?;
        // Membership changes are leader-only; the conflict check below must
        // also see the leader's committed membership.
        self.ensure_leader()?;
        let req = request.into_inner();

        let node = req
            .node
            .ok_or_else(|| Status::invalid_argument("Node information is required"))?;

        trace!("Adding learner node {}", node.node_id);

        // Reject if the node_id already exists in committed membership with a
        // different rpc_addr (ADR 0016-v2 §4.3 / F7).
        // Use borrow_watched (synchronous) to avoid introducing a yield point
        // that could expose race conditions between Raft init and add_learner.
        let check_id = node.node_id;
        let check_addr = normalize_rpc_addr(&node.rpc_addr).to_owned();
        let metrics = self.raft_node.metrics().borrow_watched().clone();
        let conflict =
            metrics
                .membership_config
                .membership()
                .nodes()
                .find_map(|(nid, existing)| {
                    if *nid == check_id && normalize_rpc_addr(&existing.rpc_addr) != check_addr {
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

        // Store the canonical `host:port` form so `init`, `join` and the
        // `retry_join_nodes` auto-join (which announces the configured URI,
        // scheme and trailing slash included) all register alike.
        let raft_node = Node {
            rpc_addr: check_addr,
            node_id: node.node_id,
        };

        let result = self
            .raft_node
            .add_learner(node.node_id, raft_node, true)
            .await
            .map_err(|e| raft_write_status("Failed to add learner node", e))?;

        trace!("Successfully added learner node {}", node.node_id);
        Ok(Response::new(result.into()))
    }

    /// Returns the cluster's currently-installed DEK epoch, wrapped under
    /// this node's own KEK, so a node joining for the first time can adopt
    /// it instead of its own bootstrap-generated random DEK (ADR 0016-v2
    /// §2.5.3).
    ///
    /// # Security
    /// Authenticated the same way as `AddLearner` (peer trust-domain check,
    /// not the `storage-operator` role): this is node-to-node bootstrap
    /// traffic between cluster peers, not an operator action.
    ///
    /// # Consistency
    /// `current_dek_wrapped` and `retired_deks_wrapped` are two independent
    /// reads, not one atomic snapshot -- a `RotateDek`/`InstallDek` commit
    /// landing between them can produce a torn view (e.g. `dek_version`
    /// still the pre-rotation epoch while `retired` already includes it).
    /// This is safe, not just tolerated: both fields come from state that
    /// was itself committed atomically by `InstallDek`'s `batch.commit()`
    /// (ADR 0016-v2 §6 step 5) before its in-memory `self.dek` swap, so a
    /// torn read here only ever yields a *valid prior* current/retired
    /// combination, never a nonexistent one -- the epoch the joiner adopts
    /// as "current" is always genuinely readable, just possibly one
    /// rotation behind. The joiner catches up to the true current epoch
    /// through normal Raft replication once it registers as a learner.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn fetch_dek(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::FetchDekResponse>, Status> {
        require_peer(&request, &self.authz, &[PeerRole::Node])?;

        let (dek_version, wrapped_dek) = self
            .sm
            .current_dek_wrapped()
            .map_err(|e| Status::internal(format!("failed to read current DEK: {e}")))?;
        let retired = self
            .sm
            .retired_deks_wrapped()
            .map_err(|e| Status::internal(format!("failed to read retired DEKs: {e}")))?
            .into_iter()
            .map(|(retired_version, retired_wrapped)| pb::raft::RetiredDek {
                dek_version: retired_version,
                wrapped_dek: retired_wrapped,
            })
            .collect();

        Ok(Response::new(pb::raft::FetchDekResponse {
            dek_version,
            wrapped_dek,
            retired,
        }))
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
        require_peer(&request, &self.authz, &[PeerRole::Operator])?;
        self.ensure_leader()?;
        let req = request.into_inner();

        trace!(
            "Changing membership. Members: {:?}, Retain: {}",
            req.members, req.retain
        );

        let result = self
            .raft_node
            .change_membership(req.members, req.retain)
            .await
            .map_err(|e| raft_write_status("Failed to change membership", e))?;

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
        request: Request<()>,
    ) -> Result<Response<pb::raft::MetricsResponse>, Status> {
        trace!("Collecting metrics");
        require_peer(&request, &self.authz, &[PeerRole::Node, PeerRole::Operator])?;
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

    /// Reports this node's Raft role and storage-encryption state (DEK
    /// epochs, pending emergency rotations, quarantine markers, nonce
    /// counter). Operator only; answered by any node.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn storage_status(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::StorageStatusResponse>, Status> {
        self.handle_storage_status(request).await
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
        self.handle_clear_quarantine(request).await
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
        self.handle_rotate_dek(request).await
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
        self.handle_confirm_rotate_dek(request).await
    }

    /// Stages a node-local, quorum-bypass DEK rotation candidate (ADR 0028
    /// §3, amending ADR 0016-v2 §6.2). Written only to this node's local
    /// Fjall `local_emergency` keyspace — never proposed to Raft. Refused
    /// unless this node's `[local_emergency]` guardrail currently permits it.
    ///
    /// # Security
    /// Same operator/mTLS boundary as `RotateDek`. Unlike `RotateDek`, this
    /// path bypasses Raft entirely by design — it exists only for use when
    /// the cluster has lost quorum and `RotateDek{emergency: true}` (a Raft
    /// proposal) would block forever.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn rotate_dek_local_emergency(
        &self,
        request: Request<pb::raft::RotateDekLocalEmergencyRequest>,
    ) -> Result<Response<pb::raft::RotateDekLocalEmergencyResponse>, Status> {
        self.handle_rotate_dek_local_emergency(request).await
    }

    /// Lists node-local DEK emergency rotation candidates on this node
    /// (ADR 0028 §6), so an operator can see any `LOCAL_EMERGENCY_CONFLICT`
    /// before choosing which `rotation_id` to reconcile.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn list_dek_local_emergency_candidates(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::ListDekLocalEmergencyCandidatesResponse>, Status> {
        self.handle_list_dek_local_emergency_candidates(request)
            .await
    }

    /// Reconciles a node-local DEK emergency rotation candidate into
    /// Raft-replicated state (ADR 0028 §6): installs the chosen candidate's
    /// DEK via the normal `InstallDek` transaction (same mutation `RotateDek`
    /// commits for a non-emergency rotation), then clears it from this
    /// node's local store and revokes any other active candidate (they
    /// lost).
    ///
    /// # Security
    /// Same operator/mTLS boundary as `RotateDek`. Not guardrail-gated
    /// (unlike staging): reconciliation is the operation an operator runs
    /// *after* quorum has returned.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn reconcile_dek_local_emergency(
        &self,
        request: Request<pb::raft::ReconcileDekLocalEmergencyRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        self.handle_reconcile_dek_local_emergency(request).await
    }

    /// Receives a best-effort, peer-to-peer gossip push of another node's
    /// local emergency candidate (ADR 0028 §5). Adopts it if this node holds
    /// no active candidate for the same subsystem/scope, marks both as
    /// conflicted if it holds a *different* active one, or no-ops if it
    /// already has this exact candidate (idempotent re-gossip).
    ///
    /// # Security
    /// Called peer-to-peer between storage nodes, not by a human operator —
    /// authorized like Raft's own inter-node RPCs
    /// (`require_peer(.., &[PeerRole::Node])`), not `require_operator`.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn gossip_local_emergency_candidate(
        &self,
        request: Request<pb::raft::GossipLocalEmergencyCandidateRequest>,
    ) -> Result<Response<pb::raft::GossipLocalEmergencyCandidateResponse>, Status> {
        self.handle_gossip_local_emergency_candidate(request).await
    }

    type BackupStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<pb::raft::BackupChunk, Status>> + Send>,
    >;

    /// Build a fresh Fjall snapshot and stream the encrypted bytes to the
    /// operator.
    ///
    /// Encryption is performed by `build_snapshot` using the Backup DEK (see
    /// ADR 0016-v2 §7). Chunks are 256 KiB; the final chunk carries the
    /// snapshot_utc_epoch and dek_version parsed from the on-disk header so
    /// the client can verify the backup envelope without decrypting it.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn backup(
        &self,
        request: Request<pb::raft::BackupRequest>,
    ) -> Result<Response<Self::BackupStream>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        trace!(actor, "operator backup requested");

        // Ensure backup targets the leader to avoid stale data.
        self.ensure_leader()?;

        // Trigger snapshot build via the snapshot builder trait.
        let mut builder = self.sm.clone();
        let _built = builder
            .build_snapshot()
            .await
            .map_err(|e| Status::internal(format!("snapshot build failed: {e}")))?;

        let snapshot_path = self
            .sm
            .latest_snapshot_path()
            .map_err(|e| Status::internal(format!("cannot locate snapshot file: {e}")))?
            .ok_or_else(|| Status::internal("snapshot build did not produce a file"))?;
        let file = tokio::fs::File::open(&snapshot_path)
            .await
            .map_err(|e| Status::internal(format!("cannot open snapshot file: {e}")))?;
        let file_size = file
            .metadata()
            .await
            .map_err(|e| Status::internal(format!("cannot stat snapshot file: {e}")))?
            .len() as usize;

        // Full on-disk header is 20 bytes (dek_version + utc_epoch +
        // nonce_salt); only the first 12 are parsed here for audit/chunk
        // metadata, the rest streams through verbatim as part of the body.
        if file_size < 20 {
            return Err(Status::internal("snapshot file too short"));
        }

        // Read and parse the first 12 bytes of the header: [dek_version:
        // u32_be][utc_epoch: u64_be].
        let (file, header_bytes, dek_version, utc_epoch) = {
            let mut file = file;
            let mut header = [0u8; 12];
            tokio::io::AsyncReadExt::read_exact(&mut file, &mut header)
                .await
                .map_err(|e| Status::internal(format!("cannot read snapshot header: {e}")))?;
            let dv = u32::from_be_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| Status::internal("corrupt snapshot header (dek_version)"))?,
            );
            let ue = u64::from_be_bytes(
                header[4..12]
                    .try_into()
                    .map_err(|_| Status::internal("corrupt snapshot header (utc_epoch)"))?,
            );
            (file, header, dv, ue)
        };

        self.audit.emit(AuditRecord::now(
            "BACKUP_CREATED",
            &actor,
            self.node_id,
            self.current_dek
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .version,
            serde_json::json!({
                "snapshot_utc_epoch": utc_epoch,
                "dek_version": dek_version,
                "bytes": file_size,
            }),
        ));

        // Stream the entire snapshot (header + body) in 256 KiB chunks. Only
        // the final chunk carries metadata. State tracks (file, bytes_written,
        // total_size, dek_version, utc_epoch, header_pending).
        const CHUNK_SIZE: usize = 256 * 1024;
        let stream = futures::stream::unfold(
            (
                file,
                0usize,
                file_size,
                dek_version,
                utc_epoch,
                Some(header_bytes),
            ),
            |(mut file, written, total, dv, ue, header_opt)| async move {
                // Terminated: nothing left to send.
                if written >= total {
                    return None;
                }

                // Determine how many bytes to prefill from the pending header.
                let (header_len, header_data) =
                    header_opt.map_or((0, Vec::new()), |h| (h.len(), h.to_vec()));
                let mut buf = Vec::with_capacity(CHUNK_SIZE);
                buf.extend(header_data);

                let to_read = CHUNK_SIZE.saturating_sub(header_len);
                let to_read = to_read.min(total.saturating_sub(written + header_len));
                if to_read > 0 {
                    let mut body = vec![0u8; to_read];
                    if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut file, &mut body).await
                    {
                        return Some((
                            Err(Status::internal(format!("read error: {e}"))),
                            (file, written, total, dv, ue, None),
                        ));
                    }
                    buf.extend(body);
                }

                let new_written = written + header_len + to_read;
                if new_written >= total {
                    return Some((
                        Ok(pb::raft::BackupChunk {
                            data: buf,
                            snapshot_utc_epoch: Some(ue),
                            dek_version: Some(dv),
                        }),
                        (file, new_written, total, dv, ue, None),
                    ));
                }

                Some((
                    Ok(pb::raft::BackupChunk {
                        data: buf,
                        snapshot_utc_epoch: None,
                        dek_version: None,
                    }),
                    (file, new_written, total, dv, ue, None),
                ))
            },
        );

        Ok(Response::new(Box::pin(stream)))
    }

    /// Accept a client-streamed encrypted backup and validate its envelope.
    ///
    /// - Initialized cluster: the backup is committed through the Raft log
    ///   (leader only) and replaces the data on every node; membership is
    ///   unchanged.
    /// - Uninitialized node (disaster recovery): the backup is installed as a
    ///   Raft snapshot, restoring the original membership. Repeat on every node
    ///   and set `elect` on one (OpenRaft "restore from snapshot").
    ///
    /// See ADR 0016-v2 §7 and the Restore runbook.
    #[tracing::instrument(level = "trace", skip(self, request))]
    async fn restore(
        &self,
        request: Request<Streaming<pb::raft::RestoreChunk>>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        self.handle_restore(request).await
    }
}

#[cfg(test)]
mod tests;
