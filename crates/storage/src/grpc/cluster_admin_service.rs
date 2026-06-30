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
use openstack_keystone_storage_crypto::{DekEpoch, KekProvider, generate_dek};
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tracing::trace;

use crate::StoreError;
use crate::app::normalize_rpc_addr;
use crate::audit::{AuditForwarder, AuditRecord};
use crate::pb;
use crate::protobuf::raft::cluster_admin_service_server::ClusterAdminService;
use crate::store_command::{MutationInner, PendingRotation, StoreCommand};
use crate::types::*;

// ---------------------------------------------------------------------------
// Security constants (ADR 0016-v2 §1 and §4.1)
// ---------------------------------------------------------------------------

/// Maximum `RotateDek` invocations per operator per hour.
const ROTATE_DEK_PER_HOUR: NonZeroU32 = {
    match NonZeroU32::new(2) {
        Some(v) => v,
        None => panic!("rate limit constant must be non-zero"),
    }
};

/// Maximum `ClearQuarantine` invocations per operator per hour.
const CLEAR_QUARANTINE_PER_HOUR: NonZeroU32 = {
    match NonZeroU32::new(10) {
        Some(v) => v,
        None => panic!("rate limit constant must be non-zero"),
    }
};

type IdentityLimiter = DefaultKeyedRateLimiter<String>;

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

/// Validates a SPIFFE URI against the
/// `spiffe://<trust-domain><spiffe_path_prefix><role>` pattern and configured
/// trust domains. Returns the `<role>` segment.
///
/// Errors with `PERMISSION_DENIED` if the URI is malformed, the trust domain is
/// not in the configured list, or the path does not match.
fn parse_spiffe_storage_id(
    id: &str,
    trust_domains: &[String],
    prefix: &str,
) -> Result<String, Status> {
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| Status::permission_denied("peer identity is not a SPIFFE URI"))?;

    let slash = rest
        .find('/')
        .ok_or_else(|| Status::permission_denied("SPIFFE ID is missing a path component"))?;
    let (domain, path) = rest.split_at(slash);

    if !trust_domains.iter().any(|d| d == domain) {
        return Err(Status::permission_denied(format!(
            "SPIFFE trust domain '{domain}' is not in the configured trust domain list"
        )));
    }

    // `path` starts with '/', strip the configured prefix to get the role.
    let role = path
        .strip_prefix(prefix)
        .filter(|r| !r.is_empty() && !r.contains('/'))
        .ok_or_else(|| {
            Status::permission_denied(format!(
                "SPIFFE ID '{id}' does not match the required pattern \
                 spiffe://<trust-domain>{prefix}<role>"
            ))
        })?;

    Ok(role.to_owned())
}

// ---------------------------------------------------------------------------
// RBAC — operator role enforcement
// ---------------------------------------------------------------------------

/// Verifies the peer identity and, in SPIFFE mode, asserts the role matches
/// the configured operator role (ADR 0016-v2 §1).
///
/// In TLS-fallback mode emits a security warning and allows the request
/// through; network isolation is the compensating control per ADR 0016-v2 §4.2.
fn require_operator<T>(
    request: &tonic::Request<T>,
    trust_domains: Option<&[String]>,
    spiffe_path_prefix: &str,
    operator_role: &str,
) -> Result<String, Status> {
    let identity = extract_peer_identity(request);

    match trust_domains {
        Some(domains) => {
            if !identity.starts_with("spiffe://") {
                return Err(Status::permission_denied(
                    "SPIFFE mode is active; peer must present a SPIFFE URI SAN",
                ));
            }
            let role = parse_spiffe_storage_id(&identity, domains, spiffe_path_prefix)?;
            if role != operator_role {
                return Err(Status::permission_denied(format!(
                    "role '{role}' is not authorized for this operation; \
                     required: '{operator_role}'"
                )));
            }
        }
        None => {
            tracing::warn!(
                identity,
                "RBAC role check skipped in TLS-fallback mode; \
                 upgrade to SPIFFE mTLS to enforce operator role-based access \
                 control (ADR 0016-v2 §4.2)"
            );
        }
    }

    Ok(identity)
}

/// Validates the peer's SPIFFE identity for internal Raft operations.
///
/// When `allowed_peer_svids` is non-empty, the identity must match one of the
/// allow-listed SVIDs. Otherwise falls back to trust-domain-only validation.
///
/// In TLS-fallback mode (`trust_domains = None`) the check is skipped entirely.
fn check_peer_trust_domain<T>(
    request: &tonic::Request<T>,
    trust_domains: Option<&[String]>,
    allowed_peer_svids: &[String],
) -> Result<String, Status> {
    let identity = extract_peer_identity(request);

    if trust_domains.is_some() && !identity.starts_with("spiffe://") {
        return Err(Status::permission_denied(
            "SPIFFE mode is active; peer must present a SPIFFE URI SAN",
        ));
    }

    if allowed_peer_svids.is_empty() {
        // Fallback: trust-domain-only check. Skipped entirely in TLS-fallback
        // mode (`trust_domains = None`), so this branch is a no-op there.
        if let Some(domains) = trust_domains {
            parse_spiffe_trust_domain(&identity, domains)?;
        }
    } else {
        // Allow-list check. In TLS-fallback mode this code is unreachable
        // because `allowed_peer_svids` is always empty when `trust_domains`
        // is `None` (set in `app.rs`).
        if !allowed_peer_svids.contains(&identity) {
            return Err(Status::permission_denied(format!(
                "SPIFFE ID '{identity}' is not in the allowed peer SVID list"
            )));
        }
    }

    Ok(identity)
}

/// Extract and validate only the SPIFFE trust domain from the peer identity,
/// returning it on success. Unlike `parse_spiffe_storage_id`, this does not
/// require a specific path prefix or role.
fn parse_spiffe_trust_domain(id: &str, trust_domains: &[String]) -> Result<(), Status> {
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| Status::permission_denied("peer identity is not a SPIFFE URI"))?;

    let slash = rest
        .find('/')
        .ok_or_else(|| Status::permission_denied("SPIFFE ID is missing a path component"))?;
    let (domain, _path) = rest.split_at(slash);

    if !trust_domains.iter().any(|d| d == domain) {
        return Err(Status::permission_denied(format!(
            "SPIFFE trust domain '{domain}' is not in the configured trust domain list"
        )));
    }

    Ok(())
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
    /// SPIFFE trust domains for SVID pattern validation.
    /// `None` in TLS-fallback mode — pattern and role checks are skipped.
    spiffe_trust_domains: Option<Vec<String>>,
    /// Per-identity rate limiter for RotateDek (ADR 0016-v2 §1: 2/hour).
    rotate_dek_limiter: Arc<IdentityLimiter>,
    /// Per-identity rate limiter for ClearQuarantine (ADR 0016-v2 §1: 10/hour).
    clear_quarantine_limiter: Arc<IdentityLimiter>,
    /// SPIFFE path prefix for SVID pattern validation. Empty in TLS-fallback.
    spiffe_path_prefix: String,
    /// SPIFFE role that authorises sensitive management operations. Empty in
    /// TLS-fallback mode.
    operator_role: String,
    /// Allow-list of SVIDs permitted for peer-to-peer Raft operations.
    /// When empty falls back to trust-domain-only check.
    allowed_peer_svids: Vec<String>,
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
        spiffe_trust_domains: Option<Vec<String>>,
        spiffe_path_prefix: String,
        operator_role: String,
        allowed_peer_svids: Vec<String>,
    ) -> Self {
        Self {
            raft_node,
            node_id,
            kek,
            current_dek,
            audit,
            pending_rotations,
            sm,
            spiffe_trust_domains,
            spiffe_path_prefix,
            operator_role,
            allowed_peer_svids,
            rotate_dek_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR))),
            clear_quarantine_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(
                CLEAR_QUARANTINE_PER_HOUR,
            ))),
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
        check_peer_trust_domain(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.allowed_peer_svids,
        )?;
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
        check_peer_trust_domain(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.allowed_peer_svids,
        )?;
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
        check_peer_trust_domain(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.allowed_peer_svids,
        )?;
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
        request: Request<()>,
    ) -> Result<Response<pb::raft::MetricsResponse>, Status> {
        trace!("Collecting metrics");
        check_peer_trust_domain(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.allowed_peer_svids,
        )?;
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        // rate limit - 10 per hour per operator identity.
        self.clear_quarantine_limiter
            .check_key(&actor)
            .map_err(|_| {
                Status::resource_exhausted("ClearQuarantine rate limit exceeded; try again later")
            })?;
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        // rate limit - 2 per hour per operator identity.
        self.rotate_dek_limiter.check_key(&actor).map_err(|_| {
            Status::resource_exhausted("RotateDek rate limit exceeded; try again later")
        })?;
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
            // NOT yet active. A second operator must call ConfirmRotateDek.
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
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
        // before proposing to Raft. The authoritative check is in the state
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
    /// ADR 0016-v2 §7). Chunks are 256 KiB; the final chunk carries the
    /// snapshot_utc_epoch and dek_version parsed from the on-disk header so
    /// the client can verify the backup envelope without decrypting it.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn backup(
        &self,
        request: Request<pb::raft::BackupRequest>,
    ) -> Result<Response<Self::BackupStream>, Status> {
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        trace!(actor, "operator backup requested");

        // Ensure backup targets the leader to avoid stale data.
        let current_leader = self.raft_node.metrics().borrow_watched().current_leader;
        if current_leader != Some(self.node_id) {
            return Err(Status::failed_precondition(
                "backup must be directed at the current cluster leader",
            ));
        }

        // Trigger snapshot build via the snapshot builder trait.
        let mut builder = self.sm.clone();
        let built = builder
            .build_snapshot()
            .await
            .map_err(|e| Status::internal(format!("snapshot build failed: {e}")))?;

        let snapshot_path = self.sm.snapshot_dir().join(&built.meta.snapshot_id);
        let file = tokio::fs::File::open(&snapshot_path)
            .await
            .map_err(|e| Status::internal(format!("cannot open snapshot file: {e}")))?;
        let file_size = file
            .metadata()
            .await
            .map_err(|e| Status::internal(format!("cannot stat snapshot file: {e}")))?
            .len() as usize;

        if file_size < 12 {
            return Err(Status::internal("snapshot file too short"));
        }

        // Read and parse the 12-byte header: [dek_version: u32_be][utc_epoch: u64_be].
        let (file, header_bytes, dek_version, utc_epoch) = {
            let mut file = file;
            let mut header = [0u8; 12];
            tokio::io::AsyncReadExt::read_exact(&mut file, &mut header)
                .await
                .map_err(|e| Status::internal(format!("cannot read snapshot header: {e}")))?;
            let dv = u32::from_be_bytes(header[..4].try_into().unwrap());
            let ue = u64::from_be_bytes(header[4..12].try_into().unwrap());
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        trace!(actor, "operator restore requested");

        let mut stream = request.into_inner();
        const MAX_RESTORE_SIZE: usize = 4 * 1024 * 1024 * 1024; // 4 GiB
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.message().await? {
            if buf.len() + chunk.data.len() > MAX_RESTORE_SIZE {
                return Err(Status::resource_exhausted(
                    "restore stream exceeds maximum allowed size (4 GiB)",
                ));
            }
            buf.extend_from_slice(&chunk.data);
        }
        if buf.is_empty() {
            return Err(Status::invalid_argument("restore stream was empty"));
        }

        let (snapshot, utc_epoch, dek_version) = self
            .sm
            .decode_backup_blob(&buf)
            .map_err(|e| Status::invalid_argument(format!("invalid backup blob: {e}")))?;

        // install_full_snapshot requires the node to be a committed leader.
        let vote = self.raft_node.metrics().borrow_watched().vote;
        if !vote.committed {
            return Err(Status::failed_precondition(
                "node is not a committed leader; direct restore to the current cluster leader",
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    const TRUST_DOMAINS: &[&str] = &["example.com", "alt.example.com"];
    const PREFIX: &str = "/keystone/storage/";
    const OPERATOR_ROLE: &str = "storage-operator";

    fn domains() -> Vec<String> {
        TRUST_DOMAINS.iter().map(|s| s.to_string()).collect()
    }

    // parse_spiffe_storage_id — valid identities

    #[test]
    fn spiffe_id_valid_operator() {
        let role = parse_spiffe_storage_id(
            "spiffe://example.com/keystone/storage/storage-operator",
            &domains(),
            PREFIX,
        )
        .expect("valid SPIFFE ID");
        assert_eq!(role, OPERATOR_ROLE);
    }

    #[test]
    fn spiffe_id_valid_node_role() {
        let role = parse_spiffe_storage_id(
            "spiffe://alt.example.com/keystone/storage/node",
            &domains(),
            PREFIX,
        )
        .expect("valid SPIFFE ID");
        assert_eq!(role, "node");
    }

    // parse_spiffe_storage_id — invalid identities

    #[test]
    fn spiffe_id_wrong_trust_domain() {
        let err = parse_spiffe_storage_id(
            "spiffe://untrusted.com/keystone/storage/storage-operator",
            &domains(),
            PREFIX,
        )
        .expect_err("untrusted domain should fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn spiffe_id_wrong_path_prefix() {
        let err = parse_spiffe_storage_id(
            "spiffe://example.com/other/service/storage-operator",
            &domains(),
            PREFIX,
        )
        .expect_err("wrong path prefix should fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn spiffe_id_empty_role() {
        let err =
            parse_spiffe_storage_id("spiffe://example.com/keystone/storage/", &domains(), PREFIX)
                .expect_err("empty role should fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn spiffe_id_extra_path_segment() {
        let err = parse_spiffe_storage_id(
            "spiffe://example.com/keystone/storage/storage-operator/extra",
            &domains(),
            PREFIX,
        )
        .expect_err("extra path segment should fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn spiffe_id_not_a_spiffe_uri() {
        let err = parse_spiffe_storage_id("https://example.com/foo", &domains(), PREFIX)
            .expect_err("non-SPIFFE URI should fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // Rate limiter — basic token consumption

    #[test]
    fn rate_limiter_allows_up_to_burst() {
        let limiter: Arc<IdentityLimiter> =
            Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR)));
        let key = "spiffe://example.com/keystone/storage/storage-operator".to_owned();
        // Initial burst of 2 should be allowed.
        assert!(limiter.check_key(&key).is_ok(), "first request allowed");
        assert!(limiter.check_key(&key).is_ok(), "second request allowed");
        // Third request within the same window should be denied.
        assert!(
            limiter.check_key(&key).is_err(),
            "third request within burst window denied"
        );
    }

    #[test]
    fn rate_limiter_independent_keys() {
        let limiter: Arc<IdentityLimiter> =
            Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR)));
        let key_a = "spiffe://example.com/keystone/storage/storage-operator".to_owned();
        let key_b = "spiffe://example.com/keystone/storage/other-operator".to_owned();
        // Exhaust key_a.
        limiter.check_key(&key_a).ok();
        limiter.check_key(&key_a).ok();
        assert!(limiter.check_key(&key_a).is_err(), "key_a exhausted");
        // key_b is independent and still has capacity.
        assert!(limiter.check_key(&key_b).is_ok(), "key_b unaffected");
    }

    // Trust domain only — used for internal cluster operations

    #[test]
    fn spiffe_trust_domain_ok_standard_path() {
        assert!(
            parse_spiffe_trust_domain(
                "spiffe://example.com/keystone/storage/storage-operator",
                &domains(),
            )
            .is_ok()
        );
    }

    #[test]
    fn spiffe_trust_domain_ok_arbitrary_path() {
        assert!(
            parse_spiffe_trust_domain("spiffe://example.com/ns/default/sa/keystone", &domains(),)
                .is_ok()
        );
    }

    #[test]
    fn spiffe_trust_domain_wrong_domain() {
        assert!(
            parse_spiffe_trust_domain("spiffe://untrusted.example.com/foo", &domains(),).is_err()
        );
    }

    #[test]
    fn spiffe_trust_domain_not_spiffe_uri() {
        assert!(parse_spiffe_trust_domain("foo", &domains(),).is_err());
    }
    #[test]
    fn spiffe_trust_domain_no_path() {
        assert!(parse_spiffe_trust_domain("spiffe://example.com", &domains(),).is_err());
    }

    #[test]
    fn normalize_add_learner_bare_vs_schema() {
        // Simulate address uniqueness check: same node, different address format.
        // Stored: "127.0.0.1:21001", new: "https://127.0.0.1:21001/"
        // After normalization both should match → no conflict.
        let stored = "127.0.0.1:21001";
        let new_with_schema = "https://127.0.0.1:21001/";
        assert_eq!(
            normalize_rpc_addr(stored),
            normalize_rpc_addr(new_with_schema),
            "same host:port with different formats must normalize to identical string"
        );
    }

    #[test]
    fn normalize_add_learner_different_hosts() {
        // Different host:port should NOT match even after normalization.
        let a = "127.0.0.1:21001";
        let b = "https://127.0.0.1:21002/";
        assert_ne!(
            normalize_rpc_addr(a),
            normalize_rpc_addr(b),
            "different ports must not match"
        );
    }

    #[test]
    fn normalize_add_learner_fqdn_from_config() {
        // Replicates the real pod-restart scenario:
        // Committed membership has bare "host:port" from init,
        // config has https:// scheme + trailing slash from Uri::Display.
        let stored = "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300";
        let from_config =
            "https://keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300/";
        assert_eq!(
            normalize_rpc_addr(stored),
            normalize_rpc_addr(from_config),
            "stored bare address must match config Uri::Display format"
        );
    }
}
