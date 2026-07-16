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
            check_svid_ttl(request)?;
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

    // In SPIFFE mode, enforce the 5-minute force-renewal window (ADR 0016-v2 §4.1).
    if trust_domains.is_some() {
        check_svid_ttl(request)?;
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

// ---------------------------------------------------------------------------
// SVID TTL enforcement (ADR 0016-v2 §4.1 — force-renewal window)
// ---------------------------------------------------------------------------

/// Extracts the peer certificate from `request` and enforces the SVID
/// force-renewal window (ADR 0016-v2 §4.1). Only called in SPIFFE mode.
///
/// Redundant with the `SpiffeIdInterceptor` that already runs this check for
/// every request reaching this service (`raft_grpc::validate_spiffe_id`) —
/// kept as defense-in-depth on the RBAC-sensitive admin surface rather than
/// relying solely on the interceptor layer.
fn check_svid_ttl<T>(request: &tonic::Request<T>) -> Result<(), Status> {
    let der = request
        .peer_certs()
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
        .ok_or_else(|| Status::permission_denied("no peer certificate presented"))?;
    check_svid_ttl_der(&der, now_unix_secs())
}

/// Stages a node-local, quorum-bypass DEK rotation candidate in
/// `local_store` (ADR 0028 §3, amending ADR 0016-v2 §6.2). Pure business
/// logic, deliberately independent of the Raft handle and gRPC types so it
/// can be unit-tested without standing up a cluster; the guardrail check
/// (whether the bypass is currently permitted at all) is the caller's
/// responsibility.
///
/// Returns the fresh candidate's `(rotation_id, dek_version)` on success.
async fn stage_dek_local_emergency_candidate(
    local_store: &dyn LocalEmergencyStore,
    kek: &dyn KekProvider,
    current_version: u32,
    initiator: &str,
    justification: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(String, u32), Status> {
    let existing = local_store
        .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
        .await
        .map_err(|e| Status::internal(format!("local emergency store error: {e}")))?;
    if let Some(active) = existing.iter().find(|c| !c.revoked) {
        return Err(Status::already_exists(format!(
            "a local emergency DEK rotation candidate (id {}) already exists on this node",
            active.rotation_id
        )));
    }

    let new_version = current_version.checked_add(1).ok_or_else(|| {
        Status::internal("DEK version space exhausted — cannot rotate beyond u32::MAX")
    })?;
    let new_raw = generate_dek();
    let wrapped_dek = kek
        .wrap_dek(new_raw.as_bytes())
        .map_err(|e| Status::internal(format!("failed to wrap new DEK: {e}")))?;

    let rotation_id = uuid::Uuid::new_v4().to_string();
    let payload = rmp_serde::to_vec(&DekEmergencyPayload {
        wrapped_dek,
        dek_version: new_version,
    })
    .map_err(|e| Status::internal(format!("failed to encode candidate payload: {e}")))?;

    let candidate = EmergencyCandidate {
        subsystem: Subsystem::Dek,
        scope_id: DEK_SCOPE_ID.to_string(),
        rotation_id: rotation_id.clone(),
        payload,
        initiator: initiator.to_string(),
        justification: justification.to_string(),
        created_at: now,
        revoked: false,
        origin_node_id: None,
        conflicted: false,
    };
    local_store
        .put_candidate(candidate)
        .await
        .map_err(|e| Status::internal(format!("local emergency store error: {e}")))?;

    Ok((rotation_id, new_version))
}

/// Validates a DEK local-emergency candidate is reconcilable and decodes its
/// payload (ADR 0028 §6): must exist, must not be revoked, the confirming
/// operator must differ from the initiator (dual-control), and its target
/// `dek_version` must be exactly one past `current_version` (otherwise a
/// different rotation already committed while this candidate was staged and
/// installing it would silently regress or duplicate a version). Pure
/// validation, independent of Raft/gRPC, so it can be unit-tested without a
/// live cluster.
async fn validate_dek_reconcile_candidate(
    local_store: &dyn LocalEmergencyStore,
    rotation_id: &str,
    confirmer: &str,
    current_version: u32,
) -> Result<DekEmergencyPayload, Status> {
    let candidate = local_store
        .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, rotation_id)
        .await
        .map_err(|e| Status::internal(format!("local emergency store error: {e}")))?
        .ok_or_else(|| {
            Status::not_found(format!(
                "no local emergency DEK rotation candidate with id {rotation_id} on this node"
            ))
        })?;
    if candidate.revoked {
        return Err(Status::failed_precondition(format!(
            "local emergency rotation candidate {rotation_id} has been revoked and cannot be reconciled"
        )));
    }
    if candidate.initiator == confirmer {
        return Err(Status::permission_denied(
            "the confirming operator must differ from the initiating operator \
             (dual-control requirement)",
        ));
    }

    let payload: DekEmergencyPayload = rmp_serde::from_slice(&candidate.payload)
        .map_err(|e| Status::internal(format!("failed to decode candidate payload: {e}")))?;
    if Some(payload.dek_version) != current_version.checked_add(1) {
        return Err(Status::failed_precondition(format!(
            "candidate {rotation_id} targets DEK version {} but the current version is \
             {current_version} (another rotation committed while this candidate was staged); \
             re-stage a fresh local-quorum-bypass rotation instead",
            payload.dek_version
        )));
    }

    Ok(payload)
}

/// Applies a gossiped candidate (ADR 0028 §5) to `local_store`: adopts it if
/// nothing active exists locally for the same `(subsystem, scope_id)`,
/// marks both the existing and incoming candidate conflicted if a
/// *different* active one exists, or no-ops on an exact re-gossip. Returns
/// `true` if a conflict was recorded.
///
/// Independent of gRPC/tonic types (beyond the return being a plain `bool`)
/// so it can be unit-tested without standing up a cluster or a gRPC
/// transport.
async fn receive_gossiped_candidate(
    local_store: &dyn LocalEmergencyStore,
    incoming: EmergencyCandidate,
) -> Result<bool, openstack_keystone_local_emergency_store::LocalEmergencyStoreError> {
    let existing_active: Vec<EmergencyCandidate> = local_store
        .list_candidates(incoming.subsystem, &incoming.scope_id)
        .await?
        .into_iter()
        .filter(|c| !c.revoked)
        .collect();

    match openstack_keystone_local_emergency_store::decide_gossip_outcome(
        &existing_active,
        &incoming,
    ) {
        openstack_keystone_local_emergency_store::GossipOutcome::Adopt => {
            local_store.put_candidate(incoming).await?;
            Ok(false)
        }
        openstack_keystone_local_emergency_store::GossipOutcome::AlreadyPresent => Ok(false),
        openstack_keystone_local_emergency_store::GossipOutcome::Conflict {
            existing_rotation_id,
        } => {
            local_store
                .mark_conflicted(
                    incoming.subsystem,
                    &incoming.scope_id,
                    &existing_rotation_id,
                )
                .await?;
            let mut incoming = incoming;
            incoming.conflicted = true;
            local_store.put_candidate(incoming).await?;
            Ok(true)
        }
    }
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
    /// ADR 0028 node-local, quorum-bypass emergency write store.
    local_emergency_store: Arc<dyn LocalEmergencyStore>,
    /// `[local_emergency]` config, snapshotted at storage init.
    local_emergency_config: LocalEmergencyProvider,
    /// Tracks how long the Raft leader has been unknown, feeding the
    /// quorum-bypass guardrail (ADR 0028 §2).
    local_emergency_leaderless_tracker: LeaderlessTracker,
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
    #[allow(clippy::too_many_arguments)]
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
            spiffe_trust_domains,
            spiffe_path_prefix,
            operator_role,
            allowed_peer_svids,
            rotate_dek_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR))),
            clear_quarantine_limiter: Arc::new(RateLimiter::keyed(Quota::per_hour(
                CLEAR_QUARANTINE_PER_HOUR,
            ))),
            local_emergency_store,
            local_emergency_config,
            local_emergency_leaderless_tracker: LeaderlessTracker::new(),
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        let req = request.into_inner();
        if req.justification.trim().is_empty() {
            return Err(Status::invalid_argument(
                "justification is required for a local-quorum-bypass DEK rotation",
            ));
        }

        let guardrail_cfg = GuardrailConfig {
            enabled: self.local_emergency_config.enabled,
            leaderless_grace_period_seconds: self
                .local_emergency_config
                .leaderless_grace_period_seconds,
        };
        let current_leader = self.raft_node.metrics().borrow_watched().current_leader;
        let now = chrono::Utc::now();
        self.local_emergency_leaderless_tracker
            .observe(current_leader, now);
        if !self.local_emergency_leaderless_tracker.is_bypass_allowed(
            &guardrail_cfg,
            current_leader,
            now,
        ) {
            return Err(Status::failed_precondition(
                "local quorum-bypass rotation is not currently permitted on this node \
                 (disabled, or quorum has not been unreachable long enough)",
            ));
        }

        let current_version = {
            self.current_dek
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .version
        };
        let (rotation_id, new_version) = stage_dek_local_emergency_candidate(
            self.local_emergency_store.as_ref(),
            self.kek.as_ref(),
            current_version,
            &actor,
            &req.justification,
            now,
        )
        .await?;

        self.audit.emit(AuditRecord::now(
            "DEK_ROTATION_LOCAL_EMERGENCY_STAGED",
            &actor,
            self.node_id,
            new_version,
            serde_json::json!({
                "rotation_id": rotation_id,
                "justification": req.justification,
            }),
        ));
        tracing::warn!(
            rotation_id,
            new_version,
            initiator = actor,
            "SECURITY: node-local quorum-bypass DEK rotation staged; NOT replicated, \
             requires explicit reconciliation once quorum returns"
        );

        Ok(Response::new(pb::raft::RotateDekLocalEmergencyResponse {
            rotation_id,
        }))
    }

    /// Lists node-local DEK emergency rotation candidates on this node
    /// (ADR 0028 §6), so an operator can see any `LOCAL_EMERGENCY_CONFLICT`
    /// before choosing which `rotation_id` to reconcile.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn list_dek_local_emergency_candidates(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::ListDekLocalEmergencyCandidatesResponse>, Status> {
        require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;

        let candidates = self
            .local_emergency_store
            .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
            .await
            .map_err(|e| Status::internal(format!("local emergency store error: {e}")))?
            .into_iter()
            .map(|c| pb::raft::DekLocalEmergencyCandidateSummary {
                rotation_id: c.rotation_id,
                initiator: c.initiator,
                justification: c.justification,
                created_at_unix: c.created_at.timestamp(),
                origin_node_id: c.origin_node_id.unwrap_or(0),
                conflicted: c.conflicted,
                revoked: c.revoked,
            })
            .collect();

        Ok(Response::new(
            pb::raft::ListDekLocalEmergencyCandidatesResponse { candidates },
        ))
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
        let actor = require_operator(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.spiffe_path_prefix,
            &self.operator_role,
        )?;
        let req = request.into_inner();
        let current_version = {
            self.current_dek
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .version
        };
        let payload = validate_dek_reconcile_candidate(
            self.local_emergency_store.as_ref(),
            &req.rotation_id,
            &actor,
            current_version,
        )
        .await?;

        let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek: payload.wrapped_dek,
            dek_version: payload.dek_version,
            is_emergency: true,
        }]);
        let install_payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;

        self.audit.emit(AuditRecord::now(
            "DEK_ROTATION_LOCAL_EMERGENCY_RECONCILED",
            &actor,
            self.node_id,
            payload.dek_version,
            serde_json::json!({ "rotation_id": req.rotation_id }),
        ));

        self.raft_node
            .client_write(install_payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")))?;

        tracing::warn!(
            rotation_id = req.rotation_id,
            new_version = payload.dek_version,
            confirmer = actor,
            "SECURITY: node-local quorum-bypass DEK rotation reconciled into Raft"
        );

        // Durably committed; clear this candidate and revoke any other
        // active sibling for this scope on this node (ADR 0028 §6).
        if let Err(e) = self
            .local_emergency_store
            .clear_candidate(Subsystem::Dek, DEK_SCOPE_ID, &req.rotation_id)
            .await
        {
            tracing::warn!(
                rotation_id = req.rotation_id,
                error = %e,
                "failed to clear reconciled local emergency DEK candidate"
            );
        }
        match self
            .local_emergency_store
            .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
            .await
        {
            Ok(siblings) => {
                for sibling in siblings.iter().filter(|c| !c.revoked) {
                    if let Err(e) = self
                        .local_emergency_store
                        .revoke_candidate(Subsystem::Dek, DEK_SCOPE_ID, &sibling.rotation_id)
                        .await
                    {
                        tracing::warn!(
                            rotation_id = sibling.rotation_id,
                            error = %e,
                            "failed to revoke superseded local emergency DEK candidate"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to list local emergency DEK candidates for post-reconcile cleanup"
                );
            }
        }

        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    /// Receives a best-effort, peer-to-peer gossip push of another node's
    /// local emergency candidate (ADR 0028 §5). Adopts it if this node holds
    /// no active candidate for the same subsystem/scope, marks both as
    /// conflicted if it holds a *different* active one, or no-ops if it
    /// already has this exact candidate (idempotent re-gossip).
    ///
    /// # Security
    /// Called peer-to-peer between storage nodes, not by a human operator —
    /// authenticated the same way as Raft's own inter-node RPCs
    /// (`check_peer_trust_domain`), not `require_operator`.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn gossip_local_emergency_candidate(
        &self,
        request: Request<pb::raft::GossipLocalEmergencyCandidateRequest>,
    ) -> Result<Response<pb::raft::GossipLocalEmergencyCandidateResponse>, Status> {
        check_peer_trust_domain(
            &request,
            self.spiffe_trust_domains.as_deref(),
            &self.allowed_peer_svids,
        )?;
        let req = request.into_inner();
        let subsystem = match pb::raft::EmergencySubsystem::try_from(req.subsystem) {
            Ok(pb::raft::EmergencySubsystem::Oauth2SigningKey) => Subsystem::Oauth2SigningKey,
            Ok(pb::raft::EmergencySubsystem::Dek) => Subsystem::Dek,
            Err(_) => {
                return Err(Status::invalid_argument("unknown emergency subsystem tag"));
            }
        };
        let created_at = chrono::DateTime::from_timestamp(req.created_at_unix, 0)
            .unwrap_or_else(chrono::Utc::now);
        let incoming = EmergencyCandidate {
            subsystem,
            scope_id: req.scope_id.clone(),
            rotation_id: req.rotation_id.clone(),
            payload: req.payload,
            initiator: req.initiator,
            justification: req.justification,
            created_at,
            revoked: false,
            origin_node_id: Some(req.origin_node_id),
            conflicted: false,
        };

        let conflict = receive_gossiped_candidate(self.local_emergency_store.as_ref(), incoming)
            .await
            .map_err(|e| Status::internal(format!("local emergency store error: {e}")))?;

        Ok(Response::new(
            pb::raft::GossipLocalEmergencyCandidateResponse { conflict },
        ))
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

    // SVID TTL enforcement (ADR 0016-v2 §4.1 — force-renewal window)

    // Unix timestamp of 2100-01-01 00:00:00 UTC (used as a stable not_after
    // anchor).
    const NOT_AFTER_2100_UNIX: i64 = 4_102_444_800;

    fn make_svid_der_not_after_2100() -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair, date_time_ymd};
        let mut params = CertificateParams::default();
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2100, 1, 1);
        let key = KeyPair::generate().expect("keygen");
        params
            .self_signed(&key)
            .expect("self-sign")
            .der()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn svid_ttl_ok() {
        let der = make_svid_der_not_after_2100();
        // 10 minutes before expiry — well outside the 5-minute window.
        assert!(check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX - 600).is_ok());
    }

    #[test]
    fn svid_ttl_force_renewal_window() {
        let der = make_svid_der_not_after_2100();
        // 4 minutes before expiry — inside the 5-minute force-renewal window.
        let err = check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX - 240)
            .expect_err("should fail inside force-renewal window");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn svid_ttl_expired() {
        let der = make_svid_der_not_after_2100();
        // 1 second past expiry.
        let err = check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX + 1)
            .expect_err("should fail when expired");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // stage_dek_local_emergency_candidate (ADR 0028 §3) — pure business
    // logic, independent of Raft/gRPC.

    mod stage_dek_local_emergency {
        use chrono::Utc;
        use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;
        use openstack_keystone_storage_crypto::EnvKek;

        use super::*;

        fn kek() -> EnvKek {
            EnvKek::from_bytes([7u8; 32])
        }

        #[tokio::test]
        async fn stages_a_fresh_candidate_and_bumps_version() {
            let store = InMemoryLocalEmergencyStore::new();
            let (rotation_id, new_version) = stage_dek_local_emergency_candidate(
                &store,
                &kek(),
                3,
                "spiffe://example.org/keystone/storage/storage-operator",
                "suspected key compromise",
                Utc::now(),
            )
            .await
            .expect("should stage");

            assert_eq!(new_version, 4);
            let candidates = store
                .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
                .await
                .unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].rotation_id, rotation_id);
            assert_eq!(candidates[0].justification, "suspected key compromise");
            assert!(!candidates[0].revoked);

            let decoded: DekEmergencyPayload =
                rmp_serde::from_slice(&candidates[0].payload).unwrap();
            assert_eq!(decoded.dek_version, 4);
        }

        #[tokio::test]
        async fn refuses_a_second_candidate_while_one_is_active() {
            let store = InMemoryLocalEmergencyStore::new();
            stage_dek_local_emergency_candidate(&store, &kek(), 3, "op-a", "reason-1", Utc::now())
                .await
                .expect("first stage should succeed");

            let err = stage_dek_local_emergency_candidate(
                &store,
                &kek(),
                3,
                "op-b",
                "reason-2",
                Utc::now(),
            )
            .await
            .expect_err("second stage should be refused while one is active");
            assert_eq!(err.code(), tonic::Code::AlreadyExists);
        }

        #[tokio::test]
        async fn allows_a_new_candidate_after_the_prior_one_is_revoked() {
            let store = InMemoryLocalEmergencyStore::new();
            let (first_id, _) = stage_dek_local_emergency_candidate(
                &store,
                &kek(),
                3,
                "op-a",
                "reason-1",
                Utc::now(),
            )
            .await
            .expect("first stage should succeed");
            store
                .revoke_candidate(Subsystem::Dek, DEK_SCOPE_ID, &first_id)
                .await
                .unwrap();

            let (second_id, new_version) = stage_dek_local_emergency_candidate(
                &store,
                &kek(),
                3,
                "op-b",
                "reason-2",
                Utc::now(),
            )
            .await
            .expect("should stage after revocation");
            assert_ne!(first_id, second_id);
            assert_eq!(new_version, 4);
        }

        #[tokio::test]
        async fn refuses_when_dek_version_space_is_exhausted() {
            let store = InMemoryLocalEmergencyStore::new();
            let err = stage_dek_local_emergency_candidate(
                &store,
                &kek(),
                u32::MAX,
                "op-a",
                "reason",
                Utc::now(),
            )
            .await
            .expect_err("version overflow should be refused");
            assert_eq!(err.code(), tonic::Code::Internal);
        }
    }

    // validate_dek_reconcile_candidate (ADR 0028 §6) — pure validation
    // logic, independent of Raft/gRPC.

    mod validate_dek_reconcile_candidate_tests {
        use chrono::Utc;
        use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;
        use openstack_keystone_storage_crypto::EnvKek;

        use super::*;

        async fn stage(store: &InMemoryLocalEmergencyStore, initiator: &str) -> String {
            stage_dek_local_emergency_candidate(
                store,
                &EnvKek::from_bytes([7u8; 32]),
                3,
                initiator,
                "suspected key compromise",
                Utc::now(),
            )
            .await
            .unwrap()
            .0
        }

        #[tokio::test]
        async fn accepts_a_fresh_candidate_from_a_different_operator() {
            let store = InMemoryLocalEmergencyStore::new();
            let rotation_id = stage(&store, "op-a").await;

            let payload = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 3)
                .await
                .unwrap();
            assert_eq!(payload.dek_version, 4);
        }

        #[tokio::test]
        async fn rejects_unknown_rotation_id() {
            let store = InMemoryLocalEmergencyStore::new();
            let err = validate_dek_reconcile_candidate(&store, "rot-unknown", "op-b", 3)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        #[tokio::test]
        async fn rejects_revoked_candidate() {
            let store = InMemoryLocalEmergencyStore::new();
            let rotation_id = stage(&store, "op-a").await;
            store
                .revoke_candidate(Subsystem::Dek, DEK_SCOPE_ID, &rotation_id)
                .await
                .unwrap();

            let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 3)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        }

        #[tokio::test]
        async fn rejects_same_operator_as_initiator() {
            let store = InMemoryLocalEmergencyStore::new();
            let rotation_id = stage(&store, "op-a").await;

            let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-a", 3)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }

        #[tokio::test]
        async fn rejects_stale_candidate_when_version_has_moved_on() {
            let store = InMemoryLocalEmergencyStore::new();
            // Staged when current_version was 3 (so it targets version 4),
            // but by the time reconciliation runs the live version has
            // already advanced to 5 (e.g. a normal RotateDek committed while
            // this candidate was staged).
            let rotation_id = stage(&store, "op-a").await;

            let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 5)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        }
    }

    // receive_gossiped_candidate (ADR 0028 §5) — pure business logic,
    // independent of Raft/gRPC.

    mod receive_gossiped_candidate_tests {
        use chrono::Utc;
        use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;

        use super::*;

        fn incoming(rotation_id: &str, origin_node_id: u64) -> EmergencyCandidate {
            EmergencyCandidate {
                subsystem: Subsystem::Dek,
                scope_id: DEK_SCOPE_ID.to_string(),
                rotation_id: rotation_id.to_string(),
                payload: vec![4, 5, 6],
                initiator: "spiffe://example.org/keystone/storage/storage-operator".to_string(),
                justification: "suspected key compromise".to_string(),
                created_at: Utc::now(),
                revoked: false,
                origin_node_id: Some(origin_node_id),
                conflicted: false,
            }
        }

        #[tokio::test]
        async fn adopts_first_gossiped_candidate() {
            let store = InMemoryLocalEmergencyStore::new();
            let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
                .await
                .unwrap();
            assert!(!conflict);

            let stored = store
                .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, "rot-remote")
                .await
                .unwrap()
                .expect("candidate should be adopted");
            assert_eq!(stored.origin_node_id, Some(2));
            assert!(!stored.conflicted);
        }

        #[tokio::test]
        async fn re_gossip_of_the_same_candidate_is_a_noop() {
            let store = InMemoryLocalEmergencyStore::new();
            receive_gossiped_candidate(&store, incoming("rot-remote", 2))
                .await
                .unwrap();

            let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
                .await
                .unwrap();
            assert!(!conflict);
        }

        #[tokio::test]
        async fn conflicting_candidate_marks_both_sides() {
            let store = InMemoryLocalEmergencyStore::new();
            // This node already has its own locally-staged active candidate.
            stage_dek_local_emergency_candidate(
                &store,
                &openstack_keystone_storage_crypto::EnvKek::from_bytes([7u8; 32]),
                3,
                "spiffe://example.org/keystone/storage/storage-operator",
                "suspected key compromise",
                Utc::now(),
            )
            .await
            .unwrap();
            let local_candidates = store
                .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
                .await
                .unwrap();
            assert_eq!(local_candidates.len(), 1);
            let local_rotation_id = local_candidates[0].rotation_id.clone();

            let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
                .await
                .unwrap();
            assert!(conflict);

            let local_after = store
                .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, &local_rotation_id)
                .await
                .unwrap()
                .unwrap();
            assert!(local_after.conflicted);
            assert!(!local_after.revoked, "conflict must not itself revoke");

            let remote_after = store
                .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, "rot-remote")
                .await
                .unwrap()
                .unwrap();
            assert!(remote_after.conflicted);
        }

        #[tokio::test]
        async fn adopts_after_local_candidate_is_revoked() {
            let store = InMemoryLocalEmergencyStore::new();
            stage_dek_local_emergency_candidate(
                &store,
                &openstack_keystone_storage_crypto::EnvKek::from_bytes([7u8; 32]),
                3,
                "op-a",
                "reason",
                Utc::now(),
            )
            .await
            .unwrap();
            let local_candidates = store
                .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
                .await
                .unwrap();
            store
                .revoke_candidate(
                    Subsystem::Dek,
                    DEK_SCOPE_ID,
                    &local_candidates[0].rotation_id,
                )
                .await
                .unwrap();

            let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
                .await
                .unwrap();
            assert!(!conflict, "a revoked local candidate must not conflict");
        }
    }
}
