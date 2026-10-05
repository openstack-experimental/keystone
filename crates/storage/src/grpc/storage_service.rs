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

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use openraft::ReadPolicy;
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ForwardToLeader, RaftError};
use openstack_keystone_storage_crypto::DekEpoch;
use tonic::metadata::MetadataValue;
use tonic::{Request, Response, Status};

use crate::DataTier;
use crate::app::{LEADER_ENDPOINT_HEADER, LEADER_ID_HEADER};
use crate::audit::{AuditForwarder, AuditRecord};
use crate::grpc::authz::{PeerAuthz, PeerRole};
use crate::pb;
use crate::protobuf::api::Response as PbResponse;
use crate::protobuf::api::storage_service_server::StorageService;
use crate::store_command::{MutationInner, StoreCommand};
use crate::types::*;

/// Maximum `ReportQuarantine` calls accepted per reporter identity per hour.
pub(crate) const QUARANTINE_REPORTS_PER_HOUR: NonZeroU32 = match NonZeroU32::new(30) {
    Some(v) => v,
    None => panic!("rate limit constant must be non-zero"),
};

/// Maximum length (bytes) of a reported quarantine partition name.
const MAX_QUARANTINE_PARTITION_LEN: usize = 128;

/// Internal service implementation for Raft protocol communications.
/// This service handles the core Raft consensus protocol operations between
/// cluster nodes.
///
/// # Responsibilities
/// - Vote requests/responses during leader election
/// - Log replication between nodes
/// - Snapshot installation for state synchronization
/// - Forwarded read requests from followers to leader
///
/// # Protocol Safety
/// This service implements critical consensus protocol operations and should
/// only be exposed to other trusted Raft cluster nodes, never to external
/// clients.
pub struct StorageServiceImpl {
    /// The local Raft node instance that this service operates on.
    pub(crate) raft_node: Raft,
    /// Direct access to the state machine store for forwarded reads.
    state_machine_store: Arc<StateMachineStore>,
    /// Peer certificate role enforcement.
    authz: Arc<PeerAuthz>,
    /// Audit record forwarder for quarantine reports.
    audit: AuditForwarder,
    /// Shared current DEK epoch (audit record `dek_version`).
    current_dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// This node's Raft ID (audit record attribution).
    node_id: u64,
    /// Per-reporter-identity rate limiter for `ReportQuarantine`.
    quarantine_limiter: DefaultKeyedRateLimiter<String>,
}

/// Validate a `ReportQuarantine` request against the current membership.
///
/// The partition must be 1..=128 bytes and the claimed `node_id` must be a
/// current cluster member (voter or learner).
pub(crate) fn validate_quarantine_report(
    node_id: u64,
    partition: &str,
    members: &BTreeSet<u64>,
) -> Result<(), Status> {
    if partition.is_empty() || partition.len() > MAX_QUARANTINE_PARTITION_LEN {
        return Err(Status::invalid_argument("partition must be 1..=128 bytes"));
    }
    if !members.contains(&node_id) {
        return Err(Status::permission_denied("node_id is not a cluster member"));
    }
    Ok(())
}

/// Whether a quarantine write outcome is a follower redirect (leader hint or
/// unknown-leader `Unavailable`), which must not be audited as a failure.
pub(crate) fn is_leader_redirect(write: &Result<(), Status>) -> bool {
    matches!(write, Err(s) if s.code() == tonic::Code::Unavailable)
}

/// `Unavailable` status carrying the leader hint headers
/// ([`LEADER_ENDPOINT_HEADER`], [`LEADER_ID_HEADER`]) that the follower-side
/// forwarding loop reads to retry against the current leader.
pub(crate) fn forward_to_leader_status(leader_id: u64, leader_addr: &str) -> Status {
    let mut status = Status::unavailable("not the leader; retry against the leader");
    let md = status.metadata_mut();
    if let Ok(v) = MetadataValue::try_from(leader_addr) {
        md.insert(LEADER_ENDPOINT_HEADER, v);
    }
    if let Ok(v) = MetadataValue::try_from(leader_id.to_string()) {
        md.insert(LEADER_ID_HEADER, v);
    }
    status
}

/// Decode a wire `command` payload and reject anything that is not a plain
/// data mutation.
pub(crate) fn decode_data_command(payload: &[u8]) -> Result<StoreCommand, Status> {
    let cmd = StoreCommand::unpack(payload)
        .map_err(|e| Status::invalid_argument(format!("malformed command: {e}")))?;
    crate::grpc::authz::ensure_data_command(&cmd)?;
    Ok(cmd)
}

impl StorageServiceImpl {
    /// Creates a new instance of the internal service.
    ///
    /// # Parameters
    /// - `raft_node`: The Raft node instance this service will operate on.
    /// - `state_machine_store`: The state machine store for direct reads.
    /// - `authz`: Peer role resolver; every RPC requires the node role.
    /// - `audit`: Audit forwarder for quarantine report records.
    /// - `current_dek`: Shared current DEK epoch (audit `dek_version`).
    /// - `node_id`: This node's Raft ID (audit attribution).
    ///
    /// # Returns
    /// A new `StorageServiceImpl` instance.
    pub fn new(
        raft_node: Raft,
        state_machine_store: Arc<StateMachineStore>,
        authz: Arc<PeerAuthz>,
        audit: AuditForwarder,
        current_dek: Arc<RwLock<Arc<DekEpoch>>>,
        node_id: u64,
    ) -> Self {
        Self {
            raft_node,
            state_machine_store,
            authz,
            audit,
            current_dek,
            node_id,
            quarantine_limiter: RateLimiter::keyed(Quota::per_hour(QUARANTINE_REPORTS_PER_HOUR)),
        }
    }

    /// Current cluster membership (voters and learners).
    fn member_ids(&self) -> BTreeSet<u64> {
        self.raft_node
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .nodes()
            .map(|(id, _)| *id)
            .collect()
    }

    /// Re-confirm this node is still leader with an up-to-date read index
    /// before serving a forwarded read.
    ///
    /// A follower that observed `ForwardToLeader` forwards the read here,
    /// but leadership can change between that observation and this RPC
    /// landing -- without re-checking, a former leader would serve a local
    /// read that is no longer guaranteed linearizable (e.g. a competing
    /// leader committed writes this node hasn't seen), silently breaking
    /// read-your-writes for the forwarded caller.
    async fn ensure_leader_linearizable(&self) -> Result<(), Status> {
        self.raft_node
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map(|_| ())
            .map_err(|e| Status::unavailable(format!("not linearizable leader: {e}")))
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    /// Saves a storage modification command.
    ///
    /// # Parameters
    /// - `request`: Contains the key and value to set.
    ///
    /// # Returns
    /// A `Result` containing a `Response` after the value is set, or a `Status`
    /// error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn command(
        &self,
        request: Request<pb::api::CommandRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        self.authz.require(&request, &[PeerRole::Node])?;
        let req = request.into_inner();
        // Check-only: the decoded value is intentionally discarded; the same
        // bytes are applied through Raft below.
        decode_data_command(&req.payload)?;

        let res =
            self.raft_node.client_write(req).await.map_err(|e| {
                Status::internal(format!("Failed to write command to store: {}", e))
            })?;

        // Convert right before the wire boundary, so the zeroizing wrapper
        // is held as long as possible (ADR 0016-v2 §8).
        Ok(Response::new(res.data.into()))
    }

    /// Handles a forwarded get request from a follower.
    ///
    /// Reads the requested key from the local state machine store, decrypts
    /// it, and returns the plaintext value along with packed metadata bytes
    /// (including revision and data tier) so that the follower can preserve
    /// the leader's metadata for correct revision-check semantics.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_get(
        &self,
        request: Request<pb::api::ForwardedGetRequest>,
    ) -> Result<Response<pb::api::ForwardedGetResponse>, Status> {
        self.authz.require(&request, &[PeerRole::Node])?;
        self.ensure_leader_linearizable().await?;
        let req = request.into_inner();
        let key = match std::str::from_utf8(&req.key) {
            Ok(s) => s.to_string(),
            Err(e) => return Err(Status::invalid_argument(format!("invalid key: {}", e))),
        };

        let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
        if self
            .state_machine_store
            .is_ephemeral_keyspace(keyspace_name)
        {
            let found = self
                .state_machine_store
                .ephemeral_get(keyspace_name, key.as_bytes());
            let (value, metadata_bytes) = match found {
                Some((value, metadata)) => (
                    Some(value),
                    metadata
                        .pack()
                        .map_err(|e| Status::internal(format!("metadata pack error: {}", e)))?,
                ),
                None => (None, Vec::new()),
            };
            return Ok(Response::new(pb::api::ForwardedGetResponse {
                not_found: value.is_none(),
                value,
                metadata: metadata_bytes,
            }));
        }

        // Read metadata to determine the data tier
        let metadata = self
            .state_machine_store
            .meta()
            .get(crate::store::state_machine::meta_key(
                keyspace_name,
                key.as_bytes(),
            ))
            .map_err(|e| Status::internal(format!("metadata read error: {}", e)))?
            .map(|raw| Metadata::unpack(raw.as_ref()))
            .transpose()
            .map_err(|e| Status::internal(format!("metadata unpack error: {}", e)))?;

        // Read encrypted value from leader's FjallDB
        let ks = match &req.keyspace {
            Some(name) => self
                .state_machine_store
                .keyspace(name)
                .map_err(|e| Status::internal(format!("keyspace error: {}", e)))?,
            None => self.state_machine_store.data().clone(),
        };

        let encrypted = ks
            .get(key.as_bytes())
            .map_err(|e| Status::internal(format!("data read error: {}", e)))?;

        let not_found = encrypted.is_none() || metadata.is_none();
        let tier = (metadata.as_ref().map(|m| m.tier as u8)).unwrap_or(DataTier::Internal as u8);
        let dek_version = metadata.as_ref().and_then(|m| m.dek_version);

        let value = encrypted.and_then(|enc| {
            let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
            let keyspace_bytes = keyspace_name.as_bytes();
            match self.state_machine_store.decrypt_state(
                &enc,
                tier,
                keyspace_bytes,
                key.as_bytes(),
                dek_version,
            ) {
                Ok(plaintext) => Some(plaintext),
                Err(e) => {
                    // Collapsed to the same wire response as "not found" below
                    // (the forwarded-get protocol has no distinct error slot),
                    // but logged so an operator can tell a quarantined/corrupt
                    // record apart from a genuinely missing key.
                    tracing::warn!(key, error = %e, "forwarded_get: decrypt_state failed");
                    None
                }
            }
        });

        let metadata_bytes = metadata
            .map(|m| m.pack())
            .transpose()
            .map_err(|e| Status::internal(format!("metadata pack error: {}", e)))?
            .unwrap_or_default();

        let response = pb::api::ForwardedGetResponse {
            value,
            not_found,
            metadata: metadata_bytes,
        };

        Ok(Response::new(response))
    }

    /// Handles a forwarded prefix scan request from a follower.
    ///
    /// Scans the local state machine store for keys matching the prefix,
    /// decrypts them, and returns the plaintext values.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_prefix(
        &self,
        request: Request<pb::api::ForwardedPrefixRequest>,
    ) -> Result<Response<pb::api::ForwardedPrefixResponse>, Status> {
        self.authz.require(&request, &[PeerRole::Node])?;
        self.ensure_leader_linearizable().await?;
        let req = request.into_inner();

        let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
        if let Some(entries) = self
            .state_machine_store
            .ephemeral_prefix(keyspace_name, &req.prefix)
        {
            let items = entries
                .into_iter()
                .filter_map(|(key_bytes, value, metadata)| {
                    let key = String::from_utf8(key_bytes).ok()?;
                    let metadata_bytes = metadata.pack().ok()?;
                    Some(pb::api::PrefixEntry {
                        key,
                        value,
                        metadata: metadata_bytes,
                    })
                })
                .collect();
            return Ok(Response::new(pb::api::ForwardedPrefixResponse {
                entries: items,
            }));
        }

        let ks = match &req.keyspace {
            Some(name) => self
                .state_machine_store
                .keyspace(name)
                .map_err(|e| Status::internal(format!("keyspace error: {}", e)))?,
            None => self.state_machine_store.data().clone(),
        };

        let meta = self.state_machine_store.meta();
        let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
        let keyspace_bytes = keyspace_name.as_bytes();

        let items: Vec<_> = ks
            .prefix(&req.prefix)
            .filter_map(|item| {
                let (key_bytes, val) = match item.into_inner() {
                    Ok(i) => i,
                    Err(_) => return None,
                };
                let k = match String::from_utf8(key_bytes.to_vec()) {
                    Ok(k) => k,
                    Err(_) => return None,
                };

                // Read metadata to determine tier and DEK epoch
                let record_meta_key =
                    crate::store::state_machine::meta_key(keyspace_name, k.as_bytes());
                let (tier, dek_version, meta_bytes) = match meta.get(&record_meta_key) {
                    Ok(Some(raw)) => {
                        let parsed = Metadata::unpack(raw.as_ref()).ok();
                        (
                            parsed
                                .as_ref()
                                .map(|m| m.tier as u8)
                                .unwrap_or(DataTier::Internal as u8),
                            parsed.and_then(|m| m.dek_version),
                            raw.to_vec(),
                        )
                    }
                    _ => (DataTier::Internal as u8, None, Vec::new()),
                };

                // Decrypt using leader's DEK
                let data = match self.state_machine_store.decrypt_state(
                    &val,
                    tier,
                    keyspace_bytes,
                    k.as_bytes(),
                    dek_version,
                ) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        // Omitted from results (same as any other filtered-out
                        // entry) but logged so a quarantined/corrupt record is
                        // distinguishable from one that simply doesn't match
                        // the prefix.
                        tracing::warn!(key = k, error = %e, "forwarded_prefix: decrypt_state failed");
                        return None;
                    }
                };

                Some(pb::api::PrefixEntry {
                    key: k,
                    value: data,
                    metadata: meta_bytes,
                })
            })
            .collect();
        Ok(Response::new(pb::api::ForwardedPrefixResponse {
            entries: items,
        }))
    }

    // Forwarded prefix-index scan from follower to leader.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_prefix_index(
        &self,
        request: Request<pb::api::ForwardedPrefixIndexRequest>,
    ) -> Result<Response<pb::api::ForwardedPrefixIndexResponse>, Status> {
        self.authz.require(&request, &[PeerRole::Node])?;
        self.ensure_leader_linearizable().await?;
        let req = request.into_inner();

        let items: Vec<_> = self
            .state_machine_store
            .index()
            .prefix(&req.prefix)
            .filter_map(|item| -> Option<String> {
                let key = match item.key() {
                    Ok(k) => k,
                    Err(_) => return None,
                };
                String::from_utf8(key.to_vec()).ok()
            })
            .collect();

        Ok(Response::new(pb::api::ForwardedPrefixIndexResponse {
            keys: items,
        }))
    }

    /// Accepts a node's report of a locally-triggered quarantine and commits
    /// it via Raft (ADR 0016-v2 §10 invariant 5).
    ///
    /// Leader-only: a non-leader answers `Unavailable` with the leader hint
    /// headers so the reporter can retry against the leader. Reports are
    /// rate limited per reporter identity and audited with that identity.
    ///
    /// # Security
    /// Requires the node role. The claimed `node_id` must be a current
    /// member; it is not bound to the reporter's certificate, so the audit
    /// record carries both the reporter identity and the claimed node.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn report_quarantine(
        &self,
        request: Request<pb::api::ReportQuarantineRequest>,
    ) -> Result<Response<()>, Status> {
        let (reporter, _) = self.authz.require(&request, &[PeerRole::Node])?;
        let req = request.into_inner();
        if self.quarantine_limiter.check_key(&reporter).is_err() {
            let status = Status::resource_exhausted("quarantine report rate limit exceeded");
            self.audit_rejected_report(&reporter, req.node_id, &req.partition, &status);
            return Err(status);
        }
        if let Err(status) =
            validate_quarantine_report(req.node_id, &req.partition, &self.member_ids())
        {
            self.audit_rejected_report(&reporter, req.node_id, &req.partition, &status);
            return Err(status);
        }

        let cmd = StoreCommand::Transaction(vec![MutationInner::Quarantine {
            node_id: req.node_id,
            partition: req.partition.clone(),
        }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;
        let write = match self.raft_node.client_write(payload).await {
            Ok(_) => Ok(()),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => Err(forward_to_leader_status(leader_id, &leader_node.rpc_addr)),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => {
                Err(Status::unavailable("not the leader; leader unknown"))
            }
            Err(e) => Err(Status::internal(format!("Raft write failed: {e}"))),
        };

        // A follower redirect is not a failure, so it is not audited.
        if !is_leader_redirect(&write) {
            let dek_version = self
                .current_dek
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .version;
            let mut details = serde_json::json!({
                "claimed_node_id": req.node_id,
                "partition": req.partition,
            });
            let event = match &write {
                Ok(()) => "QUARANTINE_REPORTED",
                Err(status) => {
                    if let Some(map) = details.as_object_mut() {
                        map.insert(
                            "error".to_string(),
                            serde_json::Value::String(status.message().to_string()),
                        );
                    }
                    "QUARANTINE_REPORTED_FAILED"
                }
            };
            self.audit.emit(AuditRecord::now(
                event,
                &reporter,
                self.node_id,
                dek_version,
                details,
            ));
        }
        write?;
        Ok(Response::new(()))
    }
}

impl StorageServiceImpl {
    /// Emits a `QUARANTINE_REPORT_REJECTED` audit record for a report that
    /// was refused before reaching Raft (rate limit or validation).
    fn audit_rejected_report(
        &self,
        reporter: &str,
        node_id: u64,
        partition: &str,
        status: &Status,
    ) {
        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit.emit(AuditRecord::now(
            "QUARANTINE_REPORT_REJECTED",
            reporter,
            self.node_id,
            dek_version,
            serde_json::json!({
                "claimed_node_id": node_id,
                "partition": partition,
                "reason": status.message(),
                "code": format!("{:?}", status.code()),
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_payload_with_admin_mutation_rejected() {
        use crate::store_command::{MutationInner, StoreCommand};
        let payload = StoreCommand::Transaction(vec![MutationInner::ClearQuarantine {
            partition: "data".into(),
        }])
        .pack()
        .unwrap();
        let err = decode_data_command(&payload).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn command_payload_with_remove_decodes_ok() {
        use crate::store_command::{MutationInner, StoreCommand};
        let payload = StoreCommand::Transaction(vec![MutationInner::Remove {
            key: b"k".to_vec(),
            keyspace: "data".into(),
            expected_revision: None,
        }])
        .pack()
        .unwrap();
        assert!(decode_data_command(&payload).is_ok());
    }

    #[test]
    fn quarantine_report_unknown_node_rejected() {
        let members: std::collections::BTreeSet<u64> = [1, 2].into();
        let e = validate_quarantine_report(9, "data", &members).unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn quarantine_report_bad_partition_rejected() {
        let members: std::collections::BTreeSet<u64> = [1].into();
        assert_eq!(
            validate_quarantine_report(1, "", &members)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let long = "x".repeat(129);
        assert_eq!(
            validate_quarantine_report(1, &long, &members)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn leader_redirect_is_not_audited_as_failure() {
        assert!(is_leader_redirect(&Err(forward_to_leader_status(
            1,
            "https://l:1"
        ))));
        assert!(is_leader_redirect(&Err(Status::unavailable(
            "not the leader; leader unknown"
        ))));
        assert!(!is_leader_redirect(&Ok(())));
        assert!(!is_leader_redirect(&Err(Status::internal(
            "Raft write failed"
        ))));
    }

    #[test]
    fn quarantine_report_ok() {
        let members: std::collections::BTreeSet<u64> = [1].into();
        assert!(validate_quarantine_report(1, "data", &members).is_ok());
        let max = "x".repeat(128);
        assert!(validate_quarantine_report(1, &max, &members).is_ok());
    }

    #[test]
    fn forward_to_leader_status_carries_leader_hint() {
        let s = forward_to_leader_status(7, "https://leader:8300");
        assert_eq!(s.code(), tonic::Code::Unavailable);
        assert_eq!(
            s.metadata()
                .get(crate::app::LEADER_ENDPOINT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("https://leader:8300")
        );
        assert_eq!(
            s.metadata()
                .get(crate::app::LEADER_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
    }

    #[test]
    fn command_payload_garbage_is_invalid_argument() {
        let err = decode_data_command(&[0xff, 0x00]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
