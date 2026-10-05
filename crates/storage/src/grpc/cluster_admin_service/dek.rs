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

//! DEK rotation and quarantine administration handlers.

use super::*;

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_clear_quarantine(
        &self,
        request: Request<pb::raft::ClearQuarantineRequest>,
    ) -> Result<Response<()>, Status> {
        let actor = require_operator(&request, &self.authz)?;
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

        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")));
        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit_outcome(
            "QUARANTINE_CLEARED",
            &actor,
            dek_version,
            serde_json::json!({ "partition": partition }),
            &write,
        );
        write?;

        Ok(Response::new(()))
    }

    pub(super) async fn handle_rotate_dek(
        &self,
        request: Request<pb::raft::RotateDekRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
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

            let write = self
                .raft_node
                .client_write(payload)
                .await
                .map_err(|e| Status::internal(format!("Raft write failed: {e}")));
            self.audit_outcome(
                "DEK_ROTATION_EMERGENCY_STAGED",
                &actor,
                current_version,
                serde_json::json!({
                    "rotation_id": rotation_id,
                    "new_version": new_version,
                    "expires_at": expires_at,
                }),
                &write,
            );
            write?;

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

        // Non-emergency: commit InstallDek directly (old DEK is retired, not
        // revoked).
        let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek,
            dek_version: new_version,
            is_emergency: false,
        }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;

        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")));
        self.audit_outcome(
            "DEK_ROTATION",
            &actor,
            new_version,
            serde_json::json!({ "previous_version": current_version }),
            &write,
        );
        write?;

        tracing::info!(new_version, "DEK rotation committed to Raft log");
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    pub(super) async fn handle_confirm_rotate_dek(
        &self,
        request: Request<pb::raft::ConfirmRotateDekRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
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

        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")));
        self.audit_outcome(
            "DEK_ROTATION_EMERGENCY_CONFIRMED",
            &actor,
            pending_version,
            serde_json::json!({ "rotation_id": req.rotation_id }),
            &write,
        );
        write?;

        tracing::warn!(
            rotation_id = req.rotation_id,
            new_version = pending_version,
            confirmer = actor,
            "SECURITY: emergency DEK rotation confirmed via dual-control"
        );
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    pub(super) async fn handle_rotate_dek_local_emergency(
        &self,
        request: Request<pb::raft::RotateDekLocalEmergencyRequest>,
    ) -> Result<Response<pb::raft::RotateDekLocalEmergencyResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
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

    pub(super) async fn handle_list_dek_local_emergency_candidates(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::ListDekLocalEmergencyCandidatesResponse>, Status> {
        require_operator(&request, &self.authz)?;

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

    pub(super) async fn handle_reconcile_dek_local_emergency(
        &self,
        request: Request<pb::raft::ReconcileDekLocalEmergencyRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
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

        let write = self
            .raft_node
            .client_write(install_payload)
            .await
            .map_err(|e| Status::internal(format!("Raft write failed: {e}")));
        self.audit_outcome(
            "DEK_ROTATION_LOCAL_EMERGENCY_RECONCILED",
            &actor,
            payload.dek_version,
            serde_json::json!({ "rotation_id": req.rotation_id }),
            &write,
        );
        write?;

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

    pub(super) async fn handle_gossip_local_emergency_candidate(
        &self,
        request: Request<pb::raft::GossipLocalEmergencyCandidateRequest>,
    ) -> Result<Response<pb::raft::GossipLocalEmergencyCandidateResponse>, Status> {
        require_peer(&request, &self.authz, &[PeerRole::Node])?;
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
}
