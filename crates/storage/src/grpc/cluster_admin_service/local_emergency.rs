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

//! Node-local, quorum-bypass DEK rotation candidates (ADR 0028).

use super::*;

/// Stages a node-local, quorum-bypass DEK rotation candidate in
/// `local_store` (ADR 0028 §3, amending ADR 0016-v2 §6.2). Pure business
/// logic, deliberately independent of the Raft handle and gRPC types so it
/// can be unit-tested without standing up a cluster; the guardrail check
/// (whether the bypass is currently permitted at all) is the caller's
/// responsibility.
///
/// Returns the fresh candidate's `(rotation_id, dek_version)` on success.
pub(super) async fn stage_dek_local_emergency_candidate(
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
pub(super) async fn validate_dek_reconcile_candidate(
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
pub(super) async fn receive_gossiped_candidate(
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
