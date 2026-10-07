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

//! `StorageStatus`: the responding node's Raft role and encryption state.

use openstack_keystone_storage_crypto::nonce::ROTATION_THRESHOLD;

use super::*;

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_storage_status(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::StorageStatusResponse>, Status> {
        require_operator(&request, &self.authz)?;

        let metrics = self.raft_node.metrics().borrow_watched().clone();
        let enc = self
            .sm
            .encryption_status()
            .map_err(|e| Status::internal(format!("cannot read storage status: {e}")))?;

        let mut pending_rotations: Vec<pb::raft::PendingDekRotation> = self
            .pending_rotations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|p| pb::raft::PendingDekRotation {
                rotation_id: p.rotation_id.clone(),
                dek_version: p.dek_version,
                expires_at: p.expires_at,
                initiator: p.initiator.clone(),
            })
            .collect();
        pending_rotations.sort_by_key(|p| p.expires_at);

        Ok(Response::new(pb::raft::StorageStatusResponse {
            node_id: self.node_id,
            state: format!("{:?}", metrics.state),
            current_leader: metrics.current_leader,
            current_term: metrics.current_term,
            last_log_index: metrics.last_log_index,
            last_applied_index: metrics.last_applied.as_ref().map(|l| l.index()),
            dek_version: enc.dek_version,
            retired_dek_versions: enc.retired_dek_versions,
            revoked_dek_versions: enc.revoked_dek_versions,
            pending_rotations,
            quarantined_partitions: enc.quarantined_partitions,
            quarantine_records: enc
                .quarantine_records
                .into_iter()
                .map(|(partition, node_id)| pb::raft::QuarantineRecord { partition, node_id })
                .collect(),
            nonce_counter: enc.nonce_counter,
            nonce_threshold: u64::from(ROTATION_THRESHOLD),
        }))
    }
}
