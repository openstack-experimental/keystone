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

//! Leadership transfer (GitHub #1444).

use std::time::Duration;

use super::*;

/// How long the old leader waits for the target to win the election. The
/// target starts it right away, so this only needs to cover an election
/// timeout (at most 3 s); openraft's trigger is fire-and-forget, so a target
/// that cannot take over is only noticed by this timeout.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the new leader.
const TRANSFER_POLL: Duration = Duration::from_millis(50);

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_transfer_leader(
        &self,
        request: Request<pb::raft::TransferLeaderAdminRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        let target = request.into_inner().node_id;
        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;

        let result = self.transfer_leader_to(target).await;
        self.audit_outcome(
            "LEADERSHIP_TRANSFERRED",
            &actor,
            dek_version,
            serde_json::json!({"from": self.node_id, "to": target}),
            &result,
        );
        result.map(|()| Response::new(pb::raft::AdminResponse::default()))
    }

    async fn transfer_leader_to(&self, target: u64) -> Result<(), Status> {
        if target == self.node_id {
            return Err(Status::failed_precondition(format!(
                "node {target} is already the leader"
            )));
        }
        let is_voter = self
            .raft_node
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .voter_ids()
            .any(|id| id == target);
        if !is_voter {
            return Err(Status::failed_precondition(format!(
                "node {target} is not a voter and cannot take over leadership"
            )));
        }
        self.raft_node
            .trigger()
            .transfer_leader(target)
            .await
            .map_err(|e| Status::internal(format!("transfer leader failed: {e}")))?;

        let deadline = tokio::time::Instant::now() + TRANSFER_TIMEOUT;
        loop {
            let leader = self.raft_node.metrics().borrow_watched().current_leader;
            if leader == Some(target) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(format!(
                    "node {target} did not become the leader in {}s (it may be \
                     lagging or unreachable)",
                    TRANSFER_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(TRANSFER_POLL).await;
        }
    }
}
