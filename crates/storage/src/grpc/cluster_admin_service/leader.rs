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

//! Leader targeting for the leader-only admin RPCs (issue #1305).
//!
//! Admin mutations are proposed under the *calling operator's* identity, so
//! they are not proxied node-to-node (the forwarding node would have to act
//! with its own `Node` identity, losing the operator attribution the audit
//! log and the rate limiters key on). Instead a non-leader answers with the
//! same `Unavailable` + leader-hint headers as the data plane
//! ([`forward_to_leader_status`]) and the client retries against the leader.

use openraft::ServerState;
use openraft::errors::ForwardToLeader;

use super::*;
use crate::grpc::storage_service::forward_to_leader_status;

/// Leader redirect for a known or unknown leader.
///
/// With both the leader id and its node record the status carries the
/// [`crate::app::LEADER_ENDPOINT_HEADER`]/[`crate::app::LEADER_ID_HEADER`]
/// hints; otherwise (election in progress) it is a bare `Unavailable`.
pub(super) fn leader_redirect(leader_id: Option<u64>, leader_node: Option<&Node>) -> Status {
    match (leader_id, leader_node) {
        (Some(id), Some(node)) => forward_to_leader_status(id, &node.rpc_addr),
        _ => Status::unavailable("not the leader; leader unknown"),
    }
}

/// Maps a failed Raft proposal to a gRPC status: `ForwardToLeader` becomes a
/// [`leader_redirect`], anything else `Internal` prefixed with `context`.
pub(super) fn raft_write_status(
    context: &str,
    err: RaftError<TypeConfig, ClientWriteError<TypeConfig>>,
) -> Status {
    match err {
        RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
            leader_id,
            leader_node,
        })) => leader_redirect(leader_id, leader_node.as_ref()),
        other => Status::internal(format!("{context}: {other}")),
    }
}

impl ClusterAdminServiceImpl {
    /// Fails with a [`leader_redirect`] unless this node is the current
    /// leader.
    ///
    /// Called before any side effect (rate-limit token, DEK generation,
    /// pending-rotation lookup) so a misdirected call costs nothing and the
    /// leader's own, authoritative state is what gets checked. The proposal
    /// itself still maps a lost race (leadership changing in between) to
    /// the same redirect via [`raft_write_status`].
    pub(super) fn ensure_leader(&self) -> Result<(), Status> {
        let metrics = self.raft_node.metrics().borrow_watched().clone();
        if metrics.state == ServerState::Leader && metrics.current_leader == Some(self.node_id) {
            return Ok(());
        }
        let leader_node = metrics
            .current_leader
            .and_then(|id| metrics.membership_config.membership().get_node(&id));
        Err(leader_redirect(metrics.current_leader, leader_node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{LEADER_ENDPOINT_HEADER, LEADER_ID_HEADER};

    #[test]
    fn redirect_with_known_leader_carries_hints() {
        let node = Node {
            node_id: 3,
            rpc_addr: "leader:8300".into(),
        };
        let status = leader_redirect(Some(3), Some(&node));
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(
            status
                .metadata()
                .get(LEADER_ENDPOINT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("leader:8300")
        );
        assert_eq!(
            status
                .metadata()
                .get(LEADER_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("3")
        );
    }

    #[test]
    fn redirect_with_unknown_leader_has_no_hints() {
        let status = leader_redirect(None, None);
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert!(status.metadata().get(LEADER_ENDPOINT_HEADER).is_none());
    }

    #[test]
    fn forward_to_leader_write_error_becomes_redirect() {
        let err = RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
            leader_id: Some(2),
            leader_node: Some(Node {
                node_id: 2,
                rpc_addr: "n2:8300".into(),
            }),
        }));
        let status = raft_write_status("Raft write failed", err);
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(
            status
                .metadata()
                .get(LEADER_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("2")
        );
    }
}
