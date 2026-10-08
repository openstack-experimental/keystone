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

//! Adopting the cluster DEK before joining (GitHub #1445).

use super::*;
use crate::app::adopt_cluster_dek;
use crate::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_adopt_cluster_dek(
        &self,
        request: Request<pb::raft::AdoptClusterDekRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        // Node role only: `join` presents the storage node's own SVID, and an
        // operator identity has no business steering which server a node
        // pulls its key material from. The server is still dialled with this
        // node's mTLS client, so it must be a trusted cluster peer.
        let actor = require_peer(&request, &self.authz, &[PeerRole::Node])?;
        let leader_addr = request.into_inner().leader_addr;
        let leader_addr = normalize_rpc_addr(&leader_addr);
        let tls_client = self
            .tls_client
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this node cannot reach its peers"))?;

        // A node that already is part of a cluster holds the cluster's DEK;
        // swapping it again could only break it. Joining stays idempotent.
        let initialized = self
            .raft_node
            .is_initialized()
            .await
            .map_err(|e| Status::internal(format!("cannot determine Raft state: {e}")))?;
        if initialized {
            tracing::info!(
                actor,
                "node is already initialized; not adopting the cluster DEK"
            );
            return Ok(Response::new(pb::raft::AdminResponse::default()));
        }

        let channel = tls_client
            .connect(leader_addr)
            .await
            .map_err(|e| Status::unavailable(format!("cannot reach {leader_addr}: {e}")))?;
        let mut client = ClusterAdminServiceClient::new(channel);
        let result = adopt_cluster_dek(&mut client, &self.sm)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()));
        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit_outcome(
            "CLUSTER_DEK_ADOPTED",
            &actor,
            dek_version,
            serde_json::json!({"leader_addr": leader_addr}),
            &result,
        );
        result.map(|()| Response::new(pb::raft::AdminResponse::default()))
    }
}
