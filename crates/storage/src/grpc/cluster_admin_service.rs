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
use std::collections::BTreeMap;

use openraft::async_runtime::WatchReceiver;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::trace;

use crate::pb;
use crate::protobuf::raft::cluster_admin_service_server::ClusterAdminService;
use crate::types::*;

/// Raft cluster administrative operations.
///
/// # Responsibilities
/// - Manages the Raft cluster
///
/// # Protocol Safety
/// This service implements the client-facing API and should validate all inputs
/// before processing them through the Raft consensus protocol.
pub struct ClusterAdminServiceImpl {
    /// The Raft node instance for consensus operations
    raft_node: Raft,
}

impl ClusterAdminServiceImpl {
    /// Creates a new instance of the API service
    ///
    /// # Arguments
    /// * `raft_node` - The Raft node instance this service will use
    pub fn new(raft_node: Raft) -> Self {
        ClusterAdminServiceImpl { raft_node }
    }
}

#[tonic::async_trait]
impl ClusterAdminService for ClusterAdminServiceImpl {
    /// Initializes a new Raft cluster with the specified nodes
    ///
    /// # Arguments
    /// * `request` - Contains the initial set of nodes for the cluster
    ///
    /// # Returns
    /// * Success response with initialization details
    /// * Error if initialization fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn init(&self, request: Request<pb::raft::InitRequest>) -> Result<Response<()>, Status> {
        trace!("Initializing Raft cluster");
        let req = request.into_inner();

        // Convert nodes into required format
        let nodes_map: BTreeMap<u64, pb::raft::Node> = req
            .nodes
            .into_iter()
            .map(|node| (node.node_id, node))
            .collect();

        // Initialize the cluster
        let result = self
            .raft_node
            .initialize(nodes_map)
            .await
            .map_err(|e| Status::internal(format!("Failed to initialize cluster: {}", e)))?;

        trace!("Cluster initialization successful");
        Ok(Response::new(result))
    }

    /// Adds a learner node to the Raft cluster
    ///
    /// # Arguments
    /// * `request` - Contains the node information and blocking preference
    ///
    /// # Returns
    /// * Success response with learner addition details
    /// * Error if the operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn add_learner(
        &self,
        request: Request<pb::raft::AddLearnerRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let req = request.into_inner();

        let node = req
            .node
            .ok_or_else(|| Status::internal("Node information is required"))?;

        trace!("Adding learner node {}", node.node_id);

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

    /// Changes the membership of the Raft cluster
    ///
    /// # Arguments
    /// * `request` - Contains the new member set and retention policy
    ///
    /// # Returns
    /// * Success response with membership change details
    /// * Error if the operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn change_membership(
        &self,
        request: Request<pb::raft::ChangeMembershipRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
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

    /// Retrieves metrics about the Raft node
    #[tracing::instrument(level = "trace", skip(self))]
    async fn metrics(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::raft::MetricsResponse>, Status> {
        trace!("Collecting metrics");
        let metrics = self.raft_node.metrics().borrow_watched().clone();
        let resp = pb::raft::MetricsResponse {
            membership: Some(metrics.membership_config.membership().clone().into()),
            other_metrics: metrics.to_string(),
        };
        Ok(Response::new(resp))
    }
}
