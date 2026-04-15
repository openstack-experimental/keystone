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

use tonic::{Request, Response, Status};

use crate::pb;
use crate::protobuf::api::Response as PbResponse;
use crate::protobuf::api::storage_service_server::StorageService;
use crate::types::*;

/// Internal service implementation for Raft protocol communications.
/// This service handles the core Raft consensus protocol operations between
/// cluster nodes.
///
/// # Responsibilities
/// - Vote requests/responses during leader election
/// - Log replication between nodes
/// - Snapshot installation for state synchronization
///
/// # Protocol Safety
/// This service implements critical consensus protocol operations and should
/// only be exposed to other trusted Raft cluster nodes, never to external
/// clients.
pub struct StorageServiceImpl {
    /// The local Raft node instance that this service operates on.
    pub(crate) raft_node: Raft,
}

impl StorageServiceImpl {
    /// Creates a new instance of the internal service.
    ///
    /// # Arguments
    /// * `raft_node` - The Raft node instance this service will operate on.
    pub fn new(raft_node: Raft) -> Self {
        Self { raft_node }
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    /// Saves a storage modification command.
    ///
    /// # Arguments
    /// * `request` - Contains the key and value to set
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is set
    /// * `Err(Status)` - Error status if the set operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn command(
        &self,
        request: Request<pb::api::CommandRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        let req = request.into_inner();

        let res = self
            .raft_node
            .client_write(req)
            //.set_value(req.key.clone(), req.value, req.keyspace)
            .await
            .map_err(|e| Status::internal(format!("Failed to write command to store: {}", e)))?;

        //debug!("Successfully set value for key: {}", req.key);
        Ok(Response::new(res.data))
    }
}
