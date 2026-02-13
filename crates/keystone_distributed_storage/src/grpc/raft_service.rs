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
use std::pin::Pin;

use futures::Stream;
use futures::StreamExt;
use openraft::Snapshot;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tracing::trace;

use crate::protobuf as pb;
use crate::protobuf::raft::VoteRequest;
use crate::protobuf::raft::VoteResponse;
use crate::protobuf::raft::raft_service_server::RaftService;
use crate::types::*;

/// Internal gRPC service implementation for Raft protocol communications.
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
pub struct RaftServiceImpl {
    /// The local Raft node instance that this service operates on
    raft_node: Raft,
}

impl RaftServiceImpl {
    /// Creates a new instance of the internal service
    ///
    /// # Arguments
    /// * `raft_node` - The Raft node instance this service will operate on
    pub fn new(raft_node: Raft) -> Self {
        RaftServiceImpl { raft_node }
    }
}

#[tonic::async_trait]
impl RaftService for RaftServiceImpl {
    /// Handles vote requests during leader election.
    ///
    /// # Arguments
    /// * `request` - The vote request containing candidate information
    ///
    /// # Returns
    /// * `Ok(Response)` - Vote response indicating whether the vote was granted
    /// * `Err(Status)` - Error status if the vote operation fails
    ///
    /// # Protocol Details
    /// This implements the RequestVote RPC from the Raft protocol.
    /// Nodes vote for candidates based on log completeness and term numbers.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn vote(&self, request: Request<VoteRequest>) -> Result<Response<VoteResponse>, Status> {
        let vote_resp = self
            .raft_node
            .vote(
                request
                    .into_inner()
                    .try_into()
                    .map_err(|e| Status::internal(format!("Vote operation failed: {}", e)))?,
            )
            .await
            .map_err(|e| Status::internal(format!("Vote operation failed: {}", e)))?;

        trace!("Vote request processed successfully");
        Ok(Response::new(vote_resp.into()))
    }

    /// Handles append entries requests for log replication.
    ///
    /// # Arguments
    /// * `request` - The append entries request containing log entries to
    ///   replicate
    ///
    /// # Returns
    /// * `Ok(Response)` - Response indicating success/failure of the append
    ///   operation
    /// * `Err(Status)` - Error status if the append operation fails
    ///
    /// # Protocol Details
    /// This implements the AppendEntries RPC from the Raft protocol.
    /// Used for both log replication and as heartbeat mechanism.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn append_entries(
        &self,
        request: Request<pb::raft::AppendEntriesRequest>,
    ) -> Result<Response<pb::raft::AppendEntriesResponse>, Status> {
        let append_resp =
            self.raft_node
                .append_entries(request.into_inner().try_into().map_err(|e| {
                    Status::internal(format!("Append entries operation failed: {}", e))
                })?)
                .await
                .map_err(|e| Status::internal(format!("Append entries operation failed: {}", e)))?;

        trace!("Append entries request processed successfully");
        Ok(Response::new(append_resp.into()))
    }

    /// Handles snapshot installation requests for state transfer using
    /// streaming.
    ///
    /// # Arguments
    /// * `request` - Stream of snapshot chunks with metadata
    ///
    /// # Returns
    /// * `Ok(Response)` - Response indicating success/failure of snapshot
    ///   installation
    /// * `Err(Status)` - Error status if the snapshot operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn snapshot(
        &self,
        request: Request<Streaming<pb::raft::SnapshotRequest>>,
    ) -> Result<Response<pb::raft::SnapshotResponse>, Status> {
        let mut stream = request.into_inner();

        // Get the first chunk which contains metadata
        let first_chunk = stream
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("Empty snapshot stream"))??;

        let vote;
        let snapshot_meta;
        {
            let meta = first_chunk
                .into_meta()
                .ok_or_else(|| Status::invalid_argument("First snapshot chunk must be metadata"))?;

            trace!("Received snapshot metadata chunk: {:?}", meta);

            vote = meta
                .vote
                .ok_or_else(|| Status::invalid_argument("Missing `Vote`"))?;

            snapshot_meta = SnapshotMeta {
                last_log_id: meta.last_log_id.map(|log_id| log_id.into()),
                last_membership: StoredMembership::new(
                    meta.last_membership_log_id.map(|x| x.into()),
                    meta.last_membership
                        .ok_or_else(|| Status::invalid_argument("Membership information missing"))?
                        .try_into()
                        .map_err(|e| {
                            Status::invalid_argument(format!("invalid membership: {:?}", e))
                        })?,
                ),
                snapshot_id: meta.snapshot_id,
            };
        }

        // Collect snapshot data
        let mut snapshot_data_bytes = Vec::new();

        while let Some(chunk) = stream.next().await {
            let data = chunk?
                .into_data_chunk()
                .ok_or_else(|| Status::invalid_argument("Snapshot chunk must be data"))?;
            snapshot_data_bytes.extend_from_slice(&data);
        }

        let snapshot = Snapshot {
            meta: snapshot_meta,
            snapshot: snapshot_data_bytes,
        };

        // Install the full snapshot
        let snapshot_resp = self
            .raft_node
            .install_full_snapshot(vote, snapshot)
            .await
            .map_err(|e| Status::internal(format!("Snapshot installation failed: {}", e)))?;

        trace!("Streaming snapshot installation request processed successfully");
        Ok(Response::new(pb::raft::SnapshotResponse {
            vote: Some(snapshot_resp.vote),
        }))
    }

    type StreamAppendStream =
        Pin<Box<dyn Stream<Item = Result<pb::raft::AppendEntriesResponse, Status>> + Send>>;

    /// Handles streaming append entries requests for pipeline replication.
    ///
    /// This enables efficient pipelining of log replication where multiple
    /// AppendEntries requests can be in-flight simultaneously.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn stream_append(
        &self,
        request: Request<Streaming<pb::raft::AppendEntriesRequest>>,
    ) -> Result<Response<Self::StreamAppendStream>, Status> {
        let input = request.into_inner();

        // Convert pb stream to openraft AppendEntriesRequest stream
        let input_stream = input.filter_map(|r| async move {
            r.ok().map(TryInto::try_into).transpose().unwrap_or(None)
        });

        // Call Raft::stream_append
        let output = self.raft_node.stream_append(input_stream);

        // Convert StreamAppendResult to pb::AppendEntriesResponse
        #[allow(clippy::result_large_err)]
        let output_stream = output.map(|result| Ok(result.into()));

        Ok(Response::new(Box::pin(output_stream)))
    }
}
