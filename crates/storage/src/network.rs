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
use std::future::Future;
use std::time::Duration;

use eyre::WrapErr;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use futures::channel::mpsc;
use openraft::base::{BoxFuture, BoxStream};
use openraft::error::{NetworkError, ReplicationClosed, Unreachable};
use openraft::network::{
    Backoff, NetBackoff, NetSnapshot, NetStreamAppend, NetTransferLeader, NetVote, RPCOption,
};
use openraft::raft::{StreamAppendError, StreamAppendResult, TransferLeaderRequest};
use openraft::{AnyError, OptionalSend, RaftNetworkFactory};
use openstack_keystone_config::DistributedStorageConfiguration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::protobuf as pb;
use crate::protobuf::raft::VoteRequest as PbVoteRequest;
use crate::protobuf::raft::VoteResponse as PbVoteResponse;
use crate::protobuf::raft::raft_service_client::RaftServiceClient;
use crate::types::NodeId;
use crate::types::TypeConfig;
use crate::types::*;

/// Network implementation for gRPC-based Raft communication.
/// Provides the networking layer for Raft nodes to communicate with each other.
pub struct Network {
    tls_ca_cert: Option<Certificate>,
    tls_client_identity: Option<Identity>,
}

impl Network {
    pub fn new(config: &DistributedStorageConfiguration) -> Result<Self, StoreError> {
        if !config.disable_tls {
            let tls_config = config
                .tls_configuration
                .as_ref()
                .ok_or(StoreError::TlsConfigMissing)?;
            let tls_client_identity = Identity::from_pem(
                std::fs::read_to_string(&tls_config.tls_cert_file)
                    .wrap_err("reading server cert file")?,
                std::fs::read_to_string(&tls_config.tls_key_file)
                    .wrap_err("reading server cert key file")?,
            );
            let tls_ca_cert = if let Some(cert_ca) = &tls_config.tls_client_ca_file {
                Some(Certificate::from_pem(std::fs::read_to_string(cert_ca)?))
            } else {
                None
            };

            Ok(Self {
                tls_ca_cert,
                tls_client_identity: Some(tls_client_identity),
            })
        } else {
            Ok(Self {
                tls_ca_cert: None,
                tls_client_identity: None,
            })
        }
    }

    fn get_server_tls_config(&self) -> Option<ClientTlsConfig> {
        if let Some(identity) = &self.tls_client_identity {
            let mut config = ClientTlsConfig::new().identity(identity.clone());
            if let Some(ca) = &self.tls_ca_cert {
                config = config.ca_certificate(ca.clone());
            }
            return Some(config);
        }
        None
    }
}

/// Implementation of the RaftNetworkFactory trait for creating new network
/// connections. This factory creates gRPC client connections to other Raft
/// nodes.
impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = NetworkConnection;

    #[tracing::instrument(level = "debug", skip_all)]
    async fn new_client(&mut self, _: NodeId, node: &Node) -> Self::Network {
        NetworkConnection::new(node.clone(), self.get_server_tls_config())
    }
}

/// Represents an active network connection to a remote Raft node.
/// Handles serialization and deserialization of Raft messages over gRPC.
pub struct NetworkConnection {
    target_node: pb::raft::Node,
    tls_config: Option<ClientTlsConfig>,
}

impl NetworkConnection {
    /// Creates a new NetworkConnection with the provided gRPC client.
    pub fn new(target_node: Node, tls_config: Option<ClientTlsConfig>) -> Self {
        NetworkConnection {
            target_node,
            tls_config,
        }
    }

    /// Creates a gRPC client to the target node.
    async fn make_client(&self) -> Result<RaftServiceClient<Channel>, RPCError> {
        let server_addr = &self.target_node.rpc_addr;

        let ep = if let Some(tls_config) = &self.tls_config {
            Channel::builder(
                format!("https://{}", server_addr)
                    .parse()
                    .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
            )
            .tls_config(tls_config.clone())
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?
        } else {
            Channel::builder(
                format!("http://{}", server_addr)
                    .parse()
                    .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
            )
        };

        let channel = ep
            .connect()
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))?;
        Ok(RaftServiceClient::new(channel))
    }

    /// Convert pb::AppendEntriesResponse to StreamAppendResult.
    ///
    /// For `StreamAppend`, conflict is encoded as `conflict = true` plus a
    /// required `last_log_id` carrying the conflict log id.
    fn pb_to_stream_result(
        resp: pb::raft::AppendEntriesResponse,
    ) -> Result<StreamAppendResult<TypeConfig>, RPCError> {
        if let Some(higher_vote) = resp.rejected_by {
            return Ok(Err(StreamAppendError::HigherVote(higher_vote)));
        }

        if resp.conflict {
            let conflict_log_id = resp.last_log_id.ok_or_else(|| {
                RPCError::Network(NetworkError::<TypeConfig>::new(&AnyError::error(
                    "Missing `last_log_id` in conflict stream-append response",
                )))
            })?;
            return Ok(Err(StreamAppendError::Conflict(conflict_log_id.into())));
        }

        Ok(Ok(resp.last_log_id.map(Into::into)))
    }

    /// Sends snapshot data in chunks through the provided channel.
    async fn send_snapshot_chunks(
        tx: &mut mpsc::Sender<pb::raft::SnapshotRequest>,
        snapshot_data: &[u8],
    ) -> Result<(), NetworkError<TypeConfig>> {
        let chunk_size = 1024 * 1024;
        for chunk in snapshot_data.chunks(chunk_size) {
            let request = pb::raft::SnapshotRequest {
                payload: Some(pb::raft::snapshot_request::Payload::Chunk(chunk.to_vec())),
            };
            tx.send(request)
                .await
                .map_err(|e| NetworkError::<TypeConfig>::new(&e))?;
        }
        Ok(())
    }
}

// =============================================================================
// Sub-trait implementations for NetworkConnection
// =============================================================================
//
// Instead of implementing RaftNetworkV2 as a monolithic trait, this example
// demonstrates implementing individual sub-traits directly. This approach:
// - Shows exactly which network capabilities are provided
// - Each impl is focused on a single concern
// - gRPC's native bidirectional streaming maps naturally to NetStreamAppend

impl NetStreamAppend<TypeConfig> for NetworkConnection {
    fn stream_append<'s, S>(
        &'s mut self,
        input: S,
        _option: RPCOption,
    ) -> BoxFuture<
        's,
        Result<BoxStream<'s, Result<StreamAppendResult<TypeConfig>, RPCError>>, RPCError>,
    >
    where
        S: Stream<Item = AppendEntriesRequest> + OptionalSend + Unpin + 'static,
    {
        let fu = async move {
            let mut client = self.make_client().await?;

            let response = client
                .stream_append(input.map(pb::raft::AppendEntriesRequest::from))
                .await
                .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))?;

            let output = response.into_inner().map(|result| {
                let resp =
                    result.map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))?;
                Self::pb_to_stream_result(resp)
            });

            Ok(Box::pin(output) as BoxStream<'s, _>)
        };

        Box::pin(fu)
    }
}

impl NetVote<TypeConfig> for NetworkConnection {
    async fn vote(
        &mut self,
        req: VoteRequest,
        _option: RPCOption,
    ) -> Result<VoteResponse, RPCError> {
        let mut client = self.make_client().await?;

        let proto_vote_req: PbVoteRequest = req.into();
        let response = client
            .vote(proto_vote_req)
            .await
            .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))?;

        let proto_vote_resp: PbVoteResponse = response.into_inner();
        #[allow(clippy::result_large_err)]
        proto_vote_resp
            .try_into()
            .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
    }
}

impl NetSnapshot<TypeConfig> for NetworkConnection {
    async fn full_snapshot(
        &mut self,
        vote: Vote,
        snapshot: Snapshot,
        _cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse, StreamingError> {
        let mut client = self.make_client().await?;

        let (mut tx, rx) = mpsc::channel(1024);
        let response = client
            .snapshot(rx)
            .await
            .map_err(|e| NetworkError::<TypeConfig>::new(&e))?;

        // 1. Send meta chunk
        let meta = &snapshot.meta;

        let request = pb::raft::SnapshotRequest {
            payload: Some(pb::raft::snapshot_request::Payload::Meta(
                pb::raft::SnapshotRequestMeta {
                    vote: Some(vote),
                    last_log_id: meta.last_log_id.map(|log_id| log_id.into()),
                    last_membership_log_id: meta
                        .last_membership
                        .log_id()
                        .map(|log_id| log_id.into()),
                    last_membership: Some(meta.last_membership.membership().clone().into()),
                    snapshot_id: meta.snapshot_id.to_string(),
                },
            )),
        };

        tx.send(request)
            .await
            .map_err(|e| NetworkError::<TypeConfig>::new(&e))?;

        // 2. Send data chunks
        Self::send_snapshot_chunks(&mut tx, &snapshot.snapshot).await?;

        // 3. Receive response
        let message = response.into_inner();

        Ok(SnapshotResponse {
            vote: message.vote.ok_or_else(|| {
                NetworkError::<TypeConfig>::new(&AnyError::error(
                    "Missing `vote` in snapshot response",
                ))
            })?,
        })
    }
}

impl NetBackoff<TypeConfig> for NetworkConnection {
    fn backoff(&self) -> Backoff {
        Backoff::new(std::iter::repeat(Duration::from_millis(200)))
    }
}

impl NetTransferLeader<TypeConfig> for NetworkConnection {
    async fn transfer_leader(
        &mut self,
        _req: TransferLeaderRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<(), RPCError> {
        Err(RPCError::Unreachable(Unreachable::new(&AnyError::error(
            "transfer_leader not implemented",
        ))))
    }
}
