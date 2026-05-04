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
use std::sync::Arc;
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
use openstack_keystone_config::TlsConfiguration;
use tokio::sync::watch;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::error;

use crate::StoreError;
use crate::protobuf as pb;
use crate::protobuf::raft::VoteRequest as PbVoteRequest;
use crate::protobuf::raft::VoteResponse as PbVoteResponse;
use crate::protobuf::raft::raft_service_client::RaftServiceClient;
use crate::types::*;

/// Network implementation for gRPC-based Raft communication.
/// Provides the networking layer for Raft nodes to communicate with each other.
#[derive(Clone)]
pub struct NetworkManager {
    /// Tls client config watcher.
    tls_config_watcher: watch::Receiver<ClientTlsConfig>,
}

impl NetworkManager {
    /// Create a new `NetworkManager`.
    ///
    /// # Parameters
    /// - `tls_config_watcher`: Tls client config watcher.
    ///
    /// # Returns
    /// A `Result` containing the `NetworkManager`, or a `StoreError`.
    pub fn new(tls_config_watcher: watch::Receiver<ClientTlsConfig>) -> Result<Self, StoreError> {
        Ok(Self { tls_config_watcher })
    }
}

/// Implementation of the RaftNetworkFactory trait for creating new network
/// connections. This factory creates gRPC client connections to other Raft
/// nodes.
impl RaftNetworkFactory<TypeConfig> for Arc<NetworkManager> {
    type Network = NetworkConnection;

    #[tracing::instrument(level = "debug", skip_all)]
    async fn new_client(&mut self, _: NodeId, node: &Node) -> Self::Network {
        NetworkConnection::new(node.clone(), self.tls_config_watcher.clone())
    }
}

/// Represents an active network connection to a remote Raft node.
/// Handles serialization and deserialization of Raft messages over gRPC.
pub struct NetworkConnection {
    /// Target node.
    target_node: pb::raft::Node,
    /// Watcher of the ClientTlsConfig.
    tls_config_watcher: watch::Receiver<ClientTlsConfig>,
}

impl NetworkConnection {
    /// Creates a new `NetworkConnection` with the provided gRPC client.
    ///
    /// # Parameters
    /// - `target_node`: Target node.
    /// - `tls_config_watcher`: Watcher of the ClientTlsConfig.
    ///
    /// # Returns
    /// A new `NetworkConnection` instance.
    pub fn new(target_node: Node, tls_config_watcher: watch::Receiver<ClientTlsConfig>) -> Self {
        NetworkConnection {
            target_node,
            tls_config_watcher,
        }
    }

    /// Creates a gRPC client to the target node.
    ///
    /// # Returns
    /// A `Result` containing the `RaftServiceClient`, or an `RPCError`.
    pub async fn make_client(&self) -> Result<RaftServiceClient<Channel>, RPCError> {
        let server_addr = &self.target_node.rpc_addr;

        let ep = Channel::builder(
            format!("https://{}", server_addr)
                .parse()
                .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
        )
        .tls_config(self.tls_config_watcher.borrow().clone())
        .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        let channel = ep
            .connect()
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))?;
        Ok(RaftServiceClient::new(channel))
    }

    /// Convert `pb::AppendEntriesResponse` to `StreamAppendResult`.
    ///
    /// For `StreamAppend`, conflict is encoded as `conflict = true` plus a
    /// required `last_log_id` carrying the conflict log id.
    ///
    /// # Parameters
    /// - `resp`: The append entries response.
    ///
    /// # Returns
    /// A `Result` containing the `StreamAppendResult`, or an `RPCError`.
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
    ///
    /// # Parameters
    /// - `tx`: The sender channel.
    /// - `snapshot_data`: The snapshot data.
    ///
    /// # Returns
    /// A `Result` indicating success, or a `NetworkError`.
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

/// Parse the [TlsConfiguration] into the [ClientTlsConfig].
///
/// # Parameters
/// - `tls_config`: The TLS configuration.
///
/// # Returns
/// A `Result` containing the `ClientTlsConfig`, or a `StoreError`.
pub fn load_tls_client_config(
    tls_config: &TlsConfiguration,
) -> Result<ClientTlsConfig, StoreError> {
    let identity = Identity::from_pem(
        std::fs::read_to_string(&tls_config.tls_cert_file).wrap_err("reading server cert file")?,
        std::fs::read_to_string(&tls_config.tls_key_file)
            .wrap_err("reading server cert key file")?,
    );
    let mut tls_client_config = ClientTlsConfig::new().identity(identity);
    if let Some(cert_ca) = &tls_config.tls_client_ca_file {
        tls_client_config = tls_client_config
            .ca_certificate(Certificate::from_pem(std::fs::read_to_string(cert_ca)?));
    };
    Ok(tls_client_config)
}

/// Initialize the [ClientTlsConfig] configuration watcher.
///
/// # Parameters
/// - `ks_config`: The distributed storage configuration.
///
/// # Returns
/// A `Result` containing the `watch::Receiver<ClientTlsConfig>`, or a
/// `StoreError`.
pub fn init_tls_watcher(
    ks_config: &DistributedStorageConfiguration,
) -> Result<watch::Receiver<ClientTlsConfig>, StoreError> {
    // 1. Initial Load: Try to load the certs once to start with a valid state
    let initial_config = load_tls_client_config(&ks_config.tls_configuration)?;

    // 2. Create the channel
    let (tx, rx) = watch::channel(initial_config);

    // 3. Spawn the File Watcher Task
    let config_clone = ks_config.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            interval.tick().await;

            // Reload from disk
            match load_tls_client_config(&config_clone.tls_configuration) {
                Ok(new_config) => {
                    // If the cert changed, broadcast to all receivers
                    let _ = tx.send(new_config);
                }
                Err(e) => {
                    error!("failed to reload TLS certificates: {:?}", e.to_string());
                }
            }
        }
    });

    // 4. Return the Receiver to be cloned into your RaftNetworkFactory
    Ok(rx)
}
