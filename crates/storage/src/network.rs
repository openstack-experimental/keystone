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
// Crypto inventory: STO-9, STO-10; see doc/src/contributor/crypto-inventory.md
//! # Raft network transport.
//!
//! Implements `openraft`'s `RaftNetworkFactory`: [`NetworkManager`] hands
//! out one [`NetworkConnection`] per peer, which carries Raft RPCs over
//! gRPC with mutual TLS using SPIFFE SVIDs. The module also holds the TLS
//! client/server configuration helpers, SVID lifetime checks, and the
//! [`CertExpiryWatchdog`] that forces certificate renewal before expiry.
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::Stream;
use futures::StreamExt;
use openraft::base::{BoxFuture, BoxStream};
use openraft::error::{NetworkError, ReplicationClosed, Timeout, Unreachable};
use openraft::network::RPCTypes;
use openraft::network::{
    Backoff, NetBackoff, NetSnapshot, NetStreamAppend, NetTransferLeader, NetVote, RPCOption,
};
use openraft::raft::{AppendError, AppendResult, TransferLeaderRequest};
use openraft::{AnyError, OptionalSend, RaftNetworkFactory};
use secrecy::ExposeSecret;
use spiffe::{X509Source, X509SourceBuilder};
use spiffe_rustls::{authorizer, mtls_client};
use tokio::sync::watch;
use tonic::Status;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, ServerTlsConfig};
use tracing::error;

use openstack_keystone_config::ConfigManager;

use crate::config::{DistributedStorageConfiguration, RaftTlsConfiguration};

use crate::StoreError;
use crate::grpc::authz::{PeerRole, resolve_identities};
use crate::protobuf as pb;
use crate::protobuf::raft::VoteRequest as PbVoteRequest;
use crate::protobuf::raft::VoteResponse as PbVoteResponse;
use crate::protobuf::raft::raft_service_client::RaftServiceClient;
use crate::spiffe_wait::SvidSelector;
use crate::types::*;

/// Strip a URI scheme (`https://`, `http://`, etc.) from `addr`, returning the
/// remaining authority + path portion (e.g. `keystone-rs-0:8300`).
///
/// Used to normalize addresses that arrive from config files (which often carry
/// an `https://` prefix) before passing them to tonic's channel builder, which
/// prepends its own scheme.
fn strip_scheme(addr: &str) -> &str {
    addr.split_once("://").map(|(_, rest)| rest).unwrap_or(addr)
}

/// TLS client mode for Raft peer connections.
///
/// * `Spiffe` — SPIFFE mTLS using a `rustls::ClientConfig` built from a live
///   X.509 SVID source.  Certificate verification is done by
///   `SpiffeServerCertVerifier` (URI SAN, not hostname).  SVID rotation is
///   handled internally by `spiffe-rustls`'s `MaterialWatcher`.
/// * `Static` — Static file-based mTLS.  The `ClientTlsConfig` is refreshed via
///   a tokio `watch` channel whenever the config file changes.
#[derive(Clone)]
pub enum RaftTlsClient {
    Spiffe(Arc<SpiffeClients>),
    Static(watch::Receiver<ClientTlsConfig>),
}

/// The SPIFFE client configurations of a node, one per SVID it presents
/// (ADR 0045 §11.1).
///
/// A connection is made on behalf of a [`PeerRole`] and presents the SVID
/// configured for that role. A node that configures no `identities` has one
/// fallback configuration that serves every role.
pub struct SpiffeClients {
    by_role: std::collections::HashMap<PeerRole, Arc<rustls::ClientConfig>>,
    fallback: Option<Arc<rustls::ClientConfig>>,
}

impl SpiffeClients {
    /// Configuration presenting the SVID used for `role`.
    fn for_role(&self, role: PeerRole) -> Result<Arc<rustls::ClientConfig>, StoreError> {
        self.by_role
            .get(&role)
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or_else(|| {
                StoreError::Other(eyre::eyre!(
                    "no SPIFFE identity is configured for role {role:?}"
                ))
            })
    }
}

impl RaftTlsClient {
    /// Build a gRPC [`Channel`] to `addr` using the configured TLS mode.
    ///
    /// In `Static` mode the channel is created lazily (no connection until the
    /// first RPC).  In `Spiffe` mode `connect_with_connector` establishes the
    /// connection eagerly so that TLS errors surface immediately.
    pub async fn connect(&self, addr: &str) -> Result<Channel, StoreError> {
        self.connect_as(addr, PeerRole::Node).await
    }

    /// Like [`Self::connect`], presenting the SVID configured for `role`.
    /// Static TLS has a single identity and ignores `role`.
    pub async fn connect_as(&self, addr: &str, role: PeerRole) -> Result<Channel, StoreError> {
        match self {
            Self::Static(rx) => {
                let tls_cfg = rx.borrow().clone();
                Ok(tonic::transport::Endpoint::from_shared(format!(
                    "https://{}",
                    strip_scheme(addr)
                ))?
                .tls_config(tls_cfg)?
                .connect_lazy())
            }
            Self::Spiffe(clients) => {
                let connector = SpiffeConnector {
                    tls: clients.for_role(role)?,
                };
                Channel::builder(format!("http://{}", strip_scheme(addr)).parse()?)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
                    .keep_alive_timeout(KEEPALIVE_TIMEOUT)
                    .keep_alive_while_idle(true)
                    .connect_with_connector(connector)
                    .await
                    .map_err(|e| StoreError::Other(eyre::eyre!("SPIFFE gRPC connect failed: {e}")))
            }
        }
    }
}

/// Tower `Service<Uri>` connector that establishes a SPIFFE mTLS connection.
///
/// Tonic's built-in TLS uses hostname verification, which fails for SPIFFE
/// certificates that carry URI SANs (`spiffe://trust-domain/path`) instead of
/// DNS SANs.  This connector bypasses tonic's TLS layer entirely: the Raft
/// node address is passed as an `http://` URI so tonic hands the raw TCP
/// stream directly to us, and we wrap it with `tokio-rustls` using the
/// SPIFFE-aware `rustls::ClientConfig` produced by
/// `spiffe_rustls::mtls_client`.
#[derive(Clone)]
struct SpiffeConnector {
    tls: Arc<rustls::ClientConfig>,
}

impl tower::Service<http::Uri> for SpiffeConnector {
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let tls = self.tls.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "URI missing host")
                })?
                .to_owned();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = tokio::time::timeout(
                CONNECT_TIMEOUT,
                tokio::net::TcpStream::connect(format!("{host}:{port}")),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??;
            // Small request/response RPCs stall ~40ms on Nagle + delayed ACK
            // without this.
            tcp.set_nodelay(true)?;
            let connector = tokio_rustls::TlsConnector::from(tls);
            // `SpiffeServerCertVerifier` validates the peer's SPIFFE URI SAN
            // and ignores the DNS server name, so any valid
            // constant name is fine here.
            let server_name = rustls::pki_types::ServerName::try_from(
                "keystone-raft-peer.internal",
            )
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("constant DNS name invalid: {e}"),
                )
            })?;
            let tls_stream = connector.connect(server_name, tcp).await?;
            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Network implementation for gRPC-based Raft communication.
/// Provides the networking layer for Raft nodes to communicate with each other.
#[derive(Clone)]
pub struct NetworkManager {
    channels: Arc<ChannelCache>,
}

impl NetworkManager {
    /// Create a new `NetworkManager`.
    pub fn new(tls_client: RaftTlsClient) -> Result<Self, StoreError> {
        Ok(Self {
            channels: Arc::new(ChannelCache::new(tls_client)),
        })
    }
}

/// Maximum lifetime of a cached channel.
///
/// A long-lived connection authenticates with the certificate it was
/// established with, so rotated or revoked certificates, and changed trust
/// bundles, only take effect on new handshakes. Rebuilding channels at least
/// this often bounds how long a stale session can survive in both TLS modes.
const CHANNEL_MAX_AGE: Duration = Duration::from_secs(300);

/// Number of channels (HTTP/2 connections) kept per peer.
///
/// h2 counts every locally reset stream on a connection and never decrements
/// the count. At 1024 it sends `GOAWAY(too_many_internal_resets)`, failing all
/// requests on that connection. Reads that time out or are dropped under load
/// reset streams, so one connection per peer reaches the cap well within
/// [`CHANNEL_MAX_AGE`]. Spreading requests over several connections multiplies
/// the headroom by this factor.
const CHANNELS_PER_PEER: usize = 4;

/// Time allowed to establish a TCP (and, in SPIFFE mode, TLS) connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP/2 PING interval on Raft channels, also while no request is in flight.
///
/// OpenRaft replicates over one long-lived `StreamAppend` stream per peer. If
/// the peer disappears without closing the connection (pod replaced under a
/// new IP, node power loss), nothing on the stream fails until the kernel
/// gives up retransmitting, which takes many minutes: the leader silently
/// stops replicating to that peer and never reconnects. Keepalive pings turn
/// that into a failed stream within [`KEEPALIVE_INTERVAL`] +
/// [`KEEPALIVE_TIMEOUT`], so OpenRaft re-establishes it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Time to wait for a PING acknowledgement before the connection is dropped.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Snapshot chunk size when OpenRaft does not request one.
const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;

/// Slowest link speed a snapshot transfer is expected to sustain. The
/// transfer deadline grows by one second per this many bytes, so a large
/// snapshot over a WAN link is not cut off by an RPC-sized timeout while a
/// stalled peer is still abandoned.
const SNAPSHOT_MIN_BYTES_PER_SEC: u64 = 1024 * 1024;

/// Per-peer cache of established gRPC channels.
///
/// OpenRaft asks the factory for a new client for every replication stream and
/// for every `ensure_linearizable` leadership confirmation. Building a
/// [`Channel`] per RPC means a fresh TCP + mTLS handshake each time, which
/// under a burst of concurrent reads piles up handshakes on the runtime,
/// delays `AppendEntries` replies past OpenRaft's 500ms heartbeat timeout and
/// makes the readers retry, creating yet more handshakes. A tonic `Channel`
/// is a cheaply cloneable handle that multiplexes requests over one HTTP/2
/// connection and reconnects on its own, so a few per peer address are enough
/// (see [`CHANNELS_PER_PEER`]).
///
/// Entries are dropped when the static TLS configuration changes (or its
/// source goes away) and after [`CHANNEL_MAX_AGE`].
pub(crate) struct ChannelCache {
    tls_client: Mutex<RaftTlsClient>,
    /// Keyed by peer address and pool slot.
    channels: Mutex<HashMap<String, (Channel, Instant)>>,
    /// Round-robin position, selects the pool slot of the next request.
    next_slot: AtomicUsize,
    max_age: Duration,
}

impl ChannelCache {
    pub(crate) fn new(tls_client: RaftTlsClient) -> Self {
        Self::with_max_age(tls_client, CHANNEL_MAX_AGE)
    }

    fn with_max_age(tls_client: RaftTlsClient, max_age: Duration) -> Self {
        Self {
            tls_client: Mutex::new(tls_client),
            channels: Mutex::new(HashMap::new()),
            next_slot: AtomicUsize::new(0),
            max_age,
        }
    }

    /// Drop cached channels that must not be reused and return the TLS mode to
    /// connect with.
    ///
    /// A changed static TLS config (certificate rotation) invalidates every
    /// channel since each was built with the previous one. A closed config
    /// watch is treated the same way: the config can no longer be refreshed,
    /// so no existing session is trusted to outlive its age limit.
    fn refresh(&self) -> RaftTlsClient {
        let mut tls = self.tls_client.lock().unwrap_or_else(|e| e.into_inner());
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        if let RaftTlsClient::Static(rx) = &mut *tls {
            match rx.has_changed() {
                Ok(true) => {
                    rx.mark_unchanged();
                    channels.clear();
                }
                Ok(false) => {}
                Err(_) => channels.clear(),
            }
        }
        channels.retain(|_, (_, created)| created.elapsed() < self.max_age);
        tls.clone()
    }

    /// Cache key of the next pool slot for `addr`.
    fn pool_key(&self, addr: &str, role: PeerRole) -> String {
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed) % CHANNELS_PER_PEER;
        format!("{addr}#{role:?}#{slot}")
    }

    /// Return a channel to `addr`, connecting if there is none yet.
    ///
    /// Requests are spread round-robin over [`CHANNELS_PER_PEER`] channels.
    pub(crate) async fn channel(&self, addr: &str) -> Result<Channel, RPCError> {
        self.channel_as(addr, PeerRole::Node).await
    }

    /// Like [`Self::channel`], presenting the SVID configured for `role`.
    /// Channels of different roles are never shared.
    pub(crate) async fn channel_as(&self, addr: &str, role: PeerRole) -> Result<Channel, RPCError> {
        let addr = strip_scheme(addr);
        let key = self.pool_key(addr, role);

        // No lock is held across an await.
        let tls_client = self.refresh();

        if let Some((channel, _)) = self
            .channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(channel.clone());
        }

        let channel = Self::connect(&tls_client, addr, role).await?;
        // Concurrent first users may each have connected; keep the first.
        Ok(self
            .channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert((channel, Instant::now()))
            .0
            .clone())
    }

    async fn connect(
        tls_client: &RaftTlsClient,
        addr: &str,
        role: PeerRole,
    ) -> Result<Channel, RPCError> {
        match tls_client {
            RaftTlsClient::Static(rx) => {
                // Clone the config out of the Ref before any await so the
                // non-Send `watch::Ref` guard is dropped before the future
                // needs to cross thread boundaries.
                let tls_cfg = rx.borrow().clone();
                Channel::builder(
                    format!("https://{addr}")
                        .parse()
                        .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
                )
                .tls_config(tls_cfg)
                .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?
                .connect_timeout(CONNECT_TIMEOUT)
                .tcp_keepalive(Some(KEEPALIVE_INTERVAL))
                .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
                .keep_alive_timeout(KEEPALIVE_TIMEOUT)
                .keep_alive_while_idle(true)
                .connect()
                .await
                .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))
            }

            RaftTlsClient::Spiffe(clients) => {
                let connector = SpiffeConnector {
                    tls: clients
                        .for_role(role)
                        .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))?,
                };
                // Use `http://` so tonic forwards the URI directly to our
                // connector without attempting its own hostname-based TLS.
                Channel::builder(
                    format!("http://{addr}")
                        .parse()
                        .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
                )
                .connect_with_connector(connector)
                .await
                .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))
            }
        }
    }
}

/// Implementation of the RaftNetworkFactory trait for creating new network
/// connections. This factory creates gRPC client connections to other Raft
/// nodes.
impl RaftNetworkFactory<TypeConfig> for Arc<NetworkManager> {
    type Network = NetworkConnection;

    #[tracing::instrument(level = "debug", skip_all)]
    async fn new_client(&mut self, target: NodeId, node: &Node) -> Self::Network {
        NetworkConnection::new(target, node.clone(), self.channels.clone())
    }
}

/// Represents an active network connection to a remote Raft node.
/// Handles serialization and deserialization of Raft messages over gRPC.
pub struct NetworkConnection {
    /// Target node id.
    target_id: NodeId,
    /// Target node.
    target_node: pb::raft::Node,
    /// Shared per-peer channel cache.
    channels: Arc<ChannelCache>,
}

impl NetworkConnection {
    /// Creates a gRPC client to the target node, reusing the cached channel.
    pub async fn make_client(&self) -> Result<RaftServiceClient<Channel>, RPCError> {
        let channel = self.channels.channel(&self.target_node.rpc_addr).await?;
        Ok(RaftServiceClient::new(channel))
    }

    /// Creates a new `NetworkConnection` for `target_node`.
    fn new(target_id: NodeId, target_node: Node, channels: Arc<ChannelCache>) -> Self {
        NetworkConnection {
            target_id,
            target_node,
            channels,
        }
    }

    /// Run `fut` under `limit`, mapping expiry to [`RPCError::Timeout`].
    ///
    /// OpenRaft passes an [`RPCOption`] to every RPC and expects the transport
    /// to honour it; without a deadline a hung peer holds the replication task
    /// until the kernel gives up on the TCP connection. OpenRaft's `Timeout`
    /// error carries both node ids but the factory does not know the local one,
    /// so `id` repeats the target (it is only used for logging).
    ///
    /// Callers bound the RPC on `RPCOption::soft_ttl`, as OpenRaft documents:
    /// it is shorter than `hard_ttl`, so the transport reports its own timeout
    /// before OpenRaft cancels the in-flight RPC.
    async fn with_deadline<T, F>(
        &self,
        action: RPCTypes,
        limit: Duration,
        fut: F,
    ) -> Result<T, RPCError>
    where
        F: Future<Output = Result<T, RPCError>>,
    {
        match tokio::time::timeout(limit, fut).await {
            Ok(res) => res,
            Err(_) => Err(RPCError::Timeout(Timeout {
                action,
                id: self.target_id,
                target: self.target_id,
                timeout: limit,
            })),
        }
    }

    /// Convert `pb::AppendEntriesResponse` to `StreamAppendResult`.
    ///
    /// For `StreamAppend`, conflict is encoded as `conflict = true` plus a
    /// required `last_log_id` carrying the conflict log id.
    fn pb_to_stream_result(
        resp: pb::raft::AppendEntriesResponse,
    ) -> Result<AppendResult<TypeConfig>, RPCError> {
        if let Some(higher_vote) = resp.rejected_by {
            return Ok(Err(AppendError::HigherVote(higher_vote)));
        }

        if resp.conflict {
            let conflict_log_id = resp.last_log_id.ok_or_else(|| {
                RPCError::Network(NetworkError::<TypeConfig>::new(&AnyError::error(
                    "Missing `last_log_id` in conflict stream-append response",
                )))
            })?;
            return Ok(Err(AppendError::Conflict {
                log_id: conflict_log_id.into(),
                hint: None,
            }));
        }

        Ok(Ok(resp.last_log_id.map(Into::into)))
    }
}

impl NetStreamAppend<TypeConfig> for NetworkConnection {
    fn stream_append<'s, S>(
        &'s mut self,
        input: S,
        option: RPCOption,
    ) -> BoxFuture<'s, Result<BoxStream<'s, Result<AppendResult<TypeConfig>, RPCError>>, RPCError>>
    where
        S: Stream<Item = AppendEntriesRequest> + OptionalSend + Unpin + 'static,
    {
        let fu = async move {
            // Only the stream setup is bounded: the stream itself is
            // long-lived and its liveness is covered by HTTP/2 keepalive.
            let response = self
                .with_deadline(RPCTypes::AppendEntries, option.soft_ttl(), async {
                    let mut client = self.make_client().await?;
                    client
                        .stream_append(input.map(pb::raft::AppendEntriesRequest::from))
                        .await
                        .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
                })
                .await?;

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
        option: RPCOption,
    ) -> Result<VoteResponse, RPCError> {
        let proto_vote_req: PbVoteRequest = req.into();
        let response = self
            .with_deadline(RPCTypes::Vote, option.soft_ttl(), async {
                let mut client = self.make_client().await?;
                client
                    .vote(proto_vote_req)
                    .await
                    .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
            })
            .await?;

        let proto_vote_resp: PbVoteResponse = response.into_inner();
        #[allow(clippy::result_large_err)]
        proto_vote_resp
            .try_into()
            .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
    }
}

impl NetSnapshot<TypeConfig> for NetworkConnection {
    type SnapshotData = Vec<u8>;

    async fn full_snapshot(
        &mut self,
        vote: Vote,
        snapshot: Snapshot,
        _cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse, StreamingError> {
        let mut client = self.make_client().await?;

        // 1. Meta chunk
        let meta = &snapshot.meta;
        let meta_request = pb::raft::SnapshotRequest {
            payload: Some(pb::raft::snapshot_request::Payload::Meta(
                pb::raft::SnapshotRequestMeta {
                    vote: Some(vote),
                    last_log_id: meta.last_log_id.map(|log_id| log_id.into()),
                    last_membership_log_id: meta
                        .last_membership
                        .log_id()
                        .map(|log_id| log_id.into()),
                    last_membership: Some(meta.last_membership.membership().clone().into()),
                    // openraft 0.10 dropped `snapshot_id` from `SnapshotMeta`
                    // (two snapshots at the same `last_log_id` are the same
                    // state regardless of transfer id); the receiver derives
                    // its own on-disk id from `last_log_id`, so this proto
                    // field is unused but kept for wire-format compatibility.
                    snapshot_id: String::new(),
                },
            )),
        };

        // 2. Data chunks. `Snapshot(stream SnapshotRequest) returns
        // (SnapshotResponse)` is client-streaming: the server only replies
        // once it has read the entire request stream (see
        // `RaftServiceImpl::snapshot`'s `while let Some(chunk) =
        // stream.next().await` loop), so the request stream must be
        // produced independently of awaiting the response. The snapshot
        // already lives in memory here; chunks are copied lazily as the
        // transport pulls them so the extra memory is one chunk, not a second
        // copy of the whole snapshot.
        let chunk_size = option
            .snapshot_chunk_size()
            .filter(|s| *s > 0)
            .unwrap_or(SNAPSHOT_CHUNK_SIZE);
        let data = snapshot.snapshot;
        let total = data.len();
        let chunks = (0..total.div_ceil(chunk_size)).map(move |i| {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(total);
            pb::raft::SnapshotRequest {
                payload: Some(pb::raft::snapshot_request::Payload::Chunk(
                    data.get(start..end).unwrap_or_default().to_vec(),
                )),
            }
        });
        let requests = futures::stream::once(futures::future::ready(meta_request))
            .chain(futures::stream::iter(chunks));

        // The whole transfer shares one deadline: OpenRaft's soft ttl plus the
        // time `total` bytes need at the slowest tolerated link speed.
        let limit =
            option.soft_ttl() + Duration::from_secs(total as u64 / SNAPSHOT_MIN_BYTES_PER_SEC);
        let response = tokio::time::timeout(limit, client.snapshot(requests))
            .await
            .map_err(|_| {
                StreamingError::Timeout(Timeout {
                    action: RPCTypes::InstallSnapshot,
                    id: self.target_id,
                    target: self.target_id,
                    timeout: limit,
                })
            })?
            .map_err(|e| NetworkError::<TypeConfig>::new(&e))?;

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
    fn backoff(&self) -> Option<Backoff> {
        Some(Backoff::new(std::iter::repeat(Duration::from_millis(200))))
    }
}

impl NetTransferLeader<TypeConfig> for NetworkConnection {
    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        openraft::raft::TransferLeaderResponse<TypeConfig>,
        openraft::error::RPCError<TypeConfig>,
    > {
        let response = self
            .with_deadline(RPCTypes::TransferLeader, option.soft_ttl(), async {
                let mut client = self.make_client().await?;
                client
                    .transfer_leader(pb::raft::TransferLeaderRequest::from(req))
                    .await
                    .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
            })
            .await?;
        response
            .into_inner()
            .try_into()
            .map_err(|e| RPCError::Network(NetworkError::<TypeConfig>::new(&e)))
    }
}

// ---------------------------------------------------------------------------
// TLS certificate expiry watchdog (manual-TLS fallback path)
// ---------------------------------------------------------------------------

/// TLS certificate expiry watchdog for the manual-TLS fallback path.
///
/// Spawns a background `tokio::task` that wakes every hour and checks the
/// remaining validity of the server TLS certificate.  Emits:
///
/// * `WARN` when fewer than 7 days remain.
/// * `ERROR` when fewer than 2 days remain.
/// * `CRITICAL` + optional shutdown when the certificate has expired.
pub struct CertExpiryWatchdog;

impl CertExpiryWatchdog {
    /// Spawn the watchdog task.
    ///
    /// `cert_pem` is the raw PEM bytes of the certificate to monitor.
    /// `shutdown_on_expiry` controls whether the process exits on expiry
    /// (production) or only logs (dev mode).
    pub fn spawn(cert_pem: Vec<u8>, shutdown_on_expiry: bool) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let check_interval = tokio::time::Duration::from_secs(3600);
            loop {
                check_cert_expiry(&cert_pem, shutdown_on_expiry);
                tokio::time::sleep(check_interval).await;
            }
        })
    }
}

fn check_cert_expiry(cert_pem: &[u8], shutdown_on_expiry: bool) {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;

    let (_, pem) = match parse_x509_pem(cert_pem) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "TLS cert expiry check: failed to parse PEM");
            return;
        }
    };
    let (_, cert) = match X509Certificate::from_der(&pem.contents) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "TLS cert expiry check: failed to parse DER");
            return;
        }
    };

    let not_after = cert.validity().not_after;
    let expiry_secs = not_after.timestamp();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let remaining_secs = expiry_secs - now_secs;

    const WARN_THRESHOLD: i64 = 7 * 24 * 3600;
    const ERROR_THRESHOLD: i64 = 2 * 24 * 3600;

    if remaining_secs <= 0 {
        tracing::error!(
            "CRITICAL: TLS certificate has expired! Renew immediately to avoid \
             cluster communication failure."
        );
        if shutdown_on_expiry {
            tracing::error!("Initiating shutdown due to expired TLS certificate.");
            std::process::exit(1);
        }
    } else if remaining_secs <= ERROR_THRESHOLD {
        tracing::error!(
            remaining_days = remaining_secs / 86400,
            "TLS certificate expires in less than 2 days — renew urgently"
        );
    } else if remaining_secs <= WARN_THRESHOLD {
        tracing::warn!(
            remaining_days = remaining_secs / 86400,
            "TLS certificate expires in less than 7 days — schedule renewal"
        );
    } else {
        tracing::debug!(
            remaining_days = remaining_secs / 86400,
            "TLS certificate expiry check passed"
        );
    }
}

/// Enforces the 30-day maximum leaf certificate validity window (ADR 0016-v2
/// §4.2).
///
/// Returns `Err` if the certificate's total validity window (`not_after −
/// not_before`) exceeds 30 days. Called at startup before the gRPC listener
/// accepts connections; the node refuses to start if the cert violates this
/// invariant.
pub fn check_cert_max_validity(cert_pem: &[u8]) -> Result<(), StoreError> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;

    let (_, pem) = parse_x509_pem(cert_pem)
        .map_err(|e| StoreError::Other(eyre::eyre!("TLS cert PEM parse failed: {e}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| StoreError::Other(eyre::eyre!("TLS cert DER parse failed: {e}")))?;

    let validity = cert.validity();
    let window_secs = validity
        .not_after
        .timestamp()
        .saturating_sub(validity.not_before.timestamp());

    const MAX_VALIDITY_SECS: i64 = 30 * 24 * 3600;

    if window_secs > MAX_VALIDITY_SECS {
        return Err(StoreError::Other(eyre::eyre!(
            "TLS leaf certificate validity ({} days) exceeds the 30-day maximum \
             enforced by ADR 0016-v2 §4.2; reissue with a shorter validity period",
            window_secs / 86400
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SVID TTL enforcement (ADR 0016-v2 §4.1 — force-renewal window)
// ---------------------------------------------------------------------------

/// Minimum remaining SVID validity before refusing an inbound SPIFFE SVID
/// (ADR 0016-v2 §4.1 — force-renewal window).
pub const FORCE_RENEWAL_SECS: i64 = 5 * 60;

/// Current Unix timestamp in seconds, saturating to 0 on a pre-epoch clock.
///
/// Shared by every `check_svid_ttl_der` call site so the
/// `SystemTime::now().duration_since(UNIX_EPOCH)...` boilerplate exists in
/// exactly one place.
pub fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Enforces the SVID force-renewal window on a raw DER certificate.
///
/// Returns `Err(PERMISSION_DENIED)` if the SVID has fewer than 5 minutes of
/// remaining validity. `now_secs` is the current Unix timestamp, injected for
/// testability — pass [`now_unix_secs`] at call sites.
pub fn check_svid_ttl_der(der: &[u8], now_secs: i64) -> Result<(), Status> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| Status::permission_denied("peer certificate is malformed"))?;

    let not_after = cert.validity().not_after.timestamp();
    let remaining = not_after.saturating_sub(now_secs);

    if remaining <= 0 {
        return Err(Status::permission_denied(
            "peer SVID has expired; refused per ADR 0016-v2 §4.1",
        ));
    }
    if remaining < FORCE_RENEWAL_SECS {
        return Err(Status::permission_denied(
            "peer SVID is in the force-renewal window; refused per ADR 0016-v2 §4.1",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Static mTLS config helpers (Tls variant of RaftTlsConfiguration)
// ---------------------------------------------------------------------------

/// Build the tonic [`ClientTlsConfig`] from the `[distributed_storage]`
/// section.
pub fn get_client_tls_config(
    ds: &DistributedStorageConfiguration,
) -> Result<ClientTlsConfig, StoreError> {
    if let RaftTlsConfiguration::Tls(tls) = &ds.tls_configuration {
        let cert_pem = tls
            .tls_cert_content
            .as_ref()
            .ok_or(StoreError::TlsConfigMissing)?
            .expose_secret();
        // Enforced here (not just once at process startup) so every load of
        // this shared config — including config-watcher hot-reloads in
        // `init_tls_watcher` and standalone callers such as `cli-manage` —
        // rejects an over-long-lived leaf cert (ADR 0016-v2 §4.2).
        check_cert_max_validity(cert_pem)?;
        let identity = Identity::from_pem(
            cert_pem,
            tls.tls_key_content
                .as_ref()
                .ok_or(StoreError::TlsConfigMissing)?
                .expose_secret(),
        );
        let mut tls_client_config = ClientTlsConfig::new().identity(identity);
        if let Some(cert_ca) = tls.tls_client_ca_content.as_ref() {
            tls_client_config =
                tls_client_config.ca_certificate(Certificate::from_pem(cert_ca.expose_secret()));
        };
        Ok(tls_client_config)
    } else {
        Err(StoreError::TlsConfigMissing)
    }
}

/// Build tonic [`ServerTlsConfig`] from the `[distributed_storage]` section.
pub fn get_server_tls_config(
    ds: &DistributedStorageConfiguration,
) -> Result<ServerTlsConfig, StoreError> {
    if let RaftTlsConfiguration::Tls(tls) = &ds.tls_configuration {
        let cert_pem = tls
            .tls_cert_content
            .as_ref()
            .ok_or(StoreError::TlsConfigMissing)?
            .expose_secret();
        // See `get_client_tls_config` — same 30-day cap (ADR 0016-v2 §4.2),
        // enforced on every load of this shared config.
        check_cert_max_validity(cert_pem)?;
        let identity = Identity::from_pem(
            cert_pem,
            tls.tls_key_content
                .as_ref()
                .ok_or(StoreError::TlsConfigMissing)?
                .expose_secret(),
        );
        let mut tls_server_config = ServerTlsConfig::new().identity(identity);
        if let Some(cert_ca) = tls.tls_client_ca_content.as_ref() {
            tls_server_config =
                tls_server_config.client_ca_root(Certificate::from_pem(cert_ca.expose_secret()));
        };
        Ok(tls_server_config)
    } else {
        Err(StoreError::TlsConfigMissing)
    }
}

// ---------------------------------------------------------------------------
// SPIFFE mTLS helpers (Spiffe variant of RaftTlsConfiguration — ADR 0016-v2)
// ---------------------------------------------------------------------------

/// Build a `rustls::ClientConfig` presenting the SVID chosen by `selector`.
///
/// SVID rotation is managed internally by `spiffe-rustls`'s `MaterialWatcher`;
/// no separate watcher task is needed.
async fn spiffe_client_config(
    purpose: &str,
    trust_domains: &[String],
    selector: SvidSelector,
) -> Result<Arc<rustls::ClientConfig>, StoreError> {
    let source = crate::spiffe_wait::wait_for_spiffe_source(
        purpose,
        X509SourceBuilder::new().picker(selector).build(),
    )
    .await
    .map_err(StoreError::Other)?;

    let mut rustls_config = mtls_client(source)
        .authorize(
            authorizer::trust_domains(trust_domains.to_vec())
                .map_err(|e| StoreError::Other(eyre::eyre!("Invalid SPIFFE trust domain: {e}")))?,
        )
        .build()
        .map_err(|e| StoreError::Other(eyre::eyre!("Failed to build SPIFFE rustls config: {e}")))?;

    // gRPC requires h2 ALPN; tonic's built-in TLS connector adds this
    // automatically, but when bypassing it via connect_with_connector we must
    // set it ourselves.
    rustls_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(rustls_config))
}

/// Initialize a SPIFFE-backed [`RaftTlsClient`] for Raft peer connections.
///
/// With `identities` configured, one client configuration is built per
/// identity, pinned by its full SPIFFE ID, and each role is served by the
/// identity listing it. Without them, a single configuration pinned by the
/// legacy `own_svid_path` serves every role.
async fn init_spiffe_raft_tls(
    spiffe: &crate::config::SpiffeTls,
) -> Result<RaftTlsClient, StoreError> {
    let by_svid_role = resolve_identities(
        &spiffe.identities,
        &spiffe.trust_domains,
        &spiffe.operator_role,
    )
    .map_err(|e| StoreError::Other(eyre::eyre!("invalid identities: {e}")))?;

    if by_svid_role.is_empty() {
        let cfg = spiffe_client_config(
            "Raft peer mTLS client",
            &spiffe.trust_domains,
            SvidSelector::Path(spiffe.own_svid_path()),
        )
        .await?;
        return Ok(RaftTlsClient::Spiffe(Arc::new(SpiffeClients {
            by_role: Default::default(),
            fallback: Some(cfg),
        })));
    }

    // Only the `node` identity is used for outbound traffic so far: no caller
    // dials with another role yet (`channel_as`/`connect_as`).
    for role in by_svid_role.keys().filter(|r| **r != PeerRole::Node) {
        tracing::warn!(
            ?role,
            "identity for this role is configured but not used for outbound connections yet"
        );
    }
    let mut by_svid: std::collections::HashMap<String, Arc<rustls::ClientConfig>> =
        Default::default();
    let mut by_role = std::collections::HashMap::new();
    for (role, svid) in by_svid_role {
        let cfg = match by_svid.get(&svid) {
            Some(cfg) => cfg.clone(),
            None => {
                let cfg = spiffe_client_config(
                    "Raft peer mTLS client",
                    &spiffe.trust_domains,
                    SvidSelector::Id(svid.clone()),
                )
                .await?;
                by_svid.insert(svid.clone(), cfg.clone());
                cfg
            }
        };
        by_role.insert(role, cfg);
    }
    Ok(RaftTlsClient::Spiffe(Arc::new(SpiffeClients {
        by_role,
        fallback: None,
    })))
}

/// Build a gRPC [`Channel`] to `target_addr` using SPIFFE mTLS.
///
/// Intended for CLI tools that establish a single connection and exit.
/// The channel uses a [`SpiffeConnector`] so that SPIFFE URI SAN verification
/// is applied instead of standard hostname verification.
///
/// `svid` pins the SVID presented to the server (see [`SvidSelector`]); `None`
/// takes whatever the Workload API returns first, which is only correct for a
/// workload holding a single SVID.
pub async fn get_spiffe_grpc_channel(
    target_addr: http::Uri,
    trust_domains: &[String],
    svid: Option<SvidSelector>,
) -> Result<Channel, StoreError> {
    let tls = match svid {
        Some(selector) => {
            spiffe_client_config("Raft gRPC client channel", trust_domains, selector).await?
        }
        None => {
            let source = crate::spiffe_wait::wait_for_spiffe_source(
                "Raft gRPC client channel",
                X509Source::new(),
            )
            .await
            .map_err(StoreError::Other)?;
            let mut cfg = mtls_client(source)
                .authorize(
                    authorizer::trust_domains(trust_domains.to_vec()).map_err(|e| {
                        StoreError::Other(eyre::eyre!("Invalid SPIFFE trust domain: {e}"))
                    })?,
                )
                .build()
                .map_err(|e| {
                    StoreError::Other(eyre::eyre!("Failed to build SPIFFE rustls config: {e}"))
                })?;
            cfg.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(cfg)
        }
    };

    let connector = SpiffeConnector { tls };

    // Rewrite the URI to `http://` so tonic doesn't attempt hostname-based TLS
    // on top of our connector's own TLS.
    let mut parts = target_addr.into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTP);
    let http_uri = http::Uri::from_parts(parts)
        .map_err(|e| StoreError::Other(eyre::eyre!("Invalid Raft peer URI: {e}")))?;

    Channel::builder(http_uri)
        .connect_with_connector(connector)
        .await
        .map_err(|e| StoreError::Other(eyre::eyre!("Failed to connect to Raft peer: {e}")))
}

// ---------------------------------------------------------------------------
// TLS watcher — entry point called from app.rs
// ---------------------------------------------------------------------------

/// Initialize the [`RaftTlsClient`] for Raft peer connections.
///
/// Dispatches to either the SPIFFE Workload API path (when
/// [`RaftTlsConfiguration::Spiffe`] is configured) or the static file-based
/// TLS watcher (when [`RaftTlsConfiguration::Tls`] is configured).
pub async fn init_tls_watcher(
    config_manager: &Arc<ConfigManager>,
) -> Result<RaftTlsClient, StoreError> {
    let spiffe_cfg = {
        let cfg = config_manager.config.read().await;
        match cfg
            .view()
            .section::<DistributedStorageConfiguration>()
            .map(|ds| &ds.tls_configuration)
        {
            Some(RaftTlsConfiguration::Spiffe(spiffe_cfg)) => Some(spiffe_cfg.clone()),
            _ => None,
        }
    };

    if let Some(spiffe_cfg) = spiffe_cfg {
        // Present the configured identity per role (or the node's own legacy
        // identity: first allowed peer SVID, else the
        // `<spiffe_path_prefix>node` convention), never some other SVID the
        // process happens to also hold.
        return init_spiffe_raft_tls(&spiffe_cfg).await;
    }

    // Static TLS fallback: load certificates from config files.
    let initial_config = {
        let cfg = config_manager.config.read().await;
        get_client_tls_config(
            cfg.view()
                .section::<DistributedStorageConfiguration>()
                .ok_or(StoreError::TlsConfigMissing)?,
        )?
    };

    let (tx, rx) = watch::channel(initial_config);

    let cm_clone = config_manager.clone();
    let mut reload_rx = config_manager.notify_tx.subscribe();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_ok() {
            let cfg = cm_clone.config.read().await;
            let Some(ds) = cfg.view().section::<DistributedStorageConfiguration>() else {
                error!("failed to reload TLS certificates: [distributed_storage] is gone");
                continue;
            };
            match get_client_tls_config(ds) {
                Ok(new_config) => {
                    let _ = tx.send(new_config);
                }
                Err(e) => {
                    error!("failed to reload TLS certificates: {:?}", e.to_string());
                }
            }
        }
    });

    Ok(RaftTlsClient::Static(rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // check_cert_max_validity — P3-A (ADR 0016-v2 §4.2)
    // ---------------------------------------------------------------------------

    fn make_cert_pem(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair, date_time_ymd};
        let mut params = CertificateParams::default();
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().expect("keygen");
        params
            .self_signed(&key)
            .expect("self-sign")
            .pem()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn cert_max_validity_ok_29_days() {
        // June 1 → June 30 = 29 days
        let pem = make_cert_pem((2026, 6, 1), (2026, 6, 30));
        assert!(check_cert_max_validity(&pem).is_ok());
    }

    #[test]
    fn cert_max_validity_ok_exactly_30_days() {
        // June 1 → July 1 = exactly 30 days
        let pem = make_cert_pem((2026, 6, 1), (2026, 7, 1));
        assert!(check_cert_max_validity(&pem).is_ok());
    }

    #[test]
    fn cert_max_validity_rejected_31_days() {
        // June 1 → July 2 = 31 days
        let pem = make_cert_pem((2026, 6, 1), (2026, 7, 2));
        assert!(check_cert_max_validity(&pem).is_err());
    }

    // ---------------------------------------------------------------------------
    // strip_scheme
    // ---------------------------------------------------------------------------

    #[test]
    fn test_strip_scheme_https() {
        assert_eq!(
            strip_scheme("https://keystone-rs-0.svc:8300"),
            "keystone-rs-0.svc:8300"
        );
    }

    #[test]
    fn test_strip_scheme_http() {
        assert_eq!(strip_scheme("http://localhost:8300"), "localhost:8300");
    }

    #[test]
    fn test_strip_scheme_no_scheme() {
        assert_eq!(
            strip_scheme("keystone-rs-0.svc:8300"),
            "keystone-rs-0.svc:8300"
        );
    }

    #[test]
    fn test_strip_scheme_fqdn() {
        assert_eq!(
            strip_scheme(
                "https://keystone-rs-0.keystone-rs-internal.default.svc.cluster.local:8300"
            ),
            "keystone-rs-0.keystone-rs-internal.default.svc.cluster.local:8300"
        );
    }
}

#[cfg(test)]
mod channel_cache_tests {
    use super::*;

    fn lazy_channel() -> Channel {
        tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()
    }

    fn cache_with(max_age: Duration) -> (ChannelCache, watch::Sender<ClientTlsConfig>) {
        let (tx, rx) = watch::channel(ClientTlsConfig::new());
        let cache = ChannelCache::with_max_age(RaftTlsClient::Static(rx), max_age);
        cache
            .channels
            .lock()
            .unwrap()
            .insert("peer:1".into(), (lazy_channel(), Instant::now()));
        (cache, tx)
    }

    fn connection() -> (NetworkConnection, watch::Sender<ClientTlsConfig>) {
        let (cache, tx) = cache_with(Duration::from_secs(60));
        let conn = NetworkConnection::new(7, pb::raft::Node::default(), Arc::new(cache));
        (conn, tx)
    }

    #[tokio::test]
    async fn with_deadline_times_out_a_hung_rpc() {
        let (conn, _tx) = connection();
        let res: Result<(), RPCError> = conn
            .with_deadline(
                RPCTypes::Vote,
                Duration::from_millis(20),
                futures::future::pending(),
            )
            .await;
        match res {
            Err(RPCError::Timeout(t)) => {
                assert_eq!(t.target, 7);
                assert_eq!(t.timeout, Duration::from_millis(20));
            }
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_deadline_passes_through_a_fast_rpc() {
        let (conn, _tx) = connection();
        let res = conn
            .with_deadline(RPCTypes::Vote, Duration::from_secs(5), async {
                Ok::<_, RPCError>(42)
            })
            .await;
        assert_eq!(res.unwrap(), 42);
    }

    fn cached(cache: &ChannelCache) -> usize {
        cache.channels.lock().unwrap().len()
    }

    #[tokio::test]
    async fn spreads_requests_over_a_pool_per_peer() {
        let (cache, _tx) = cache_with(CHANNEL_MAX_AGE);
        let keys: std::collections::HashSet<_> = (0..CHANNELS_PER_PEER * 3)
            .map(|_| cache.pool_key("peer:1", PeerRole::Node))
            .collect();
        assert_eq!(keys.len(), CHANNELS_PER_PEER);
    }

    #[tokio::test]
    async fn pool_keys_separate_roles() {
        let (cache, _tx) = cache_with(CHANNEL_MAX_AGE);
        // Compare at the same slot: channels of different roles are never
        // shared, so the role must be part of the key.
        cache
            .next_slot
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let node = cache.pool_key("peer:1", PeerRole::Node);
        cache
            .next_slot
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let voter = cache.pool_key("peer:1", PeerRole::Voter);
        assert_ne!(node, voter);
    }

    #[tokio::test]
    async fn keeps_fresh_channels() {
        let (cache, _tx) = cache_with(CHANNEL_MAX_AGE);
        cache.refresh();
        assert_eq!(cached(&cache), 1);
    }

    #[tokio::test]
    async fn static_tls_change_drops_channels_once() {
        let (cache, tx) = cache_with(CHANNEL_MAX_AGE);
        tx.send(ClientTlsConfig::new()).unwrap();
        cache.refresh();
        assert_eq!(cached(&cache), 0);

        // The change was consumed: channels added afterwards are kept.
        cache
            .channels
            .lock()
            .unwrap()
            .insert("peer:1".into(), (lazy_channel(), Instant::now()));
        cache.refresh();
        assert_eq!(cached(&cache), 1);
    }

    #[tokio::test]
    async fn closed_tls_watch_drops_channels() {
        let (cache, tx) = cache_with(CHANNEL_MAX_AGE);
        drop(tx);
        cache.refresh();
        assert_eq!(cached(&cache), 0);
    }

    #[tokio::test]
    async fn expired_channels_are_dropped() {
        let (cache, _tx) = cache_with(Duration::ZERO);
        cache.refresh();
        assert_eq!(cached(&cache), 0);
    }
}

#[cfg(test)]
mod spiffe_clients_tests {
    use super::*;

    fn client_config() -> Arc<rustls::ClientConfig> {
        let provider = openstack_keystone_tls_provider::provider();
        let _ = rustls::crypto::CryptoProvider::install_default(provider);
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    #[test]
    fn for_role_prefers_the_role_binding() {
        let node_cfg = client_config();
        let voter_cfg = client_config();
        let clients = SpiffeClients {
            by_role: std::collections::HashMap::from([(PeerRole::Voter, voter_cfg.clone())]),
            fallback: Some(node_cfg.clone()),
        };
        assert!(Arc::ptr_eq(
            &clients.for_role(PeerRole::Voter).unwrap(),
            &voter_cfg
        ));
        assert!(Arc::ptr_eq(
            &clients.for_role(PeerRole::Node).unwrap(),
            &node_cfg
        ));
    }

    #[test]
    fn for_role_errors_when_nothing_serves_the_role() {
        let clients = SpiffeClients {
            by_role: Default::default(),
            fallback: None,
        };
        assert!(clients.for_role(PeerRole::Node).is_err());
    }
}
