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
use openstack_keystone_config::RaftTlsConfiguration;
use secrecy::ExposeSecret;
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client};
use tokio::sync::watch;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, ServerTlsConfig};
use tracing::error;

use openstack_keystone_config::{Config, ConfigManager};

use crate::StoreError;
use crate::protobuf as pb;
use crate::protobuf::raft::VoteRequest as PbVoteRequest;
use crate::protobuf::raft::VoteResponse as PbVoteResponse;
use crate::protobuf::raft::raft_service_client::RaftServiceClient;
use crate::types::*;

/// TLS client mode for Raft peer connections.
///
/// * `Spiffe` — SPIFFE mTLS using a `rustls::ClientConfig` built from a live
///   X.509 SVID source.  Certificate verification is done by
///   `SpiffeServerCertVerifier` (URI SAN, not hostname).  SVID rotation is
///   handled internally by `spiffe-rustls`'s `MaterialWatcher`.
/// * `Static` — Static file-based mTLS.  The `ClientTlsConfig` is refreshed
///   via a tokio `watch` channel whenever the config file changes.
#[derive(Clone)]
pub enum RaftTlsClient {
    Spiffe(Arc<rustls::ClientConfig>),
    Static(watch::Receiver<ClientTlsConfig>),
}

impl RaftTlsClient {
    /// Build a gRPC [`Channel`] to `addr` using the configured TLS mode.
    ///
    /// In `Static` mode the channel is created lazily (no connection until the
    /// first RPC).  In `Spiffe` mode `connect_with_connector` establishes the
    /// connection eagerly so that TLS errors surface immediately.
    pub async fn connect(&self, addr: &str) -> Result<Channel, StoreError> {
        match self {
            Self::Static(rx) => {
                let tls_cfg = rx.borrow().clone();
                Ok(tonic::transport::Endpoint::from_shared(format!(
                    "https://{addr}"
                ))?
                .tls_config(tls_cfg)?
                .connect_lazy())
            }
            Self::Spiffe(cfg) => {
                let connector = SpiffeConnector { tls: cfg.clone() };
                Channel::builder(format!("http://{addr}").parse()?)
                    .connect_with_connector(connector)
                    .await
                    .map_err(|e| {
                        StoreError::Other(eyre::eyre!("SPIFFE gRPC connect failed: {e}"))
                    })
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
/// SPIFFE-aware `rustls::ClientConfig` produced by `spiffe_rustls::mtls_client`.
#[derive(Clone)]
struct SpiffeConnector {
    tls: Arc<rustls::ClientConfig>,
}

impl tower::Service<http::Uri> for SpiffeConnector {
    type Response =
        hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

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
            let tcp = tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;
            let connector = tokio_rustls::TlsConnector::from(tls);
            // `SpiffeServerCertVerifier` validates the peer's SPIFFE URI SAN and
            // ignores the DNS server name, so any valid constant name is fine here.
            let server_name =
                rustls::pki_types::ServerName::try_from("keystone-raft-peer.internal")
                    .expect("constant DNS name is valid");
            let tls_stream = connector.connect(server_name, tcp).await?;
            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
}

/// Network implementation for gRPC-based Raft communication.
/// Provides the networking layer for Raft nodes to communicate with each other.
#[derive(Clone)]
pub struct NetworkManager {
    tls_client: RaftTlsClient,
}

impl NetworkManager {
    /// Create a new `NetworkManager`.
    pub fn new(tls_client: RaftTlsClient) -> Result<Self, StoreError> {
        Ok(Self { tls_client })
    }
}

/// Implementation of the RaftNetworkFactory trait for creating new network
/// connections. This factory creates gRPC client connections to other Raft
/// nodes.
impl RaftNetworkFactory<TypeConfig> for Arc<NetworkManager> {
    type Network = NetworkConnection;

    #[tracing::instrument(level = "debug", skip_all)]
    async fn new_client(&mut self, _: NodeId, node: &Node) -> Self::Network {
        NetworkConnection::new(node.clone(), self.tls_client.clone())
    }
}

/// Represents an active network connection to a remote Raft node.
/// Handles serialization and deserialization of Raft messages over gRPC.
pub struct NetworkConnection {
    /// Target node.
    target_node: pb::raft::Node,
    /// TLS client mode (SPIFFE or static).
    tls_client: RaftTlsClient,
}

impl NetworkConnection {
    /// Creates a new `NetworkConnection` with the provided gRPC client.
    pub fn new(target_node: Node, tls_client: RaftTlsClient) -> Self {
        NetworkConnection {
            target_node,
            tls_client,
        }
    }

    /// Creates a gRPC client to the target node.
    pub async fn make_client(&self) -> Result<RaftServiceClient<Channel>, RPCError> {
        let addr = &self.target_node.rpc_addr;

        let channel = match &self.tls_client {
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
                .connect()
                .await
                .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))?
            }

            RaftTlsClient::Spiffe(cfg) => {
                let connector = SpiffeConnector { tls: cfg.clone() };
                // Use `http://` so tonic forwards the URI directly to our
                // connector without attempting its own hostname-based TLS.
                Channel::builder(
                    format!("http://{addr}")
                        .parse()
                        .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?,
                )
                .connect_with_connector(connector)
                .await
                .map_err(|e| RPCError::Unreachable(Unreachable::<TypeConfig>::new(&e)))?
            }
        };

        Ok(RaftServiceClient::new(channel))
    }

    /// Convert `pb::AppendEntriesResponse` to `StreamAppendResult`.
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
    fn backoff(&self) -> Option<Backoff> {
        Some(Backoff::new(std::iter::repeat(Duration::from_millis(200))))
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

// ---------------------------------------------------------------------------
// Static mTLS config helpers (Tls variant of RaftTlsConfiguration)
// ---------------------------------------------------------------------------

/// Build the tonic [`ClientTlsConfig`] from the Keystone [`Config`].
pub fn get_client_tls_config(config: &Config) -> Result<ClientTlsConfig, StoreError> {
    if let Some(ds) = &config.distributed_storage
        && let RaftTlsConfiguration::Tls(tls) = &ds.tls_configuration
    {
        let identity = Identity::from_pem(
            tls.tls_cert_content
                .as_ref()
                .ok_or(StoreError::TlsConfigMissing)?
                .expose_secret(),
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

/// Build tonic [`ServerTlsConfig`] from the Keystone [`Config`].
pub fn get_server_tls_config(config: &Config) -> Result<ServerTlsConfig, StoreError> {
    if let Some(ds) = &config.distributed_storage
        && let RaftTlsConfiguration::Tls(tls) = &ds.tls_configuration
    {
        let identity = Identity::from_pem(
            tls.tls_cert_content
                .as_ref()
                .ok_or(StoreError::TlsConfigMissing)?
                .expose_secret(),
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

/// Initialize a SPIFFE-backed [`RaftTlsClient`] for Raft peer connections.
///
/// Connects to the SPIRE Workload API and builds a `rustls::ClientConfig` via
/// [`spiffe_rustls::mtls_client`].  SVID rotation is managed internally by
/// `spiffe-rustls`'s `MaterialWatcher`; no separate watcher task is needed.
async fn init_spiffe_raft_tls(trust_domains: Vec<String>) -> Result<RaftTlsClient, StoreError> {
    let source = X509Source::new()
        .await
        .map_err(|e| StoreError::Other(eyre::eyre!("SPIFFE X509Source init failed: {e}")))?;

    let mut rustls_config = mtls_client(source)
        .authorize(
            authorizer::trust_domains(trust_domains)
                .map_err(|e| StoreError::Other(eyre::eyre!("Invalid SPIFFE trust domain: {e}")))?,
        )
        .build()
        .map_err(|e| StoreError::Other(eyre::eyre!("Failed to build SPIFFE rustls config: {e}")))?;

    // gRPC requires h2 ALPN; tonic's built-in TLS connector adds this
    // automatically, but when bypassing it via connect_with_connector we must
    // set it ourselves.
    rustls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(RaftTlsClient::Spiffe(Arc::new(rustls_config)))
}

/// Build a gRPC [`Channel`] to `target_addr` using SPIFFE mTLS.
///
/// Intended for CLI tools that establish a single connection and exit.
/// The channel uses a [`SpiffeConnector`] so that SPIFFE URI SAN verification
/// is applied instead of standard hostname verification.
pub async fn get_spiffe_grpc_channel(
    target_addr: http::Uri,
    trust_domains: &[String],
) -> Result<Channel, StoreError> {
    let source = X509Source::new()
        .await
        .map_err(|e| StoreError::Other(eyre::eyre!("SPIFFE X509Source init failed: {e}")))?;

    let mut rustls_config = mtls_client(source)
        .authorize(
            authorizer::trust_domains(trust_domains.to_vec())
                .map_err(|e| StoreError::Other(eyre::eyre!("Invalid SPIFFE trust domain: {e}")))?,
        )
        .build()
        .map_err(|e| StoreError::Other(eyre::eyre!("Failed to build SPIFFE rustls config: {e}")))?;

    rustls_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = SpiffeConnector {
        tls: Arc::new(rustls_config),
    };

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
    let spiffe_trust_domains = {
        let cfg = config_manager.config.read().await;
        if let Some(ds) = &cfg.distributed_storage {
            if let RaftTlsConfiguration::Spiffe(spiffe_cfg) = &ds.tls_configuration {
                Some(spiffe_cfg.trust_domains.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(trust_domains) = spiffe_trust_domains {
        return init_spiffe_raft_tls(trust_domains).await;
    }

    // Static TLS fallback: load certificates from config files.
    let initial_config = {
        let cfg = config_manager.config.read().await;
        get_client_tls_config(&cfg)?
    };

    let (tx, rx) = watch::channel(initial_config);

    let cm_clone = config_manager.clone();
    let mut reload_rx = config_manager.notify_tx.subscribe();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_ok() {
            let cfg = cm_clone.config.read().await;
            match get_client_tls_config(&cfg) {
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
