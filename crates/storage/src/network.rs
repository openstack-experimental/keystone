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

/// Network implementation for gRPC-based Raft communication.
/// Provides the networking layer for Raft nodes to communicate with each other.
#[derive(Clone)]
pub struct NetworkManager {
    /// Tls client config watcher.
    tls_config_watcher: watch::Receiver<ClientTlsConfig>,
    //config_manager: Arc<ConfigManager>,
}

impl NetworkManager {
    /// Create a new `NetworkManager`.
    ///
    /// # Parameters
    /// - `config_manager`: The Keystone [`ConfigManager`] instance.
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
// Phase 9 — SPIFFE Mode (ADR 0016-v2 §4.1 / F4)
// ---------------------------------------------------------------------------

/// SVID TTL ceiling enforced per ADR 0016-v2 §4.1.
const SVID_MAX_TTL_SECS: u64 = 3600;
/// Minimum remaining SVID validity before rejection (force-renewal window).
const SVID_MIN_REMAINING_SECS: u64 = 300;

/// SPIFFE Workload API provider — interface stub.
///
/// In production this contacts the SPIRE agent at
/// `unix:///tmp/spire-agent/public/api.sock`, retrieves a JWT or X.509 SVID,
/// and enforces the TTL ceiling.
///
/// This implementation always returns [`StoreError::Other`] (SPIFFE workload
/// API not yet implemented).  The struct is defined to lock in the abstraction
/// boundary before the SPIRE client is wired up.
pub struct SpiffeTlsProvider {
    /// SPIFFE trust domain, e.g. `"example.org"`.
    pub trust_domain: String,
    /// Expected role path component, e.g. `"storage"`.
    pub role: String,
}

impl SpiffeTlsProvider {
    pub fn new(trust_domain: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            role: role.into(),
        }
    }

    /// Validate that a SPIFFE ID matches the expected pattern:
    /// `spiffe://<trust_domain>/keystone/storage/<role>`.
    pub fn validate_spiffe_id(&self, spiffe_id: &str) -> Result<(), StoreError> {
        let expected_prefix = format!("spiffe://{}/keystone/storage/", self.trust_domain);
        if !spiffe_id.starts_with(&expected_prefix) {
            return Err(StoreError::Other(eyre::eyre!(
                "SPIFFE ID {spiffe_id:?} does not match expected pattern \
                 spiffe://{}/keystone/storage/<role>",
                self.trust_domain
            )));
        }
        let role_suffix = &spiffe_id[expected_prefix.len()..];
        if role_suffix != self.role {
            return Err(StoreError::Other(eyre::eyre!(
                "SPIFFE ID {spiffe_id:?} role component {role_suffix:?} does not match \
                 expected role {:?}",
                self.role
            )));
        }
        Ok(())
    }
}

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
    // x509-parser uses its own ASN1Time; convert via timestamp.
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

/// Validate SVID remaining TTL against enforcement thresholds.
///
/// Called before accepting a connection in SPIFFE mode.
///
/// Returns `Err` if the SVID has expired, has less than
/// [`SVID_MIN_REMAINING_SECS`] remaining, or exceeds [`SVID_MAX_TTL_SECS`]
/// (which would violate the ADR §4.1 TTL ceiling).
pub fn validate_svid_ttl(issued_at_secs: u64, expires_at_secs: u64) -> Result<(), StoreError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let ttl = expires_at_secs.saturating_sub(issued_at_secs);
    if ttl > SVID_MAX_TTL_SECS {
        return Err(StoreError::Other(eyre::eyre!(
            "SVID TTL {ttl}s exceeds maximum allowed {SVID_MAX_TTL_SECS}s"
        )));
    }

    let remaining = expires_at_secs.saturating_sub(now);
    if remaining < SVID_MIN_REMAINING_SECS {
        return Err(StoreError::Other(eyre::eyre!(
            "SVID has only {remaining}s remaining validity \
             (minimum {SVID_MIN_REMAINING_SECS}s required); force-renew SVID"
        )));
    }

    Ok(())
}

/// Build the tonic [`ClientTlsConfig`] from the Keystone [`Config`].
///
/// Initialize the [`ClientTlsConfig`] from the distributed_storage or the
/// listener configuration of the Keystone [`Config`].
///
/// For all of the [`tls_client_ca`, `tls_cert`, `tls_key`] the corresponding
/// value is searched in the distributed_storage configuration.
///
/// # Parameters
/// - `config`: The Keystone [`Config`] instance.
///
/// # Returns
/// A `Result` containing the `ClientTlsConfig`, or a `StoreError`.
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
///
/// Initialize the [`ServerTlsConfig`] from the distributed_storage or the
/// listener configuration of the Keystone [`Config`].
///
/// For all of the [`tls_client_ca`, `tls_cert`, `tls_key`] the corresponding
/// value is searched in the distributed_storage configuration.
///
/// # Parameters
/// - `config`: The Keystone [`Config`] instance.
///
/// # Returns
/// A `Result` containing the `ServerTlsConfig`, or a `StoreError`.
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

/// Initialize the [ClientTlsConfig] configuration watcher.
///
/// # Parameters
/// - `config_manager`: The Keystone [`ConfigManager`].
///
/// # Returns
/// A `Result` containing the `watch::Receiver<ClientTlsConfig>`, or a
/// `StoreError`.
pub async fn init_tls_watcher(
    config_manager: &Arc<ConfigManager>,
) -> Result<watch::Receiver<ClientTlsConfig>, StoreError> {
    // 1. Initial Load: Try to load the certs once to start with a valid state
    let cfg = config_manager.config.read().await;
    let initial_config = get_client_tls_config(&cfg)?;

    // 2. Create the channel
    let (tx, rx) = watch::channel(initial_config);

    // 3. Spawn the File Watcher Task
    let cm_clone = config_manager.clone();
    let mut reload_rx = config_manager.notify_tx.subscribe();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_ok() {
            let cfg = cm_clone.config.read().await;
            match get_client_tls_config(&cfg) {
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
