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
//! # Raft gRPC listener
use std::sync::Arc;

use color_eyre::eyre::{Report, Result};
use openstack_keystone_config::RaftTlsConfiguration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tonic::service::InterceptorLayer;

use openstack_keystone_distributed_storage::{
    app::{Storage, get_app_server},
    network::get_server_tls_config,
};
use openstack_keystone_storage_api::StorageApi;

use crate::config::Config;
use crate::server::listener::spiffe_common;

/// Validate a SPIFFE ID from the peer certificate chain against the allowed
/// trust domains and expected path prefix.
///
/// This is the core validation performed by [`SpiffeIdInterceptor::call`].
/// Exposed as a standalone function for testability.
fn validate_spiffe_id(
    peer_certs: Option<Arc<Vec<rustls::pki_types::CertificateDer<'static>>>>,
    trust_domains: &[String],
    allowed_peer_svids: &[String],
) -> std::result::Result<(), tonic::Status> {
    use spiffe::cert::spiffe_id_from_der;

    let certs = peer_certs
        .ok_or_else(|| tonic::Status::permission_denied("mTLS required: no peer certificate"))?;

    let leaf = certs.first().ok_or_else(|| {
        tonic::Status::permission_denied("mTLS required: empty certificate chain")
    })?;

    let spiffe_id = spiffe_id_from_der(leaf.as_ref()).map_err(|e| {
        tonic::Status::permission_denied(format!("Invalid SPIFFE ID in peer certificate: {e}"))
    })?;

    let td_name = spiffe_id.trust_domain_name();
    if !trust_domains.iter().any(|td| td == td_name) {
        return Err(tonic::Status::permission_denied(format!(
            "SPIFFE trust domain {td_name:?} is not in the allowed list"
        )));
    }

    // If allowed_peer_svids is configured, enforce exact SVID match for tight
    // identity control (ADR 0016-v2 §4.1). Otherwise fall back to prefix check.
    let spiffe_uri = format!("spiffe://{}{}", td_name, spiffe_id.path());
    if !allowed_peer_svids.is_empty() {
        if !allowed_peer_svids.contains(&spiffe_uri) {
            return Err(tonic::Status::permission_denied(format!(
                "SPIFFE ID '{}' is not in the allowed peer SVID list",
                spiffe_uri
            )));
        }
    } else {
        // Fallback: accept paths starting with `/keystone/storage/` (custom format) or
        // `/ns/<namespace>/sa/<service-account>` (standard SPIRE SpiffeID format).
        let path = spiffe_id.path();
        if !(path.starts_with("/keystone/storage/") || path.starts_with("/ns/")) {
            return Err(tonic::Status::permission_denied(format!(
                "SPIFFE ID path {:?} does not match allowed prefix (expected `/keystone/storage/` or `/ns/<ns>/sa/<sa>`)",
                path
            )));
        }
    }

    Ok(())
}

/// gRPC interceptor that enforces SPIFFE mTLS identity on Raft connections.
///
/// Every inbound gRPC request must carry a peer certificate whose SPIFFE ID
/// matches one of the configured trust domains (ADR 0016-v2 §4.1).
/// When `allowed_peer_svids` is configured, only those exact SVIDs are
/// accepted.
#[derive(Clone)]
struct SpiffeIdInterceptor {
    trust_domains: Arc<Vec<String>>,
    allowed_peer_svids: Arc<Vec<String>>,
}

impl tonic::service::Interceptor for SpiffeIdInterceptor {
    fn call(
        &mut self,
        req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        validate_spiffe_id(
            req.peer_certs(),
            &self.trust_domains,
            &self.allowed_peer_svids,
        )?;
        Ok(req)
    }
}

/// Start Raft backed distributed storage.
///
/// Broadcasts `true` on `bound_signal` once the Raft gRPC listener is bound
/// and accepting connections.  Callers may use this to coordinate with
/// [`ensure_raft_initialized`] — a non-bootstrap node should wait for its own
/// listener to be ready before calling `add_learner`, otherwise the leader
/// cannot replicate back to it.
pub async fn start_raft_app(
    storage: Arc<Storage>,
    config: Config,
    cancel_token: CancellationToken,
    bound_signal: tokio::sync::watch::Sender<bool>,
) -> Result<(), Report> {
    let Some(ds) = &config.distributed_storage else {
        return Ok(());
    };

    let storage_app = get_app_server(&storage).await?;

    // Install aws-lc-rs as the default rustls provider (idempotent).
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        if rustls::crypto::CryptoProvider::install_default(provider).is_err() {
            tracing::warn!("Failed to install aws-lc-rs crypto provider");
        }
    }

    let grpc_addr = ds.node_listener_addr;

    match &ds.tls_configuration {
        RaftTlsConfiguration::Spiffe(spiffe_cfg) => {
            let trust_domains = spiffe_cfg.trust_domains.clone();
            let allowed_peer_svids = spiffe_cfg.allowed_peer_svids.clone();

            let server_config = match spiffe_common::build_spiffe_config(
                cancel_token.clone(),
                trust_domains.clone(),
            )
            .await?
            {
                Some(cfg) => cfg,
                None => return Ok(()),
            };

            let acceptor = TlsAcceptor::from(server_config);
            let listener = TcpListener::bind(grpc_addr).await?;

            let interceptor = SpiffeIdInterceptor {
                trust_domains: Arc::new(trust_domains),
                allowed_peer_svids: Arc::new(allowed_peer_svids),
            };

            let mut server =
                tonic::transport::Server::builder().layer(InterceptorLayer::new(interceptor));
            let tonic_router = server.add_routes(storage_app);

            tracing::info!(
                "Starting distributed storage at {:?} with SPIFFE mTLS",
                grpc_addr
            );

            // Build a stream of pre-TLS-wrapped connections.  TLS handshake
            // failures are logged and skipped; TCP accept errors terminate the
            // stream and surface to tonic as a transient error.  After
            // consecutive handshake failures the loop returns `Err` to prevent
            // a tight retry loop under targeted attacks.
            const MAX_CONSECUTIVE_TLS_FAILURES: u32 = 10;
            let incoming = futures_util::stream::try_unfold(
                (listener, acceptor, 0u32),
                |(listener, acceptor, mut fail_count)| async move {
                    loop {
                        let (tcp, _) = listener.accept().await?;
                        match acceptor.accept(tcp).await {
                            Ok(tls) => {
                                return Ok::<_, std::io::Error>(Some((
                                    tls,
                                    (listener, acceptor, 0u32),
                                )));
                            }
                            Err(e) => {
                                fail_count += 1;
                                tracing::warn!("Raft gRPC TLS handshake failed: {e}");
                                if fail_count >= MAX_CONSECUTIVE_TLS_FAILURES {
                                    return Err(std::io::Error::other(format!(
                                        "giving up after {MAX_CONSECUTIVE_TLS_FAILURES} \
                                             consecutive TLS handshake failures"
                                    )));
                                }
                            }
                        }
                    }
                },
            );

            _ = bound_signal.send(true);
            tonic_router
                .serve_with_incoming_shutdown(incoming, async move {
                    cancel_token.cancelled().await;
                })
                .await?;
        }

        RaftTlsConfiguration::Tls(_) => {
            let mut server =
                tonic::transport::Server::builder().tls_config(get_server_tls_config(&config)?)?;
            let tonic_router = server.add_routes(storage_app);

            tracing::info!("Starting distributed storage at {:?}", grpc_addr);

            _ = bound_signal.send(true);
            tonic_router
                .serve_with_shutdown(grpc_addr, async move {
                    cancel_token.cancelled().await;
                })
                .await?;
        }
    }

    Ok(())
}

/// Ensure Raft cluster is initialized with at least the current node, or join
/// an existing cluster if this node is not the bootstrap node.
///
/// `listener_bound` is a watch channel that [`start_raft_app`] signals once the
/// Raft gRPC listener is bound.  Non-bootstrap nodes wait for this signal
/// before calling `add_learner`, ensuring their own listener is ready to accept
/// replication traffic from the leader.
pub async fn ensure_raft_initialized(
    storage: Arc<Storage>,
    config: Config,
    mut listener_bound: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Report> {
    let Some(ds) = &config.distributed_storage else {
        return Ok(());
    };

    let node_id = storage.node_id();
    let my_cluster_addr = ds.node_cluster_addr.to_string();

    // Bootstrap node (node_id == 0): self-bootstrap as a single-node cluster.
    // Known peers join later via [add_learner] (non-bootstrap path below).
    if !storage.is_initialized().await? && node_id == 0 {
        let self_node = openstack_keystone_storage_api::Node {
            node_id,
            rpc_addr: my_cluster_addr.clone(),
        };

        tracing::info!("Self-bootstrapping integrated storage as single-node cluster.");
        storage
            .initialize([(node_id, self_node)].into_iter().collect())
            .await?;
        return Ok(());
    }

    // Non-bootstrap node: auto-join using known peer addresses.
    if ds.retry_join_nodes.is_empty() {
        if !storage.is_initialized().await? {
            return Err(Report::msg(
                "Raft cluster is not initialized and no retry_join_nodes configured - \
                 set retry_join_nodes or join manually",
            ));
        }
        return Ok(());
    }

    // Already-initialized node (e.g. pod restart): storage has persisted Raft
    // state including membership. The node is already a member, so no need to
    // call add_learner which would fail with "node_id already registered".
    if storage.is_initialized().await? {
        let node_id = storage.node_id();
        tracing::info!(
            node_id,
            "Raft storage already initialized — skipping cluster join (node restart)"
        );
        return Ok(());
    }

    let join_addrs: Vec<&str> = ds
        .retry_join_nodes
        .iter()
        .filter(|(pid, _)| *pid != node_id)
        .map(|(_, addr)| addr.as_str())
        .collect();

    if join_addrs.is_empty() {
        return Err(Report::msg(
            "retry_join_nodes contains only this node - no peers to join",
        ));
    }

    // Wait for our own Raft gRPC listener to be bound before calling
    // add_learner.  Without this, the leader may try to replicate back to us
    // before the port is accepting connections, causing join timeouts.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let _ = listener_bound.changed().await;
    })
    .await
    .map_err(|_| Report::msg("Raft listener did not bind within 30s — aborting cluster join"))?;

    // With publishNotReadyAddresses: true on the headless service, DNS records
    // are available for non-ready pods.  The FQDN from config will resolve
    // correctly, so the leader can replicate to us once replication starts.
    tracing::info!(
        node_id,
        join_count = join_addrs.len(),
        "Waiting for Raft cluster to be available before joining..."
    );
    for attempt in 0..60 {
        for join_addr in &join_addrs {
            match storage.join_cluster(join_addr, &my_cluster_addr).await {
                Ok(()) => {
                    tracing::info!(node_id, join_addr, "Successfully joined Raft cluster.");
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!(
                        node_id,
                        join_addr,
                        ?e,
                        "join attempt failed, trying next address"
                    );
                }
            }
        }
        if attempt % 10 == 0 {
            tracing::debug!(
                node_id,
                attempt,
                "still waiting for join addresses to be available"
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(Report::msg(
        "timed out joining Raft cluster - none of the retry_join_nodes responded",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, SanType};

    fn generate_spiffe_cert(
        trust_domain: &str,
        path: &str,
    ) -> rustls::pki_types::CertificateDer<'static> {
        use rcgen::KeyPair;

        let spiffe_uri = format!("spiffe://{trust_domain}{path}");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let san_uri = spiffe_uri.try_into().unwrap();
        params.subject_alt_names = vec![SanType::URI(san_uri)];
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn test_spiffe_id_valid() {
        let trust_domains = vec!["example.org".to_string()];
        let cert = generate_spiffe_cert("example.org", "/keystone/storage/node-0");
        let certs = Some(Arc::new(vec![cert]));
        assert!(validate_spiffe_id(certs, &trust_domains, &[]).is_ok());
    }

    #[test]
    fn test_spiffe_id_unauthorized_trust_domain() {
        let trust_domains = vec!["example.org".to_string()];
        let cert = generate_spiffe_cert("evil.org", "/keystone/storage/node-0");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &trust_domains, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("evil.org"));
    }

    #[test]
    fn test_spiffe_id_invalid_path() {
        let trust_domains = vec!["example.org".to_string()];
        let cert = generate_spiffe_cert("example.org", "/admin/delete");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &trust_domains, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("does not match allowed prefix"));
    }

    #[test]
    fn test_spiffe_id_standard_spire_path() {
        let trust_domains = vec!["example.org".to_string()];
        let cert = generate_spiffe_cert("example.org", "/ns/default/sa/keystone");
        let certs = Some(Arc::new(vec![cert]));
        assert!(validate_spiffe_id(certs, &trust_domains, &[]).is_ok());
    }

    #[test]
    fn test_spiffe_id_no_certs() {
        let trust_domains = vec!["example.org".to_string()];
        let err = validate_spiffe_id(None, &trust_domains, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("no peer certificate"));
    }

    #[test]
    fn test_spiffe_id_empty_chain() {
        let trust_domains = vec!["example.org".to_string()];
        let certs = Some(Arc::new(vec![]));
        let err = validate_spiffe_id(certs, &trust_domains, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("empty certificate chain"));
    }

    #[test]
    fn test_spiffe_id_invalid_cert() {
        let trust_domains = vec!["example.org".to_string()];
        let certs = Some(Arc::new(vec![rustls::pki_types::CertificateDer::from(
            vec![0x00, 0x01],
        )]));
        let err = validate_spiffe_id(certs, &trust_domains, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Invalid SPIFFE ID"));
    }

    #[test]
    fn test_spiffe_id_multiple_trust_domains() {
        let trust_domains = vec!["example.org".to_string(), "example.net".to_string()];
        let cert_1 = generate_spiffe_cert("example.org", "/keystone/storage/node-0");
        let cert_2 = generate_spiffe_cert("example.net", "/keystone/storage/node-1");

        assert!(validate_spiffe_id(Some(Arc::new(vec![cert_1])), &trust_domains, &[]).is_ok());
        assert!(validate_spiffe_id(Some(Arc::new(vec![cert_2])), &trust_domains, &[]).is_ok());
    }
}
