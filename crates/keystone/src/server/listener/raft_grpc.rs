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
//! # Raft gRPC listener
use std::sync::Arc;

use color_eyre::eyre::{Report, Result};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tonic::service::InterceptorLayer;

use openstack_keystone_distributed_storage::config::{
    DistributedStorageConfiguration, RaftTlsConfiguration,
};
use openstack_keystone_distributed_storage::{
    app::{Storage, get_app_server},
    grpc::authz::{PeerAuthz, PeerRole},
    network::{check_svid_ttl_der, get_server_tls_config, now_unix_secs},
};

use crate::server::listener::spiffe_common;

/// HTTP/2 keepalive PING interval and acknowledgement timeout for peer
/// connections. A peer that vanished without closing its connection (pod
/// replaced, node power loss) would otherwise keep its replication stream
/// open here until the kernel gives up on the socket.
const PEER_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(5);

/// Validate the SPIFFE ID of the peer certificate and resolve its storage role.
///
/// The identity is resolved through [`PeerAuthz::role_of_identity`]: only
/// `<spiffe_path_prefix><role>` paths and exact `allowed_peer_svids` entries
/// are accepted. Per-RPC role enforcement stays in the service handlers; this
/// is a coarse gate rejecting unknown identities early.
///
/// Exposed as a standalone function for testability.
fn validate_spiffe_id(
    peer_certs: Option<Arc<Vec<rustls::pki_types::CertificateDer<'static>>>>,
    authz: &PeerAuthz,
) -> std::result::Result<PeerRole, tonic::Status> {
    use spiffe::cert::spiffe_id_from_der;

    let certs = peer_certs
        .ok_or_else(|| tonic::Status::permission_denied("mTLS required: no peer certificate"))?;

    let leaf = certs.first().ok_or_else(|| {
        tonic::Status::permission_denied("mTLS required: empty certificate chain")
    })?;

    let spiffe_id = spiffe_id_from_der(leaf.as_ref()).map_err(|e| {
        tonic::Status::permission_denied(format!("Invalid SPIFFE ID in peer certificate: {e}"))
    })?;

    let uri = format!(
        "spiffe://{}{}",
        spiffe_id.trust_domain_name(),
        spiffe_id.path()
    );
    let role = authz.role_of_identity(&uri)?;

    // Enforce the 5-minute force-renewal window (ADR 0016-v2 §4.1).
    // This guards ALL Raft gRPC routes including StorageService forwarded
    // reads. ClusterAdminService handlers additionally re-check this
    // themselves (`cluster_admin_service::check_svid_ttl`) — that's
    // intentional defense-in-depth for the RBAC-sensitive admin surface, not
    // duplicated oversight.
    check_svid_ttl_der(leaf.as_ref(), now_unix_secs())?;

    Ok(role)
}

/// gRPC interceptor that enforces SPIFFE mTLS identity on Raft connections.
///
/// Every inbound gRPC request must carry a peer certificate whose SPIFFE ID
/// resolves to a storage role via [`PeerAuthz`] (ADR 0016-v2 §4.1).
#[derive(Clone)]
struct SpiffeIdInterceptor {
    authz: Arc<PeerAuthz>,
}

impl tonic::service::Interceptor for SpiffeIdInterceptor {
    fn call(
        &mut self,
        req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        validate_spiffe_id(req.peer_certs(), &self.authz)?;
        Ok(req)
    }
}

/// Start Raft backed distributed storage.
///
/// Broadcasts `true` on `bound_signal` once the Raft gRPC listener is bound
/// and accepting connections.  Callers may use this to coordinate with
/// [`openstack_keystone_distributed_storage::bootstrap::ensure_raft_initialized`]
/// — a non-bootstrap node should wait for its own
/// listener to be ready before calling `add_learner`, otherwise the leader
/// cannot replicate back to it.
pub async fn start_raft_app(
    storage: Arc<Storage>,
    ds: DistributedStorageConfiguration,
    cancel_token: CancellationToken,
    bound_signal: tokio::sync::watch::Sender<bool>,
) -> Result<(), Report> {
    let ds = &ds;

    let storage_app = get_app_server(&storage).await?;

    // Install the build-selected rustls provider (idempotent).
    if !openstack_keystone_tls_provider::install_default() {
        tracing::warn!(
            "Failed to install the {} crypto provider",
            openstack_keystone_tls_provider::PROVIDER_NAME
        );
    }

    let grpc_addr = ds.node_listener_addr;

    match &ds.tls_configuration {
        RaftTlsConfiguration::Spiffe(spiffe_cfg) => {
            let trust_domains = spiffe_cfg.trust_domains.clone();
            let allowed_peer_svids = spiffe_cfg.allowed_peer_svids.clone();
            let spiffe_path_prefix = spiffe_cfg.spiffe_path_prefix.clone();

            // This node's own storage identity: the first `allowed_peer_svids`
            // entry (the identity every peer requires of this node in a
            // homogeneous cluster) or the `<spiffe_path_prefix>node`
            // registration convention. Pinning it keeps the listener from
            // presenting some other SVID the process also holds.
            let own_svid_path = spiffe_cfg.own_svid_path();

            let server_config = match spiffe_common::build_spiffe_config(
                cancel_token.clone(),
                trust_domains.clone(),
                Some(&own_svid_path),
            )
            .await?
            {
                Some(cfg) => cfg,
                None => return Ok(()),
            };

            let acceptor = TlsAcceptor::from(server_config);
            let listener = TcpListener::bind(grpc_addr).await?;

            let interceptor = SpiffeIdInterceptor {
                authz: Arc::new(PeerAuthz::spiffe(
                    trust_domains,
                    spiffe_path_prefix,
                    spiffe_cfg.operator_role.clone(),
                    allowed_peer_svids,
                )),
            };

            let mut server = tonic::transport::Server::builder()
                .http2_keepalive_interval(Some(PEER_KEEPALIVE))
                .http2_keepalive_timeout(Some(PEER_KEEPALIVE))
                .layer(InterceptorLayer::new(interceptor));
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
                        // Avoid Nagle + delayed ACK stalls (~40ms) on small
                        // RPC responses.
                        tcp.set_nodelay(true)?;
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
            let mut server = tonic::transport::Server::builder()
                .http2_keepalive_interval(Some(PEER_KEEPALIVE))
                .http2_keepalive_timeout(Some(PEER_KEEPALIVE))
                .tls_config(get_server_tls_config(ds)?)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::grpc::authz::PeerRole;
    use rcgen::{CertificateParams, DistinguishedName, SanType};

    fn authz(trust_domains: &[&str], prefix: &str, allowed: &[&str]) -> PeerAuthz {
        PeerAuthz::spiffe(
            trust_domains.iter().map(|s| s.to_string()).collect(),
            prefix.to_string(),
            "storage-operator".into(),
            allowed.iter().map(|s| s.to_string()).collect(),
        )
    }

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
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let cert = generate_spiffe_cert("example.org", "/keystone/storage/node");
        let certs = Some(Arc::new(vec![cert]));
        assert_eq!(validate_spiffe_id(certs, &a).unwrap(), PeerRole::Node);
    }

    #[test]
    fn test_spiffe_id_unauthorized_trust_domain() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let cert = generate_spiffe_cert("evil.org", "/keystone/storage/node");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("evil.org"));
    }

    #[test]
    fn test_spiffe_id_custom_prefix_configured() {
        // A cluster that sets a non-default `spiffe_path_prefix` must have it
        // enforced here, not the `/keystone/storage/` literal.
        let a = authz(&["example.org"], "/custom/raft/", &[]);
        let cert = generate_spiffe_cert("example.org", "/custom/raft/node");
        let certs = Some(Arc::new(vec![cert]));
        assert!(validate_spiffe_id(certs, &a).is_ok());
    }

    #[test]
    fn test_spiffe_id_default_prefix_rejected_when_custom_configured() {
        let a = authz(&["example.org"], "/custom/raft/", &[]);
        let cert = generate_spiffe_cert("example.org", "/keystone/storage/node");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("has no authorised storage role"));
    }

    #[test]
    fn test_spiffe_id_invalid_path() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let cert = generate_spiffe_cert("example.org", "/admin/delete");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("has no authorised storage role"));
    }

    #[test]
    fn test_spiffe_id_standard_spire_path_rejected_without_allow_list() {
        // The `/ns/<ns>/sa/<sa>` fallback no longer exists.
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let cert = generate_spiffe_cert("example.org", "/ns/default/sa/keystone");
        let certs = Some(Arc::new(vec![cert]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("has no authorised storage role"));
    }

    #[test]
    fn test_spiffe_id_standard_spire_path_accepted_when_listed() {
        let a = authz(
            &["example.org"],
            "/keystone/storage/",
            &["spiffe://example.org/ns/default/sa/keystone"],
        );
        let cert = generate_spiffe_cert("example.org", "/ns/default/sa/keystone");
        let certs = Some(Arc::new(vec![cert]));
        assert_eq!(validate_spiffe_id(certs, &a).unwrap(), PeerRole::Node);
    }

    #[test]
    fn test_spiffe_id_operator_accepted_and_resolves_operator() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let cert = generate_spiffe_cert("example.org", "/keystone/storage/storage-operator");
        let certs = Some(Arc::new(vec![cert]));
        assert_eq!(validate_spiffe_id(certs, &a).unwrap(), PeerRole::Operator);
    }

    #[test]
    fn test_spiffe_id_no_certs() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let err = validate_spiffe_id(None, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("no peer certificate"));
    }

    #[test]
    fn test_spiffe_id_empty_chain() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let certs = Some(Arc::new(vec![]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("empty certificate chain"));
    }

    #[test]
    fn test_spiffe_id_invalid_cert() {
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let certs = Some(Arc::new(vec![rustls::pki_types::CertificateDer::from(
            vec![0x00, 0x01],
        )]));
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Invalid SPIFFE ID"));
    }

    #[test]
    fn test_spiffe_id_svid_in_force_renewal_window() {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType, date_time_ymd};

        // Build a cert whose not_after is in the past (expired / force-renewal
        // window).
        let spiffe_uri = "spiffe://example.org/keystone/storage/node"
            .try_into()
            .unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(spiffe_uri)];
        // not_before < not_after but both in the past → expired.
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap().der().clone();
        let certs = Some(Arc::new(vec![cert]));
        let a = authz(&["example.org"], "/keystone/storage/", &[]);
        let err = validate_spiffe_id(certs, &a).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message().contains("expired") || err.message().contains("force-renewal"),
            "unexpected error: {}",
            err.message()
        );
    }

    #[test]
    fn test_spiffe_id_multiple_trust_domains() {
        let a = authz(&["example.org", "example.net"], "/keystone/storage/", &[]);
        let cert_1 = generate_spiffe_cert("example.org", "/keystone/storage/node");
        let cert_2 = generate_spiffe_cert("example.net", "/keystone/storage/node");

        assert!(validate_spiffe_id(Some(Arc::new(vec![cert_1])), &a).is_ok());
        assert!(validate_spiffe_id(Some(Arc::new(vec![cert_2])), &a).is_ok());
    }
}
