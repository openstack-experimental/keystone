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
use std::collections::HashMap;
use std::sync::Arc;

use color_eyre::eyre::{Report, Result};
use openstack_keystone_config::RaftTlsConfiguration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tonic::service::InterceptorLayer;
use tracing::info;

use openstack_keystone_distributed_storage::{
    app::{Storage, get_app_server},
    network::get_server_tls_config,
};

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::server::listener::spiffe_common;

/// gRPC interceptor that enforces SPIFFE mTLS identity on Raft connections.
///
/// Every inbound gRPC request must carry a peer certificate whose SPIFFE ID
/// matches the pattern `spiffe://<trust_domain>/keystone/storage/<role>` for
/// one of the configured trust domains (ADR 0016-v2 §4.1).
#[derive(Clone)]
struct SpiffeIdInterceptor {
    trust_domains: Arc<Vec<String>>,
}

impl tonic::service::Interceptor for SpiffeIdInterceptor {
    fn call(
        &mut self,
        req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        use spiffe::cert::spiffe_id_from_der;

        let certs = req
            .peer_certs()
            .ok_or_else(|| tonic::Status::permission_denied("mTLS required: no peer certificate"))?;

        let leaf = certs.first().ok_or_else(|| {
            tonic::Status::permission_denied("mTLS required: empty certificate chain")
        })?;

        let spiffe_id = spiffe_id_from_der(leaf.as_ref()).map_err(|e| {
            tonic::Status::permission_denied(format!(
                "Invalid SPIFFE ID in peer certificate: {e}"
            ))
        })?;

        let td_name = spiffe_id.trust_domain_name();
        if !self.trust_domains.iter().any(|td| td == td_name) {
            return Err(tonic::Status::permission_denied(format!(
                "SPIFFE trust domain {td_name:?} is not in the allowed list"
            )));
        }

        if !spiffe_id.path().starts_with("/keystone/storage/") {
            return Err(tonic::Status::permission_denied(format!(
                "SPIFFE ID path {:?} does not match /keystone/storage/<role>",
                spiffe_id.path()
            )));
        }

        Ok(req)
    }
}

/// Start Raft backed distributed storage.
pub async fn start_raft_app(
    storage: Arc<Storage>,
    config: Config,
    cancel_token: CancellationToken,
) -> Result<(), Report> {
    let Some(ds) = &config.distributed_storage else {
        return Ok(());
    };

    let storage_app = get_app_server(&storage).await?;

    // Install aws-lc-rs as the default rustls provider (idempotent).
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let grpc_addr = ds.node_listener_addr;

    match &ds.tls_configuration {
        RaftTlsConfiguration::Spiffe(spiffe_cfg) => {
            let trust_domains = spiffe_cfg.trust_domains.clone();

            let server_config =
                match spiffe_common::build_spiffe_config(cancel_token.clone(), trust_domains.clone())
                    .await?
                {
                    Some(cfg) => cfg,
                    None => return Ok(()),
                };

            let acceptor = TlsAcceptor::from(server_config);
            let listener = TcpListener::bind(grpc_addr).await?;

            let interceptor = SpiffeIdInterceptor {
                trust_domains: Arc::new(trust_domains),
            };

            let mut server = tonic::transport::Server::builder()
                .layer(InterceptorLayer::new(interceptor));
            let tonic_router = server.add_routes(storage_app);

            info!(
                "Starting distributed storage at {:?} with SPIFFE mTLS",
                grpc_addr
            );

            // Build a stream of pre-TLS-wrapped connections.  TLS handshake
            // failures are logged and skipped; TCP accept errors terminate the
            // stream and surface to tonic as a transient error.
            let incoming = futures_util::stream::try_unfold(
                (listener, acceptor),
                |(listener, acceptor)| async move {
                    loop {
                        let (tcp, _) = listener.accept().await?;
                        match acceptor.accept(tcp).await {
                            Ok(tls) => {
                                return Ok::<_, std::io::Error>(Some((tls, (listener, acceptor))));
                            }
                            Err(e) => tracing::warn!("Raft gRPC TLS handshake failed: {e}"),
                        }
                    }
                },
            );

            tonic_router
                .serve_with_incoming_shutdown(incoming, async move {
                    cancel_token.cancelled().await;
                })
                .await?;
        }

        RaftTlsConfiguration::Tls(_) => {
            let mut server = tonic::transport::Server::builder()
                .tls_config(get_server_tls_config(&config)?)?;
            let tonic_router = server.add_routes(storage_app);

            info!("Starting distributed storage at {:?}", grpc_addr);

            tonic_router
                .serve_with_shutdown(grpc_addr, async move {
                    cancel_token.cancelled().await;
                })
                .await?;
        }
    }

    Ok(())
}

/// Ensure Raft cluster is initialized with at least the current node.
pub async fn ensure_raft_initialized(state: ServiceState, config: Config) -> Result<(), Report> {
    if let Some(ds) = &config.distributed_storage
        && let Some(storage) = state.storage.as_deref()
        && !storage.is_initialized().await?
        && ds.node_id == 0
        && let (Some(host), Some(port)) = (ds.node_cluster_addr.host(), ds.node_cluster_addr.port())
    {
        info!("Initializing the integrated storage since it is not initialized.");
        storage
            .initialize(HashMap::from([(
                0,
                openstack_keystone_storage_api::Node {
                    node_id: 0,
                    rpc_addr: format!("{host}:{port}"),
                },
            )]))
            .await?;
    }
    Ok(())
}
