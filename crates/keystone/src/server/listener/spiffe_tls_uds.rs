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
//! # Unix socket listener with SPIFFE integration

use std::path::Path;

use axum::Router;
use color_eyre::eyre::{Report, Result};
use eyre::Context;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use openstack_keystone_core::common::SpiffeId as CoreSpiffeId;
use spiffe::cert::spiffe_id_from_der;
use tokio::fs;
use tokio::net::UnixListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::info;

use crate::config::Interface;
use crate::server::listener::spiffe_common;

/// Verify peer credentials obtained via SO_PEERCRED against expected UID/GID.
///
/// Returns `Ok(())` when all configured checks pass, or `Err` if any configured
/// value does not match the connecting process's credentials.
fn verify_peer_credentials(
    stream: &tokio::net::UnixStream,
    expected_uid: Option<u32>,
    expected_gid: Option<u32>,
) -> Result<(), Report> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let creds = getsockopt(&stream, PeerCredentials)
        .wrap_err("failed to get peer credentials via SO_PEERCRED")?;

    if let Some(expected) = expected_uid
        && creds.uid() != expected
    {
        return Err(color_eyre::eyre::eyre!(
            "UDS peer UID {} does not match expected {}",
            creds.uid(),
            expected
        ));
    }
    if let Some(expected) = expected_gid
        && creds.gid() != expected
    {
        return Err(color_eyre::eyre::eyre!(
            "UDS peer GID {} does not match expected {}",
            creds.gid(),
            expected
        ));
    }
    Ok(())
}

/// Start the Axum REST api over the Unix Socket with the SPIFFE mTLS enabled.
///
/// The TLS server is started requesting the client certificates verified using
/// the SPIFFE workload API. Socket peer credentials (SO_PEERCRED) are validated
/// before the TLS handshake when `peer_uid` or `peer_gid` are configured.
pub async fn start_axum_app(
    socket_path: &Path,
    app: Router,
    token: CancellationToken,
    trust_domains: Vec<String>,
    interface: Interface,
    peer_uid: Option<u32>,
    peer_gid: Option<u32>,
) -> Result<(), Report> {
    let spiffe_server_config =
        match spiffe_common::build_spiffe_config(token.clone(), trust_domains).await? {
            Some(config) => config,
            None => return Ok(()),
        };

    let acceptor = TlsAcceptor::from(spiffe_server_config);

    info!("Starting Admin API at {:?} with SPIFFE mTLS", socket_path);
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(&parent).await.wrap_err_with(|| {
            format!(
                "creating parent directory {:?} for the UDS socket",
                socket_path
            )
        })?;
    }
    tokio::fs::remove_file(&socket_path).await.ok();
    let listener = UnixListener::bind(socket_path)?;
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            Ok((stream, _peer_addr)) = listener.accept() => {
                // SO_PEERCRED validation BEFORE TLS wrap (cheap kernel-level check)
                if let Err(e) = verify_peer_credentials(&stream, peer_uid, peer_gid) {
                    tracing::warn!("UDS connection rejected: peer credential mismatch: {}", e);
                    continue;
                }

                let acceptor = acceptor.clone();
                let app = app.clone();
                let conn_token = token.clone();
                let interface_clone = interface.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let (_, connection) = tls_stream.get_ref();
                            let spiffe_id: Option<CoreSpiffeId> = connection
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .map(|leaf| spiffe_id_from_der(leaf))
                                .transpose()
                                .unwrap_or_default()
                                .and_then(|s| {
                                    let id = CoreSpiffeId::new(&s.to_string());
                                    if id.is_none() {
                                        tracing::warn!("peer presented a SPIFFE certificate with an unparsable SVID '{}'; dropping identity", s);
                                    }
                                    id
                                });

                            let hyper_service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let mut app = app.clone();
                                let spiffe_id = spiffe_id.clone();
                                let interface_clone = interface_clone.clone();
                                async move {
                                    let mut req = req;
                                    if let Some(spiffe_id) = spiffe_id {
                                        // Move the client TLS certificate into the request extensions
                                        tracing::debug!("The client supplied certificate for spiffe_id: {:?}", spiffe_id);

                                        req.extensions_mut().insert(spiffe_id);
                                    }
                                    req.extensions_mut().insert(interface_clone);
                                    // Call Axum and explicitly wrap the result
                                    app.call(req).await
                                }
                            });

                            let builder = Builder::new(TokioExecutor::new());
                            let conn = builder.serve_connection(TokioIo::new(tls_stream), hyper_service);

                            // Pinning is required for select! on hyper futures
                            tokio::pin!(conn);

                            tokio::select! {
                                res = &mut conn => {
                                    // Normal completion
                                    if let Err(err) = res {
                                        tracing::debug!("TLS connection error: {:?}", err);
                                    }
                                },
                                _ = conn_token.cancelled() => {
                                    // Signal hyper to stop accepting new requests on this keep-alive connection
                                    tracing::debug!("received shutdown in the TLS serve loop");
                                    conn.as_mut().graceful_shutdown();
                                    // Wait for the current request to finish
                                    let _ = conn.await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("TLS handshake failed for socket connection: {}", e);
                        }
                    }
                });
            }
        }
    }

    fs::remove_file(&socket_path).await.ok();
    Ok(())
}
