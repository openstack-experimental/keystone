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
//! Main Keystone executable.
//!
//! This is the entry point of the `keystone` binary.

use std::sync::Arc;

use axum::Router;
use color_eyre::eyre::{Report, Result, eyre};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use spiffe_rustls::{authorizer, mtls_server};
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::info;

use crate::config::Interface;

/// Start the Axum REST api with the SPIFFE mTLS enabled.
///
/// The TLS server is started requesting the client certificates verified using
/// the SPIFFE workload API.
pub async fn start_axum_app(
    addr: std::net::SocketAddr,
    app: Router,
    token: CancellationToken,
    trust_domains: Vec<String>,
    interface: Interface,
) -> Result<(), Report> {
    // Establish connection to SPIFFE is a blocking operation. Operator may want to
    // abort the process when such connection hangs, so we need to have a
    // dedicated signal handling.
    match std::env::var("SPIFFE_ENDPOINT_SOCKET") {
        Ok(val) => {
            if !val.starts_with("unix:///") {
                return Err(eyre!(
                    "Variable 'SPIFFE_ENDPOINT_SOCKET' must start with `unix:///` for SPIFFE integration"
                ));
            }
        }
        Err(_) => {
            return Err(eyre!(
                "Variable 'SPIFFE_ENDPOINT_SOCKET' must be set for SPIFFE supported mTLS"
            ));
        }
    }
    let source = tokio::select! {
        res = spiffe::X509Source::new() => {res?}
        _ = token.cancelled() => {
            tracing::info!("Ctrl+C signal received while waiting for the SPIFFE communication");
            return Ok(())
        }
    };
    let spiffe_server_config = Arc::new(
        mtls_server(source)
            .authorize(authorizer::trust_domains(trust_domains)?)
            .build()?,
    );

    let acceptor = TlsAcceptor::from(spiffe_server_config);

    info!("Starting Rest API at {:?} with SPIFFE mTLS", addr);
    let listener = TcpListener::bind(&addr).await?;
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            Ok((stream, peer_addr)) = listener.accept() => {
                let acceptor = acceptor.clone();
                let app = app.clone();
                let conn_token = token.clone();
                let interface_clone = interface.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok((tls_stream, peer_identity)) => {

                            let hyper_service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let mut app = app.clone();
                                let spiffe_id = peer_identity.spiffe_id().cloned();
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
                                    //let res = app.call(req).await.unwrap();

                                    //// Use the turbofish operator to satisfy the Result<Response, Error> bound
                                    //Ok::<_, std::convert::Infallible>(res)
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
                                        eprintln!("Connection error: {:?}", err);
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
                            tracing::info!("TLS Handshake failed for {}: {}", peer_addr, e);
                            return;
                        }
                    }
                });
            }
        }
    }

    Ok(())
}
