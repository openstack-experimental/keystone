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
//! # TLS server listener with the SPIFFE integration

use axum::Router;
use axum::extract::ConnectInfo;
use color_eyre::eyre::{Report, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::info;

use openstack_keystone_core::common::SpiffeId as CoreSpiffeId;

use crate::config::Interface;
use crate::server::listener::spiffe_common;

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
    let spiffe_server_config =
        match spiffe_common::build_spiffe_config(token.clone(), trust_domains).await? {
            Some(config) => config,
            None => return Ok(()),
        };

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
                            let spiffe_id = peer_identity.spiffe_id().and_then(|s| {
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
                                    attach_request_context(
                                        req.extensions_mut(),
                                        spiffe_id,
                                        peer_addr,
                                        interface_clone,
                                    );
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
                            tracing::warn!("TLS handshake failed for {}: {}", peer_addr, e);
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

/// Attach the per-request context derived from an mTLS connection onto the
/// request extensions before it is handed to the axum app.
///
/// Because `hyper::service::service_fn` bypasses axum's make-service, the
/// context the public HTTP path gets for free must be injected by hand here:
///   * the peer's validated [`CoreSpiffeId`], when present;
///   * the raw TCP peer address in the same [`ConnectInfo<SocketAddr>`]
///     extension the public listener populates via
///     `into_make_service_with_connect_info` (issue #358), so `client.addr` is
///     captured on the internal interface too;
///   * the [`Interface`] the request arrived on.
fn attach_request_context(
    extensions: &mut axum::http::Extensions,
    spiffe_id: Option<CoreSpiffeId>,
    peer_addr: std::net::SocketAddr,
    interface: Interface,
) {
    if let Some(spiffe_id) = spiffe_id {
        // Move the client TLS certificate into the request extensions
        tracing::debug!(
            "The client supplied certificate for spiffe_id: {:?}",
            spiffe_id
        );
        extensions.insert(spiffe_id);
    }
    extensions.insert(ConnectInfo(peer_addr));
    extensions.insert(interface);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attaches_connect_info_and_interface_without_spiffe_id() {
        let mut ext = axum::http::Extensions::new();
        let peer: std::net::SocketAddr = "203.0.113.7:4711".parse().unwrap();

        attach_request_context(&mut ext, None, peer, Interface::Internal);

        // Issue #358: the mTLS peer address is captured in the same extension
        // type the public listener uses, so `client.addr` is populated here.
        assert_eq!(
            ext.get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0),
            Some(peer)
        );
        assert_eq!(ext.get::<Interface>(), Some(&Interface::Internal));
        // No SVID presented → no SpiffeId extension.
        assert!(ext.get::<CoreSpiffeId>().is_none());
    }

    #[test]
    fn attaches_spiffe_id_when_present() {
        let mut ext = axum::http::Extensions::new();
        let peer: std::net::SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
        let spiffe_id = CoreSpiffeId::new("spiffe://example.org/workload").unwrap();

        attach_request_context(&mut ext, Some(spiffe_id.clone()), peer, Interface::Internal);

        assert_eq!(ext.get::<CoreSpiffeId>(), Some(&spiffe_id));
        assert_eq!(
            ext.get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0),
            Some(peer)
        );
    }
}
