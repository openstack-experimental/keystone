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
use color_eyre::eyre::{OptionExt, Report, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::signal;
//use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use secrecy::ExposeSecret;
use spiffe_rustls::{authorizer, mtls_server};
use tokio::net::TcpListener;
//use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
//use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tower::Service;
//use tower::ServiceBuilder;
use tracing::info;

use openstack_keystone_core::api::auth::RawClientCertificate;

use crate::config::Config;
//use crate::keystone::ServiceState;

#[derive(Debug)]
pub struct KeystoneVerifier;

impl ClientCertVerifier for KeystoneVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    // We return empty hints to keep the handshake small
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // In a dynamic system, we accept the cert at the handshake level.
        // The middleware will perform the actual CA-validation against
        // the database-backed root certificates.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

/// Start the Axum REST api with the permissive mTLS enabled.
///
/// The TLS server is started requesting the client certificates, but not
/// requiring them. When a certificate is present (on a Transport layer) it is
/// passed as an extension to the regular authentication extractor (application
/// layer) where it can be checked against a DB backed list of CAs.
pub async fn start_rest_api_with_mtls(
    addr: std::net::SocketAddr,
    app: Router,
    config: Config,
    //shared_state: ServiceState,
    token: CancellationToken,
) -> Result<(), Report> {
    //let cert_file = "";
    // config
    //     .distributed_storage
    //     .as_ref()
    //     .and_then(|ds| ds.tls_configuration.tls_cert_file.clone())
    //     .ok_or_else(|| {
    //         color_eyre::eyre::eyre!("TLS certificate file not configured for REST
    // API")     })?;

    //let key_file = "";
    // config
    //     .distributed_storage
    //     .as_ref()
    //     .and_then(|ds| ds.tls_configuration.tls_key_file.clone())
    //     .ok_or_else(|| color_eyre::eyre::eyre!("TLS key file not configured for
    // REST API"))?;

    //let config = axum_server::rustls::RustlsConfig::from_pem_file(cert_file,
    // key_file)    .await
    //    .wrap_err("Failed to load TLS config")?;

    // 1. CONFIGURE TLS: This is the "Request but not Require" magic
    if let Some(tls_config) = config.listener.tls_configuration {
        // spiffe
        // TODO: the SPIFFE_ENDPOINT_SOCKET env must be set and start with unix:///tmp/....
        // TODO: do not start SPIFFE when env is not set - raise error or switch to normal TLS
        // Establish connection to SPIFFE is a blocking operation. Operator may want to abort the
        // process when such connection hangs, so we need to have a dedicated signal handling.
        let source = tokio::select! {
            res = spiffe::X509Source::new() => {res?}
            _ = signal::ctrl_c() => {
                tracing::info!("Ctrl+C signal received while waiting for the SPIFFE communication");
                return Ok(())
            }
        };
        let spiffe_server_config = Arc::new(
            mtls_server(source)
                .authorize(authorizer::trust_domains(["example.org"])?)
                .build()?,
        );

        // non-spiffe
        let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(
            tls_config
                .tls_cert_content
                .as_ref()
                .ok_or_eyre("TLS certificate is missing")?
                .expose_secret(),
        )
        //.unwrap()
        .collect::<Result<Vec<_>, _>>()?;

        // 2. Load the Private Key
        let key = PrivateKeyDer::from_pem_slice(
            tls_config
                .tls_key_content
                .ok_or_eyre("TLS key is missing")?
                .expose_secret(),
        )
        .unwrap();

        //let mut roots = rustls::RootCertStore::empty();
        //let ca_certs: Vec<CertificateDer> = //vec![CertificateDer::from_pem_slice("".as_bytes()).unwrap()];
        //Cert//ificateDer::pem_file_iter("/etc/keystone/keystone.crt")
        //.unwrap()
        //.collect::<Result<Vec<_>, _>>()?;
        //roots
        //.add_parsable_certificates(certs.clone()) //rustls_webpki::anchor_from_trusted_cert().unwrap())
        //;
        //let client_verifier = WebPkiClientVerifier::builder(roots.into())
        //    .allow_unauthenticated() // <--- CRITICAL: Handshake succeeds even without cert
        //    .build()
        //    .unwrap();

        let tls_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(KeystoneVerifier))
                .with_single_cert(certs, key)
                .unwrap(),
        );

        let acceptor = TlsAcceptor::from(spiffe_server_config);
        //let rustls_config =
        // axum_server::tls_rustls::RustlsConfig::from_config(server_config.into());
        //.with_no_client_auth();
        //.with_safe_default_protocol_versions()
        //.unwrap();

        info!("Starting Rest API at {:?} with optional mTLS", addr);
        //bind_rustls(addr, rustls_config)
        //    .handle(shared_state.server_handle)
        //    .serve(app.into_make_service())
        //    //.with_graceful_shutdown(shutdown_signal(shared_state))
        //    .await
        //    .map_err(|e| color_eyre::eyre::eyre!("Server error: {e}"))?;
        let listener = TcpListener::bind(&config.listener.tcp_address).await?;
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                Ok((stream, peer_addr)) = listener.accept() => {
                    let acceptor = acceptor.clone();
                    let app = app.clone();
                    let conn_token = token.clone();

                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::info!("TLS Handshake failed for {}: {}", peer_addr, e);
                                return;
                            }
                        };

                        // Extract peer certificates from the TLS session
                        let (_, session) = tls_stream.get_ref();
                        let peer_certs = session.peer_certificates().map(|c| c.to_vec());

                        let hyper_service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut app = app.clone();
                            let certs = peer_certs.clone();
                            async move {
                                let mut req = req;
                                if let Some(chain) = certs {
                                    // Move the client TLS certificate into the request extensions
                                    tracing::debug!("The client supplied certificates: {:?}", chain);
                                    req.extensions_mut().insert(RawClientCertificate(chain));
                                }
                                // Call Axum and explicitly wrap the result
                                app.call(req).await
                                //let res = app.call(req).await.unwrap();

                                //// Use the turbofish operator to satisfy the Result<Response, Error> bound
                                //Ok::<_, std::convert::Infallible>(res)
                            }
                        });

                        let builder = Builder::new(TokioExecutor::new());
                        let conn = builder.serve_connection(TokioIo::new(tls_stream), hyper_service);

                        // Pinning is often required for select! on hyper futures
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
                    });
                }
            }
        }
    }

    Ok(())
}
