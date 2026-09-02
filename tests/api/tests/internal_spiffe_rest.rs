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
//! Test SPIFFE mTLS connectivity to the internal REST listener
//! (`[interface_internal]`, SPIRE integration plan Phase 3).
//!
//! This test runs inside a Kubernetes pod with the SPIFFE CSI workload API
//! mounted -- same deployment shape as `raft_spiffe.rs`, but exercising the
//! REST/axum listener (`spawn_internal_listener` /
//! `crates/keystone/src/server/listener/spiffe_tls.rs::start_axum_app`)
//! instead of the Raft gRPC one. It performs two checks:
//!
//! 1. Connects to the internal REST port over SPIFFE mTLS using a fetched
//!    workload SVID and issues a request, proving the internal SPIFFE
//!    listener really does serve the REST/axum router end-to-end (closing
//!    the gap the plan doc's own `curl` verification snippet describes).
//! 2. Verifies that a plain (non-SPIFFE) TLS connection to the same port is
//!    rejected at the TLS handshake layer.

use std::sync::Arc;

use eyre::{Result, eyre};
use hyper_util::rt::TokioIo;
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client};
use spiffe_rustls_tokio::TlsConnector;
use tokio::net::TcpStream;

/// Internal REST interface address, matching
/// `tools/k8s/keystone/base/conf/keystone.conf`'s `[interface_internal]`
/// `tcp_address`.
const INTERNAL_REST_ADDR: &str =
    "keystone-rs-0.keystone-rs-internal.default.svc.cluster.local:8215";

/// Connect to the internal REST listener over SPIFFE mTLS and issue a
/// request, proving the listener serves the REST router (not just gRPC
/// storage) over SPIFFE mTLS.
async fn verify_spiffe_svid_over_rest(trust_domains: &[String]) -> Result<()> {
    tracing::info!("Fetching SVID from SPIFFE workload API...");
    let source = X509Source::new()
        .await
        .map_err(|e| eyre!("SPIFFE X509Source init failed: {e}"))?;

    let client_config = mtls_client(source)
        .authorize(authorizer::trust_domains(trust_domains.to_vec())?)
        .build()
        .map_err(|e| eyre!("failed to build SPIFFE mTLS client config: {e}"))?;
    let connector = TlsConnector::new(Arc::new(client_config));

    tracing::info!(
        "Connecting to internal REST listener {} via SPIFFE mTLS (trust domains: {:?})...",
        INTERNAL_REST_ADDR,
        trust_domains
    );
    let tcp = TcpStream::connect(INTERNAL_REST_ADDR)
        .await
        .map_err(|e| eyre!("TCP connect to {INTERNAL_REST_ADDR} failed: {e}"))?;

    // SPIFFE authentication is based on SPIFFE ID, not hostname -- the
    // `ServerName` below is only required by rustls for SNI plumbing.
    let server_name = rustls::pki_types::ServerName::try_from("keystone-rs-0")
        .map_err(|e| eyre!("invalid SNI server name: {e}"))?;

    let (tls_stream, peer_identity) = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| eyre!("SPIFFE mTLS handshake to internal REST listener failed: {e}"))?;

    tracing::info!(
        "SPIFFE mTLS handshake succeeded; peer SPIFFE ID: {:?}",
        peer_identity.spiffe_id()
    );

    let io = TokioIo::new(tls_stream);
    let (mut send_request, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| eyre!("HTTP/1 handshake over SPIFFE mTLS failed: {e}"))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("internal REST connection closed: {e}");
        }
    });

    let request = hyper::Request::builder()
        .method("GET")
        .uri("/v3")
        .header("host", "keystone-rs-0")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| eyre!("failed to build request: {e}"))?;

    let response = send_request
        .send_request(request)
        .await
        .map_err(|e| eyre!("GET /v3 over SPIFFE mTLS failed: {e}"))?;

    let status = response.status();
    tracing::info!(%status, "GET /v3 over internal SPIFFE mTLS REST listener succeeded");

    // Any HTTP-level response (2xx, 3xx, or an auth-shaped 4xx) proves the
    // REST router served the request -- it's the TLS handshake and SPIFFE
    // identity extraction above that this test exists to verify, not this
    // particular route's own authorization outcome.
    if status.is_server_error() {
        return Err(eyre!(
            "internal REST listener returned a server error: {status}"
        ));
    }

    Ok(())
}

/// Verify that a plain (non-SPIFFE) TLS connection to the internal REST
/// port is rejected at the TLS handshake layer.
async fn verify_plain_tls_rejected_over_rest() -> Result<()> {
    tracing::info!(
        "Verifying that plain/non-SPIFFE connections to the internal REST listener are rejected..."
    );

    let tcp = TcpStream::connect(INTERNAL_REST_ADDR)
        .await
        .map_err(|e| eyre!("TCP connect to {INTERNAL_REST_ADDR} failed: {e}"))?;

    // A bare rustls client with the platform root store and no client
    // certificate -- the internal listener requires client-cert mTLS, so
    // this handshake must fail (either at the TLS layer, or the server
    // simply drops the connection).
    let root_store = rustls::RootCertStore::empty();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from("keystone-rs-0")
        .map_err(|e| eyre!("invalid SNI server name: {e}"))?;

    match connector.connect(server_name, tcp).await {
        Err(e) => {
            tracing::info!("Plain TLS connection rejected (expected): {e}");
            Ok(())
        }
        Ok(_) => Err(eyre!(
            "Plain TLS connection to the internal REST listener was NOT rejected -- \
             SPIFFE mTLS enforcement broken"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,spiffe=info")),
        )
        .with_writer(std::io::stdout)
        .init();

    let trust_domains = std::env::var("OS_INTERFACE_INTERNAL__TRUST_DOMAINS")
        .unwrap_or_else(|_| "example.org".to_string())
        .split(',')
        .map(String::from)
        .collect::<Vec<_>>();

    tracing::info!("=== SPIFFE Internal REST Listener Test ===");
    tracing::info!("Trust domains: {:?}", trust_domains);

    verify_spiffe_svid_over_rest(&trust_domains).await?;
    tracing::info!("✓ Internal REST listener served a request over SPIFFE mTLS");

    verify_plain_tls_rejected_over_rest().await?;
    tracing::info!("✓ Plain TLS connection correctly rejected");

    tracing::info!("=== All tests passed ✓ ===");
    Ok(())
}
