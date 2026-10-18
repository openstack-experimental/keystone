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
//! HTTP client for the internal SPIFFE mTLS listener of the live API harness.
//!
//! The harness SPIRE agent (`tools/start-spire.sh`) hands every workload of
//! the current uid all of the registered test SVIDs; [`post_form`] picks the
//! one to present by its SPIFFE ID.

use std::sync::Arc;

use eyre::{Result, eyre};
use hyper_util::rt::TokioIo;
use reqwest::StatusCode;
use serde_json::Value;
use spiffe::X509Svid;
use spiffe::x509_source::SvidPicker;
use spiffe::{TrustDomain, X509SourceBuilder};
use spiffe_rustls::{authorizer, mtls_client};
use spiffe_rustls_tokio::TlsConnector;
use tokio::net::TcpStream;

/// SPIRE agent Workload API socket of the harness.
const AGENT_SOCKET: &str = "unix:///tmp/spire-ci-test-harness/agent.sock";
/// `[interface_internal]` address of the harness keystone.
const INTERNAL_ADDR: &str = "127.0.0.1:8215";
/// Trust domain of the harness.
const TRUST_DOMAIN: &str = "example.org";

/// Pick the SVID with the given SPIFFE ID.
#[derive(Debug)]
struct IdPicker(String);

impl SvidPicker for IdPicker {
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
        svids
            .iter()
            .position(|svid| svid.spiffe_id().to_string() == self.0)
    }
}

/// `POST path` with a form `body` to the internal interface, presenting the
/// X.509-SVID `svid_id` in the mTLS handshake. Returns the status and the
/// JSON body (`Null` when it is not JSON).
pub async fn post_form(
    svid_id: &str,
    path: &str,
    body: &[(&str, &str)],
) -> Result<(StatusCode, Value)> {
    let source = X509SourceBuilder::new()
        .endpoint(AGENT_SOCKET)
        .picker(IdPicker(svid_id.to_string()))
        .build()
        .await
        .map_err(|e| eyre!("no SVID `{svid_id}` from the SPIRE agent: {e}"))?;

    let config = mtls_client(source)
        .authorize(authorizer::trust_domains([
            TRUST_DOMAIN.parse::<TrustDomain>()?
        ])?)
        .build()
        .map_err(|e| eyre!("mTLS client config: {e}"))?;
    let connector = TlsConnector::new(Arc::new(config));

    let tcp = TcpStream::connect(INTERNAL_ADDR).await?;
    // SPIFFE authenticates the peer by ID; the name is only for rustls.
    let server_name = rustls::pki_types::ServerName::try_from("keystone")?;
    let (tls, _peer) = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| eyre!("mTLS handshake with the internal interface: {e}"))?;

    let (mut send, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let form = serde_urlencoded::to_string(body)?;
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", INTERNAL_ADDR)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(http_body_util::Full::new(bytes::Bytes::from(form)))?;
    let rsp = send.send_request(request).await?;
    let status = rsp.status();
    let bytes = http_body_util::BodyExt::collect(rsp.into_body())
        .await?
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, json))
}
