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
//! # SPIFFE shared initialization
//!
//! Shared SPIFFE configuration setup used by both TCP and Unix socket
//! listeners.

use std::sync::Arc;

use color_eyre::eyre::{Report, Result, eyre};
use rustls::ServerConfig;
use spiffe::X509Svid;
use spiffe::x509_source::SvidPicker;
use spiffe_rustls::{authorizer, mtls_server};
use tokio_util::sync::CancellationToken;

/// Selects the SVID whose SPIFFE ID path exactly matches a configured value.
///
/// The Workload API returns every SVID a workload's selectors match (e.g. a
/// devstack process registered under both `/service/keystone` and
/// `/keystone/storage/node` via the same `unix:uid` selector). Without a
/// picker, `X509Source` presents index 0 of that list ("the default SVID"),
/// which is whichever entry the SPIRE server happened to return first -- not
/// necessarily the identity this listener/client is meant to present. Pinning
/// by exact path keeps e.g. the raft gRPC listener from ever presenting the
/// plain `/service/keystone` identity (or vice versa).
#[derive(Debug)]
struct PathSvidPicker {
    path: String,
}

impl SvidPicker for PathSvidPicker {
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
        svids
            .iter()
            .position(|svid| svid.spiffe_id().path() == self.path)
    }
}

/// Build the SPIFFE mTLS server configuration.
///
/// Validates the `SPIFFE_ENDPOINT_SOCKET` environment variable, establishes the
/// SPIFFE `X509Source`, and constructs a `ServerConfig` authorized for the
/// given trust domains. When `spiffe_id_path` is set it pins which SVID the
/// source presents if the Workload API returns more than one for this process
/// (see [`PathSvidPicker`]) -- if no SVID has that exact path, initialization
/// fails rather than silently presenting a different identity. When it is
/// `None` the source presents the Workload API's default (first) SVID.
/// Cancellation is respected during the SPIFFE source initialization. Returns
/// `Ok(None)` if cancelled before the SPIFFE source was established.
pub async fn build_spiffe_config(
    token: CancellationToken,
    trust_domains: Vec<String>,
    spiffe_id_path: Option<&str>,
) -> Result<Option<Arc<ServerConfig>>, Report> {
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
        res = async {
            match spiffe_id_path {
                Some(path) => spiffe::X509SourceBuilder::new()
                    .picker(PathSvidPicker { path: path.to_string() })
                    .build()
                    .await,
                None => spiffe::X509Source::new().await,
            }
        } => { res? }
        _ = token.cancelled() => {
            tracing::info!("Cancelled while waiting for SPIFFE X509 source");
            return Ok(None);
        }
    };

    let config = Arc::new(
        mtls_server(source)
            .authorize(authorizer::trust_domains(trust_domains)?)
            .build()?,
    );

    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_with_path(trust_domain: &str, path: &str) -> (Vec<u8>, Vec<u8>) {
        use rcgen::{
            CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose, SanType,
        };

        let spiffe_uri = format!("spiffe://{trust_domain}{path}");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(spiffe_uri.try_into().unwrap())];
        // X509Svid::parse_from_der requires KeyUsage and BasicConstraints extensions.
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.is_ca = IsCa::ExplicitNoCa;
        let key = KeyPair::generate().unwrap();
        let cert_der = params.self_signed(&key).unwrap().der().to_vec();
        (cert_der, key.serialize_der())
    }

    fn svid_with_path(trust_domain: &str, path: &str) -> Arc<X509Svid> {
        let (cert_der, key_der) = cert_with_path(trust_domain, path);
        Arc::new(X509Svid::parse_from_der(&cert_der, &key_der).unwrap())
    }

    #[test]
    fn picks_svid_matching_configured_path() {
        let svids = vec![
            svid_with_path("example.org", "/service/keystone"),
            svid_with_path("example.org", "/keystone/storage/node"),
        ];
        let picker = PathSvidPicker {
            path: "/keystone/storage/node".to_string(),
        };
        assert_eq!(picker.pick_svid(&svids), Some(1));
    }

    #[test]
    fn returns_none_when_no_svid_matches() {
        let svids = vec![svid_with_path("example.org", "/service/keystone")];
        let picker = PathSvidPicker {
            path: "/keystone/storage/node".to_string(),
        };
        assert_eq!(picker.pick_svid(&svids), None);
    }
}
