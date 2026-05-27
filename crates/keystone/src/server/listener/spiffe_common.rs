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
//! Shared SPIFFE configuration setup used by both TCP and Unix socket listeners.

use std::sync::Arc;

use color_eyre::eyre::{Report, Result, eyre};
use rustls::ServerConfig;
use spiffe_rustls::{authorizer, mtls_server};
use tokio_util::sync::CancellationToken;

/// Build the SPIFFE mTLS server configuration.
///
/// Validates the `SPIFFE_ENDPOINT_SOCKET` environment variable, establishes the
/// SPIFFE `X509Source`, and constructs a `ServerConfig` authorized for the given
/// trust domains. Cancellation is respected during the SPIFFE source
/// initialization. Returns `Ok(None)` if cancelled before the SPIFFE source
/// was established.
pub async fn build_spiffe_config(
    token: CancellationToken,
    trust_domains: Vec<String>,
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
        res = spiffe::X509Source::new() => { res? }
        _ = token.cancelled() => {
            tracing::info!("Ctrl+C signal received while waiting for the SPIFFE communication");
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
