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
use spiffe_rustls::{authorizer, mtls_server};
use tokio_util::sync::CancellationToken;

use openstack_keystone_distributed_storage::spiffe_wait::{PathSvidPicker, wait_for_spiffe_source};

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
                Some(path) => wait_for_spiffe_source(
                    "SPIFFE mTLS listener",
                    spiffe::X509SourceBuilder::new()
                        .picker(PathSvidPicker::new(path))
                        .build(),
                )
                .await,
                None => wait_for_spiffe_source("SPIFFE mTLS listener", spiffe::X509Source::new()).await,
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
