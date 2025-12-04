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

use bytes::Bytes;
use eyre::Report;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use openstack_keystone::api::v4::federation::types::*;

pub async fn auth() -> String {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&json!({"auth": {"identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "name": "admin",
                    "password": "password",
                    "domain": {
                        "id": "default"
                    },
                }
            }
        },
        "scope": {
            "project": {
                "name": "admin",
                "domain": {"id": "default"}
            }
        }}}))
        .send()
        .await
        .unwrap()
        .headers()
        .get("X-Subject-Token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

pub async fn setup_idp<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    client_id: K,
    client_secret: S,
) -> Result<(IdentityProviderResponse, MappingResponse), Report> {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let dex_url = env::var("DEX_URL").expect("DEX_URL is set");
    let client = Client::new();

    let idp: IdentityProviderResponse = client
        .post(format!("{}/v4/federation/identity_providers", keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "identity_provider": {
                "id": "dex",
                "name": "dex",
                "enabled": true,
                "domain_id": "default",
                "default_mapping_name": "default",
                "oidc_discovery_url": format!("{}/dex", dex_url),
                "oidc_client_id": client_id.as_ref(),
                "oidc_client_secret": client_secret.as_ref(),
             }
        }))
        .send()
        .await?
        .json()
        .await?;

    let mapping: MappingResponse = client
        .post(format!(
            "{}/v4/federation/mappings",
            keystone_url,
        ))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "mapping": {
                "id": "dex",
                "name": "default",
                "enabled": true,
                "domain_id": "default",
                "idp_id": idp.identity_provider.id.clone(),
                "allowed_redirect_uris": ["http://localhost:8080/v4/identity_providers/dex/callback"],
                "user_id_claim": "sub",
                "user_name_claim": "name",
                "oidc_scopes": ["email", "profile"],
             }
        }))
        .send()
        .await?.json().await?;

    Ok((idp, mapping))
}

/// Information for finishing the authorization request (received as a callback
/// from `/authorize` call)
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationAuthCodeCallbackResponse {
    /// Authorization code
    pub code: Option<String>,
    /// Authorization state
    pub state: Option<String>,
    /// IDP error
    pub error: Option<String>,
    /// IDP error description
    pub error_description: Option<String>,
}

/// Start the OAUTH2 callback server
pub async fn auth_callback_server(
    addr: SocketAddr,
    state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>>,
    cancel_token: CancellationToken,
) -> Result<(), Report> {
    let listener = TcpListener::bind(addr).await?;
    // Wait maximum 2 minute for auth processing
    let webserver_timeout = Duration::from_secs(120);
    loop {
        let state_clone = state.clone();

        tokio::select! {
            Ok((stream, _addr)) = listener.accept() => {
                let io = TokioIo::new(stream);
                let cancel_token_srv = cancel_token.clone();
                let cancel_token_conn = cancel_token.clone();

                let service = service_fn(move |req| {
                    let state_clone = state_clone.clone();
                    let cancel_token = cancel_token_srv.clone();
                    handle_request(req, state_clone, cancel_token)
                });

                tokio::task::spawn(async move {
                    let cancel_token = cancel_token_conn.clone();
                    if http1::Builder::new().serve_connection(io, service).await.is_err() {
                        cancel_token.cancel();
                    }
                });
            },
            _ = cancel_token.cancelled() => {
                break;
            },
            _ = tokio::time::sleep(webserver_timeout) => {
                cancel_token.cancel();
            }
        }
    }
    Ok(())
}

/// Server request handler function
async fn handle_request(
    req: Request<IncomingBody>,
    state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>>,
    cancel_token: CancellationToken,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Report> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/oidc/callback") => {
            if let Some(query) = req.uri().query() {
                let res = serde_urlencoded::from_bytes::<FederationAuthCodeCallbackResponse>(
                    query.as_bytes(),
                )?;

                if res.error_description.is_some() {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Empty::<Bytes>::new().boxed())
                        .unwrap());
                }
                let mut data = state.lock().expect("state lock can not be obtained");
                *data = Some(res);
                cancel_token.cancel();

                Ok(Response::builder()
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap())
            }
        }
        (&Method::POST, "/oidc/callback") => {
            let b = req.collect().await?.to_bytes();
            let res = serde_urlencoded::from_bytes::<FederationAuthCodeCallbackResponse>(&b)?;
            if res.error_description.is_some() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap());
            }
            let mut data = state.lock().expect("state lock can not be obtained");
            *data = Some(res);
            cancel_token.cancel();

            Ok(Response::builder()
                .body(Empty::<Bytes>::new().boxed())
                .unwrap())
        }
        _ => {
            // Return 404 not found response.
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::<Bytes>::new().boxed())
                .unwrap())
        }
    }
}
