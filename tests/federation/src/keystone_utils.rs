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
#![allow(unused)]

use bytes::Bytes;
use eyre::Report;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use openstack_keystone::api::v4::auth::token::types::TokenResponse;
use openstack_keystone::api::v4::user::types::*;
use openstack_keystone::federation::api::types::*;

static CONFIG: OnceLock<TestConfig> = OnceLock::new();

#[derive(Debug)]
pub struct TestConfig {
    pub client: Client,
    pub keystone_url: String,
}

fn load_config() -> TestConfig {
    // We use .expect() here because if these are missing, the application
    // cannot start correctly, so we crash immediately.
    let keystone_url =
        env::var("KEYSTONE_URL").expect("FATAL: Environment variable KEYSTONE_URL must be set");
    let client = Client::new();

    // Return the loaded configuration
    TestConfig {
        client,
        keystone_url,
    }
}

pub fn get_config() -> &'static TestConfig {
    CONFIG.get_or_init(load_config)
}

pub async fn auth(config: &TestConfig) -> String {
    config
        .client
        .post(format!("{}/v3/auth/tokens", &config.keystone_url))
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

pub async fn ensure_user<T: AsRef<str>, U: AsRef<str>, D: AsRef<str>>(
    token: T,
    user_name: U,
    domain_id: D,
) -> Result<User, Report> {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let user_rsp = client
        .post(format!("{}/v4/users", keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "user": {
                "name": user_name.as_ref(),
                "domain_id": domain_id.as_ref()
             }
        }))
        .send()
        .await?;
    if !user_rsp.status().is_success() {
        return Ok(client
            .get(format!("{}/v4/users", keystone_url))
            .query(&[
                ("domain_id", domain_id.as_ref()),
                ("name", user_name.as_ref()),
            ])
            .header("x-auth-token", token.as_ref())
            .send()
            .await?
            .json::<UserList>()
            .await?
            .users
            .first()
            .expect("cannot find user")
            .clone());
    }
    let user: UserResponse = user_rsp.json().await?;

    Ok(user.user)
}

pub async fn create_idp<T: AsRef<str>>(
    config: &TestConfig,
    token: T,
    idp: IdentityProviderCreateRequest,
) -> Result<IdentityProvider, Report> {
    Ok(config
        .client
        .post(format!(
            "{}/v4/federation/identity_providers",
            &config.keystone_url
        ))
        .header("x-auth-token", token.as_ref())
        .json(&serde_json::to_value(idp)?)
        .send()
        .await?
        .json::<IdentityProviderResponse>()
        .await?
        .identity_provider)
}

pub async fn create_mapping<T: AsRef<str>>(
    config: &TestConfig,
    token: T,
    mapping: MappingCreateRequest,
) -> Result<Mapping, Report> {
    Ok(config
        .client
        .post(format!("{}/v4/federation/mappings", &config.keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&serde_json::to_value(mapping)?)
        .send()
        .await?
        .json::<MappingResponse>()
        .await?
        .mapping)
}

pub async fn exchange_authorization_code(
    config: &TestConfig,
    state: Option<String>,
    code: Option<String>,
) -> Result<TokenResponse, Report> {
    Ok(config
        .client
        .post(format!(
            "{}/v4/federation/oidc/callback",
            &config.keystone_url
        ))
        .json(&json!({
            "state": state,
            "code": code
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await?)
}

pub async fn auth_jwt(
    config: &TestConfig,
    jwt: String,
    idp_id: String,
    mapping_name: String,
) -> Result<TokenResponse, Report> {
    Ok(config
        .client
        .post(format!(
            "{}/v4/federation/identity_providers/{}/jwt",
            &config.keystone_url, idp_id
        ))
        .header(AUTHORIZATION, format!("bearer {jwt}"))
        .header("openstack-mapping", mapping_name)
        .send()
        .await
        .unwrap()
        .json()
        .await?)
}

pub async fn initialize_oidc_auth<IDP, MAPPING>(
    config: &TestConfig,
    idp_id: IDP,
    mapping_name: MAPPING,
) -> Result<IdentityProviderAuthResponse, Report>
where
    IDP: AsRef<str> + std::fmt::Display,
    MAPPING: AsRef<str> + std::fmt::Display,
{
    Ok(config
        .client
        .post(format!(
            "{}/v4/federation/identity_providers/{}/auth",
            &config.keystone_url, idp_id
        ))
        .json(&json!({
            "redirect_uri": "http://localhost:8050/oidc/callback",
            "mapping_id": mapping_name.as_ref(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await?)
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
