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
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use eyre::Report;
use std::env;
use std::sync::{Arc, Mutex};
use thirtyfour::prelude::*;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing_test::traced_test;

mod keystone_utils;

use keystone_utils::*;

use openstack_keystone::federation::api::types::*;

pub async fn setup_idp<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    client_id: K,
    client_secret: S,
) -> Result<(IdentityProvider, Mapping), Report> {
    let config = get_config();
    let dex_url = env::var("DEX_URL").expect("DEX_URL is set");

    let idp = create_idp(
        config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreate {
                name: "dex".into(),
                enabled: true,
                domain_id: Some("default".into()),
                default_mapping_name: Some("default".into()),
                oidc_discovery_url: Some(format!("{}/dex", dex_url)),
                oidc_client_id: Some(client_id.as_ref().into()),
                oidc_client_secret: Some(client_secret.as_ref().into()),
                ..Default::default()
            },
        },
    )
    .await?;

    let mapping = create_mapping(
        config,
        token.as_ref(),
        MappingCreateRequest {
            mapping: MappingCreate {
                id: Some("dex".into()),
                name: "default".into(),
                enabled: true,
                domain_id: Some("default".into()),
                idp_id: idp.id.clone(),
                allowed_redirect_uris: Some(vec![
                    "http://localhost:8080/v4/identity_providers/dex/callback".into(),
                ]),
                user_id_claim: "sub".into(),
                user_name_claim: "name".into(),
                oidc_scopes: Some(vec!["email".into(), "profile".into()]),
                ..Default::default()
            },
        },
    )
    .await?;

    Ok((idp, mapping))
}

#[tokio::test]
#[traced_test]
async fn test_login_oidc() {
    let config = get_config();
    let user_name = "admin@example.com";
    let user_password = "password";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let token = auth(config).await;
    let (idp, mapping) = setup_idp(&token, client_id, client_secret).await.unwrap();

    let auth_req = initialize_oidc_auth(config, &idp.id, &mapping.id)
        .await
        .unwrap();

    // Prepare the callback server
    let cancel_token = CancellationToken::new();
    let state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>> = Arc::new(Mutex::new(None));

    tokio::spawn({
        let cancel_token = cancel_token.clone();
        async move {
            if let Ok(()) = signal::ctrl_c().await {
                cancel_token.cancel();
            }
        }
    });

    let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8050));
    let callback_handle = tokio::spawn({
        let cancel_token = cancel_token.clone();
        let state = state.clone();
        async move { auth_callback_server(socket_addr, state, cancel_token).await }
    });

    // Start the selenium part
    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless().unwrap();
    let driver = WebDriver::new(
        format!(
            "http://localhost:{}",
            env::var("BROWSERDRIVER_PORT").unwrap_or("4444".to_string())
        ),
        caps,
    )
    .await
    .unwrap();

    debug!("Going to {:?}", auth_req.auth_url.clone());
    driver.goto(auth_req.auth_url).await.unwrap();

    debug!("Page source is {:?}", driver.source().await.unwrap());

    let username_input = driver.query(By::Id("login")).first().await.unwrap();
    username_input.send_keys(user_name).await.unwrap();
    let password_input = driver.query(By::Id("password")).first().await.unwrap();
    password_input.send_keys(user_password).await.unwrap();
    let login = driver.find(By::Id("submit-login")).await.unwrap();
    login.click().await.unwrap();

    // Accept access request
    let accept = driver
        .find(By::ClassName("theme-btn--success"))
        .await
        .unwrap();
    accept.click().await.unwrap();

    debug!("Page source is {:?}", driver.source().await.unwrap());

    driver.quit().await.unwrap();

    let _res = callback_handle.await.unwrap();

    let guard = state.lock().expect("poisoned guard");
    let res: FederationAuthCodeCallbackResponse = guard.clone().unwrap();

    let _auth_rsp = exchange_authorization_code(config, res.state, res.code)
        .await
        .unwrap();
    // TODO: Add checks for the response
}
