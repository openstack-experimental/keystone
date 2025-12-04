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

use reqwest::Client;
use serde_json::json;
use std::env;
use std::sync::{Arc, Mutex};
use thirtyfour::prelude::*;
use tokio::signal;
use tokio_util::sync::CancellationToken;

mod keystone_utils;

use keystone_utils::*;

use openstack_keystone::api::v4::auth::token::types::TokenResponse;
use openstack_keystone::api::v4::federation::types::*;

#[tokio::test]
async fn test_login_oidc() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    let user_name = "admin@example.com";
    let user_password = "password";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let token = auth().await;
    let (idp, mapping) = setup_idp(&token, client_id, client_secret).await.unwrap();

    let auth_req: IdentityProviderAuthResponse = client
        .post(format!(
            "{}/v4/federation/identity_providers/{}/auth",
            keystone_url, idp.identity_provider.id
        ))
        .json(&json!({
            "redirect_uri": "http://localhost:8050/oidc/callback",
            "mapping_id": mapping.mapping.id,
        }))
        .send()
        .await
        .unwrap()
        .json()
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

    println!("Going to {:?}", auth_req.auth_url.clone());
    driver.goto(auth_req.auth_url).await.unwrap();

    println!("Page source is {:?}", driver.source().await.unwrap());

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

    println!("Page source is {:?}", driver.source().await.unwrap());

    driver.quit().await.unwrap();

    let _res = callback_handle.await.unwrap();

    let guard = state.lock().expect("poisoned guard");
    let res: FederationAuthCodeCallbackResponse = guard.clone().unwrap();

    let _auth_rsp: TokenResponse = client
        .post(format!("{}/v4/federation/oidc/callback", keystone_url))
        .json(&json!({
            "state": res.state,
            "code": res.code
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // TODO: Add checks for the response
}
