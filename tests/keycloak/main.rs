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
use reqwest::header::AUTHORIZATION;
use serde_json::json;
use std::env;
use std::sync::{Arc, Mutex};
use thirtyfour::prelude::*;
use tokio::signal;
use tokio_util::sync::CancellationToken;

mod keycloak_utils;
mod keystone_utils;

use keycloak_utils::*;
use keystone_utils::*;

use openstack_keystone::api::v4::auth::token::types::TokenResponse;
use openstack_keystone::api::v4::federation::types::*;

#[tokio::test]
async fn test_login_oidc_keycloak() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    let user_name = "test";
    let user_password = "pass";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let keycloak = get_keycloak_admin(&client).await.unwrap();

    create_keycloak_client(&keycloak, client_id, client_secret)
        .await
        .unwrap();
    let user = create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let group = create_keycloak_group(&keycloak, "group1").await.unwrap();
    put_user_to_group(&keycloak, user, group).await.unwrap();

    let token = auth().await;
    let (idp, mapping) = setup_keycloak_idp(&token, client_id, client_secret)
        .await
        .unwrap();

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

    //let delay = Duration::new(5, 0);
    //driver.set_implicit_wait_timeout(delay).await.unwrap();

    println!("Going to {:?}", auth_req.auth_url.clone());
    driver.goto(auth_req.auth_url).await.unwrap();

    println!("Page source is {:?}", driver.source().await.unwrap());

    let username_input = driver.query(By::Id("username")).first().await.unwrap();
    username_input.send_keys(user_name).await.unwrap();
    let password_input = driver.query(By::Id("password")).first().await.unwrap();
    password_input.send_keys(user_password).await.unwrap();
    let login = driver.find(By::Id("kc-login")).await.unwrap();
    login.click().await.unwrap();

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

#[tokio::test]
async fn test_login_jwt_keycloak() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    let user_name = "test";
    let user_password = "pass";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let keycloak = get_keycloak_admin(&client).await.unwrap();

    create_keycloak_client(&keycloak, client_id, client_secret)
        .await
        .unwrap();
    create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let jwt = generate_user_jwt(client_id, client_secret, user_name, user_password)
        .await
        .unwrap();
    println!("jwt is {:?}", jwt);

    let token = auth().await;
    let user = ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, mapping) = setup_kecloak_idp_jwt(&token, client_id, client_secret)
        .await
        .unwrap();

    let _auth_rsp: TokenResponse = client
        .post(format!(
            "{}/v4/federation/identity_providers/{}/jwt",
            keystone_url, idp.identity_provider.id
        ))
        .header(AUTHORIZATION, format!("bearer {jwt}"))
        .header("openstack-mapping", mapping.mapping.name)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
}
