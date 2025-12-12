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
use tracing::{debug, info};
use tracing_test::traced_test;

mod keystone_utils;
mod keycloak {
    pub mod utils;
}

use keycloak::utils::*;
use keystone_utils::*;

use openstack_keystone::api::v4::federation::types::*;

pub async fn setup_keycloak_idp<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    client_id: K,
    client_secret: S,
) -> Result<(IdentityProvider, Mapping), Report> {
    let config = get_config();
    let keycloak_url = env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL is set");

    let idp = create_idp(
        &config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreate {
                name: "keycloak".into(),
                enabled: true,
                oidc_discovery_url: Some(format!("{}/realms/master", keycloak_url)),
                oidc_client_id: Some(client_id.as_ref().into()),
                oidc_client_secret: Some(client_secret.as_ref().into()),
                ..Default::default()
            },
        },
    )
    .await?;

    let mapping = create_mapping(
        &config,
        token.as_ref(),
        MappingCreateRequest {
            mapping: MappingCreate {
                id: Some("kc".into()),
                name: "keycloak".into(),
                enabled: true,
                idp_id: idp.id.clone(),
                allowed_redirect_uris: Some(vec![
                    "http://localhost:8080/v4/identity_providers/kc/callback".into(),
                ]),
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                groups_claim: Some("groups".into()),
                ..Default::default()
            },
        },
    )
    .await?;

    Ok((idp, mapping))
}

pub async fn setup_kecloak_idp_jwt<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    _client_id: K,
    _client_secret: S,
) -> Result<(IdentityProvider, Mapping), Report> {
    let config = get_config();
    let keycloak_url = env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL is set");

    let idp = create_idp(
        &config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreate {
                name: "keycloak_jwt".into(),
                enabled: true,
                oidc_discovery_url: Some(format!("{}/realms/master", keycloak_url)),
                jwks_url: Some(format!(
                    "{}/realms/master/protocol/openid-connect/certs",
                    keycloak_url
                )),
                bound_issuer: Some(format!("{}/realms/master", keycloak_url)),
                ..Default::default()
            },
        },
    )
    .await?;

    let mapping = create_mapping(
        &config,
        token.as_ref(),
        MappingCreateRequest {
            mapping: MappingCreate {
                id: Some("kc_jwt".into()),
                name: "keycloak_jwt".into(),
                enabled: true,
                r#type: Some(MappingType::Jwt),
                idp_id: idp.id.clone(),
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                ..Default::default()
            },
        },
    )
    .await?;

    Ok((idp, mapping))
}

#[tokio::test]
#[traced_test]
async fn test_login_oidc_keycloak() {
    let config = get_config();
    let user_name = "test";
    let user_password = "pass";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let keycloak = get_keycloak_admin(&config.client).await.unwrap();

    create_keycloak_client(&keycloak, client_id, client_secret)
        .await
        .unwrap();
    let user = create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let group = create_keycloak_group(&keycloak, "group1").await.unwrap();
    put_user_to_group(&keycloak, user, group).await.unwrap();

    let token = auth(&config).await;
    let (idp, mapping) = setup_keycloak_idp(&token, client_id, client_secret)
        .await
        .unwrap();

    let auth_req = initialize_oidc_auth(&config, &idp.id, &mapping.id)
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

    info!("Going to {:?}", auth_req.auth_url.clone());
    driver.goto(auth_req.auth_url).await.unwrap();

    debug!("Page source is {:?}", driver.source().await.unwrap());

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

    let _auth_rsp = exchange_authorization_code(&config, res.state, res.code)
        .await
        .unwrap();

    // TODO: Add checks for the response
}

#[tokio::test]
#[traced_test]
async fn test_login_jwt_keycloak() {
    let config = get_config();
    let user_name = "test";
    let user_password = "pass";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let keycloak = get_keycloak_admin(&config.client).await.unwrap();

    create_keycloak_client(&keycloak, client_id, client_secret)
        .await
        .unwrap();
    create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let jwt = generate_user_jwt(client_id, client_secret, user_name, user_password)
        .await
        .unwrap();

    let token = auth(&config).await;
    ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, mapping) = setup_kecloak_idp_jwt(&token, client_id, client_secret)
        .await
        .unwrap();

    let _auth_rsp = auth_jwt(&config, jwt, idp.id, mapping.name).await.unwrap();
}
