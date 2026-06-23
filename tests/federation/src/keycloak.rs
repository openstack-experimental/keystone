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
use local_ip_address::local_ip;
use std::env;
use std::sync::{Arc, Mutex};
use thirtyfour::prelude::*;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::federation::*;
use openstack_keystone_api_types::v4::mapping::*;

mod keystone_utils;
mod keycloak {
    pub mod utils;
}

use crate::keycloak::utils::*;
use crate::keystone_utils::*;

pub async fn setup_keycloak_idp<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    client_id: K,
    client_secret: S,
) -> Result<(IdentityProvider, MappingRuleSet), Report> {
    let config = get_config();
    let keycloak_url = env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL is set");

    let idp = create_idp(
        config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreateBuilder::default()
                .name(Uuid::new_v4().simple().to_string())
                .enabled(true)
                .domain_id("default")
                .default_mapping_name("default")
                .oidc_discovery_url(format!("{}/realms/master", keycloak_url))
                .oidc_client_id(client_id.as_ref())
                .oidc_client_secret(client_secret.as_ref())
                .build()?,
        },
    )
    .await?;

    let ruleset = create_ruleset(
        config,
        token.as_ref(),
        MappingRuleSetCreateRequest {
            mapping: MappingRuleSetCreate {
                mapping_id: None,
                domain_id: Some("default".into()),
                source: IdentitySource::Federation {
                    idp_id: idp.id.clone(),
                },
                domain_resolution_mode: DomainResolutionMode::Fixed,
                enabled: true,
                rules: vec![MappingRule {
                    name: "default".into(),
                    description: None,
                    r#match: MatchCriteria::AllOf(vec![]),
                    identity: IdentityBinding {
                        identity_mode: Some(IdentityMode::Local),
                        user_name: "${claims.preferred_username}".into(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                }],
            },
        },
    )
    .await?;

    Ok((idp, ruleset))
}

pub async fn setup_kecloak_idp_jwt<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    _client_id: K,
    _client_secret: S,
) -> Result<(IdentityProvider, MappingRuleSet), Report> {
    let config = get_config();
    let keycloak_url = env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL is set");
    let ruleset_name = Uuid::new_v4().simple().to_string();

    let idp = create_idp(
        config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreateBuilder::default()
                .name(Uuid::new_v4().simple().to_string())
                .enabled(true)
                .domain_id("default")
                .default_mapping_name(&ruleset_name)
                .oidc_discovery_url(format!("{}/realms/master", keycloak_url))
                .jwks_url(format!(
                    "{}/realms/master/protocol/openid-connect/certs",
                    keycloak_url
                ))
                .bound_issuer(format!("{}/realms/master", keycloak_url))
                .build()?,
        },
    )
    .await?;

    let ruleset = create_ruleset(
        config,
        token.as_ref(),
        MappingRuleSetCreateRequest {
            mapping: MappingRuleSetCreate {
                mapping_id: Some(ruleset_name.clone()),
                domain_id: Some("default".into()),
                source: IdentitySource::Federation {
                    idp_id: idp.id.clone(),
                },
                domain_resolution_mode: DomainResolutionMode::Fixed,
                enabled: true,
                rules: vec![MappingRule {
                    name: ruleset_name.clone(),
                    description: None,
                    r#match: MatchCriteria::AllOf(Vec::new()),
                    identity: IdentityBinding {
                        identity_mode: Some(IdentityMode::Local),
                        user_name: "${claims.preferred_username}".into(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: Vec::new(),
                    groups: Vec::new(),
                }],
            },
        },
    )
    .await?;

    Ok((idp, ruleset))
}

#[tokio::test]
#[traced_test]
async fn test_login_oidc_keycloak() {
    let config = get_config();
    let user_name = "test";
    let user_password = "pass";
    let client_id = uuid::Uuid::new_v4().simple().to_string();
    let client_secret = "keystone_test_secret";
    let local_ip_address = local_ip().expect("cannot fetch local address");

    let keycloak = get_keycloak_admin(&config.client).await.unwrap();

    create_keycloak_client(
        &keycloak,
        &client_id,
        client_secret,
        &format!("http://{}:8050/*", local_ip_address),
    )
    .await
    .unwrap();
    let user = create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let group = create_keycloak_group(&keycloak, "group1").await.unwrap();
    put_user_to_group(&keycloak, user, group).await.unwrap();

    let token = auth(config).await;
    let (idp, _ruleset) = setup_keycloak_idp(&token, &client_id, client_secret)
        .await
        .unwrap();

    let auth_req = initialize_oidc_auth(
        config,
        &idp.id,
        "default",
        &format!("http://{}:8050/oidc/callback", local_ip_address),
    )
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

    let socket_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8050));
    let callback_handle = tokio::spawn({
        let cancel_token = cancel_token.clone();
        let state = state.clone();
        async move { auth_callback_server(socket_addr, state, cancel_token).await }
    });

    // Start the selenium part
    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless().unwrap();
    let driver = WebDriver::new(
        env::var("BROWSERDRIVER_URL").unwrap_or("http://localhost:4444".to_string()),
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

    let _auth_rsp = exchange_authorization_code(config, res.state, res.code)
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
    let client_id = uuid::Uuid::new_v4().simple().to_string();
    let client_secret = "keystone_test_secret";
    let local_ip_address = local_ip().expect("cannot fetch local address");

    let keycloak = get_keycloak_admin(&config.client).await.unwrap();

    create_keycloak_client(
        &keycloak,
        &client_id,
        client_secret,
        &format!("http://{}:8050/*", local_ip_address),
    )
    .await
    .unwrap();
    create_keycloak_user(&keycloak, user_name, user_password)
        .await
        .unwrap();
    let jwt = generate_user_jwt(&client_id, client_secret, user_name, user_password)
        .await
        .unwrap();

    let token = auth(config).await;
    ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, _ruleset) = setup_kecloak_idp_jwt(&token, &client_id, client_secret)
        .await
        .unwrap();

    let _auth_rsp = auth_jwt(config, jwt, idp.id, idp.default_mapping_name.unwrap())
        .await
        .unwrap();
}
