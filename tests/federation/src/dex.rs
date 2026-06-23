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

use std::env;
use std::time::Duration;

use thirtyfour::prelude::*;
use tracing::debug;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::federation::*;
use openstack_keystone_api_types::v4::mapping::*;

mod keystone_utils;
use keystone_utils::*;

pub async fn setup_idp<T: AsRef<str>, K: AsRef<str>, S: AsRef<str>>(
    token: T,
    client_id: K,
    client_secret: S,
) -> Result<(IdentityProvider, MappingRuleSet), eyre::Report> {
    let config = get_config();
    let dex_url = env::var("DEX_URL").expect("DEX_URL is set");

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
                .oidc_discovery_url(format!("{dex_url}/dex"))
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
                        user_name: "${claims.name}".into(),
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

async fn wait_for_callback(timeout_secs: u64) -> FederationAuthCodeCallbackResponse {
    let callback_url =
        env::var("CALLBACK_URL").unwrap_or_else(|_| "http://dex-callback:8050".to_string());

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(timeout_secs) {
        let resp = reqwest::get(format!("{callback_url}/status")).await;
        if let Ok(r) = resp {
            if r.status().is_success() {
                if let Ok(data) = r.json::<FederationAuthCodeCallbackResponse>().await {
                    return data;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    panic!("Timed out waiting for callback from {callback_url}");
}

#[tokio::test]
#[traced_test]
async fn test_login_oidc() {
    let config = get_config();
    let user_name = "admin@example.com";
    let user_password = "password";
    let client_id = "keystone_test";
    let client_secret = "keystone_test_secret";

    let token = auth(&config).await;
    let (idp, ruleset) = setup_idp(&token, client_id, client_secret).await.unwrap();

    let redirect_uri = "http://dex-callback:8050/oidc/callback";
    let callback_url =
        env::var("CALLBACK_URL").unwrap_or_else(|_| "http://dex-callback:8050".to_string());

    // Clear previous callback data
    let _ = reqwest::get(format!("{callback_url}/clear")).await;

    let auth_resp = initialize_oidc_auth(&config, &idp.id, &ruleset.mapping_id, redirect_uri)
        .await
        .unwrap();

    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless().unwrap();

    let browserdriver_url = env::var("BROWSERDRIVER_URL")
        .unwrap_or_else(|_| "http://selenium-service:4444".to_string());

    let driver = WebDriver::new(&browserdriver_url, caps).await.unwrap();

    debug!("Navigating to {}", auth_resp.auth_url);
    driver.goto(auth_resp.auth_url).await.unwrap();

    debug!("Page source: {:?}", driver.source().await.unwrap());

    let username_input = driver.query(By::Id("login")).first().await.unwrap();
    username_input.send_keys(user_name).await.unwrap();

    let password_input = driver.query(By::Id("password")).first().await.unwrap();
    password_input.send_keys(user_password).await.unwrap();

    let login = driver.find(By::Id("submit-login")).await.unwrap();
    login.click().await.unwrap();

    // Accept consent
    let accept = driver
        .find(By::ClassName("theme-btn--success"))
        .await
        .unwrap();
    accept.click().await.unwrap();

    debug!(
        "Page source after consent: {:?}",
        driver.source().await.unwrap()
    );
    driver.quit().await.unwrap();

    let res = wait_for_callback(60).await;
    let _auth_rsp = exchange_authorization_code(&config, res.state, res.code)
        .await
        .unwrap();
}
