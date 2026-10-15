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
#![allow(dead_code)]

//! Federated sign-in on the OAuth2 OP login page against a real Keycloak.
//!
//! The OP (`/v4/oauth2/{domain}/authorize`) offers the enabled identity
//! providers of its domain next to the password form. These tests register a
//! Keycloak-backed IdP in a fresh OP domain and drive the whole round trip:
//! OP login page, Keycloak, OP callback, consent, authorization code and
//! token. The negative tests talk to the callback directly and check that a
//! forged, replayed or foreign callback cannot sign anyone in.
//!
//! Needs `KEYSTONE_URL`, `KEYCLOAK_URL` and `BROWSERDRIVER_URL` (a Selenium
//! Firefox that reaches both services and this host). A missing fixture fails
//! the tests instead of skipping them.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use eyre::{Report, eyre};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::time::Duration;
use thirtyfour::prelude::*;
use tracing_test::traced_test;
use url::Url;
use uuid::Uuid;

use openstack_keystone_api_types::federation::*;
use openstack_keystone_api_types::v4::mapping::*;

mod keystone_utils;
mod keycloak {
    pub mod utils;
}

use crate::keycloak::utils::*;
use crate::keystone_utils::*;

thread_local! {
    static CONFIG: &'static TestConfig = Box::leak(Box::new(TestConfig {
        client: Client::new(),
        keystone_url: env::var("KEYSTONE_URL").unwrap_or_default(),
    }));
}

/// Per-test HTTP client config.
///
/// `#[tokio::test]` gives every test its own runtime, while the shared
/// `keystone_utils::get_config()` client pools connections process-wide. A
/// pooled connection whose runtime already ended fails the next request with
/// `DispatchGone`. Each test runs on its own thread, so a thread-local client
/// is never reused across runtimes.
fn get_config() -> &'static TestConfig {
    CONFIG.with(|c| *c)
}

/// The message the OP login page shows for every failed upstream sign-in.
const UPSTREAM_FAILED: &str = "sign-in with the identity provider failed";
const KC_PASSWORD: &str = "pass";

/// The relying party's redirect URI. Public clients may only use `https://`
/// (or `http://localhost`, which the remote browser cannot serve), so the URI
/// points at a host that never resolves: the browser ends on its own error
/// page, which still carries the URL it was sent to.
struct Rp {
    redirect_uri: String,
}

impl Rp {
    fn new() -> Self {
        Self {
            redirect_uri: "https://rp.invalid/cb".into(),
        }
    }

    /// Wait until the browser was sent to the redirect URI and return that
    /// URL.
    async fn wait_for_redirect(&self, driver: &WebDriver) -> Result<Url, Report> {
        let mut last = String::new();
        for _ in 0..80 {
            // `current_url` itself fails on Firefox's error page; the error
            // text names that page.
            last = match driver.current_url().await {
                Ok(url) => url.to_string(),
                Err(e) => {
                    let text = e.to_string();
                    match text.find("about:neterror") {
                        Some(i) => text[i..]
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        None => return Err(e.into()),
                    }
                }
            };
            let target = if last.starts_with("about:neterror") {
                // Firefox keeps the failed URL in `u`.
                Url::parse(&last)?
                    .query_pairs()
                    .find(|(k, _)| k == "u")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            } else {
                last.clone()
            };
            if target.starts_with(&self.redirect_uri) {
                return Ok(target.parse()?);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(eyre!(
            "browser never reached {}; stuck at {last}\n{}",
            self.redirect_uri,
            driver.source().await.unwrap_or_default()
        ))
    }
}

/// A fresh OP domain with a Keycloak-backed IdP, an OP client and a Keycloak
/// user.
struct Fixture {
    admin_token: String,
    domain_id: String,
    idp: IdentityProvider,
    client_id: String,
    rp: Rp,
    kc_user: String,
}

impl Fixture {
    /// `with_keycloak`: also register the OP as a Keycloak client and create
    /// the Keycloak user. Tests that never sign in upstream skip it: they
    /// only need the IdP to be discoverable, and Keycloak's admin API is the
    /// slowest, flakiest part of the setup.
    ///
    /// `allowed_user`: when set, the mapping only accepts that Keycloak user
    /// name, so the fixture's own user is unmapped.
    async fn new(
        with_keycloak: bool,
        device: bool,
        allowed_user: Option<&str>,
    ) -> Result<Self, Report> {
        let config = get_config();
        let keycloak_url = env::var("KEYCLOAK_URL")?;
        let admin_token = auth(config).await;
        let domain_id = create_op_domain(&admin_token).await?;

        let suffix = Uuid::new_v4().simple().to_string();
        let kc_client_id = format!("op-{suffix}");
        let kc_secret = "keystone_test_secret";
        let kc_user = format!("fed-{suffix}");
        if with_keycloak {
            let callback = format!(
                // Where Keycloak sends the browser back to: the OP callback.
                "{}/v4/oauth2/{domain_id}/{}/federated/callback",
                config.keystone_url,
                if device { "device" } else { "authorize" }
            );
            retry(|| async {
                let keycloak = get_keycloak_admin(&config.client).await?;
                create_keycloak_client(&keycloak, &kc_client_id, kc_secret, &callback).await?;
                create_keycloak_user(&keycloak, &kc_user, KC_PASSWORD).await?;
                Ok(())
            })
            .await?;
        }

        let idp = create_idp(
            config,
            &admin_token,
            IdentityProviderCreateRequest {
                identity_provider: IdentityProviderCreateBuilder::default()
                    .name(format!("Keycloak {suffix}"))
                    .enabled(true)
                    .domain_id(&domain_id)
                    .default_mapping_name("default")
                    .oidc_discovery_url(format!("{keycloak_url}/realms/master"))
                    .oidc_client_id(&kc_client_id)
                    .oidc_client_secret(kc_secret)
                    .build()?,
            },
        )
        .await?;
        let r#match = match allowed_user {
            Some(name) => {
                MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "preferred_username".into(),
                    value: json!(name),
                })])
            }
            None => MatchCriteria::AllOf(vec![]),
        };
        create_ruleset(
            config,
            &admin_token,
            MappingRuleSetCreateRequest {
                mapping: MappingRuleSetCreate {
                    mapping_id: None,
                    domain_id: Some(domain_id.clone()),
                    source: IdentitySource::Federation {
                        idp_id: idp.id.clone(),
                    },
                    domain_resolution_mode: DomainResolutionMode::Fixed,
                    enabled: true,
                    rules: vec![MappingRule {
                        name: "default".into(),
                        description: None,
                        r#match,
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

        let rp = Rp::new();
        let client = if device {
            json!({
                "grant_types": ["device_code"],
                "allowed_scopes": ["openid"],
                "redirect_uris": [],
            })
        } else {
            json!({
                "grant_types": ["authorization_code"],
                "allowed_scopes": ["openid"],
                "redirect_uris": [rp.redirect_uri],
            })
        };
        let mut body = json!({
            "provider_id": format!("fed-{suffix}"),
            "name": "federated test client",
            "confidential": false,
            "token_endpoint_auth_method": "none",
            "require_pkce": true,
        });
        body.as_object_mut()
            .unwrap()
            .extend(client.as_object().unwrap().clone());
        let rsp = config
            .client
            .post(format!(
                "{}/v4/oauth2/{domain_id}/clients",
                config.keystone_url
            ))
            .header("x-auth-token", &admin_token)
            .json(&json!({ "oauth2_client": body }))
            .send()
            .await?;
        let status = rsp.status();
        let rsp: Value = rsp.json().await?;
        if !status.is_success() {
            return Err(eyre!("client registration failed with {status}: {rsp}"));
        }
        let client_id = rsp["oauth2_client"]["client_id"]
            .as_str()
            .ok_or_else(|| eyre!("no client_id in {rsp}"))?
            .to_string();

        Ok(Self {
            admin_token,
            domain_id,
            idp,
            client_id,
            rp,
            kc_user,
        })
    }

    fn op(&self, path: &str) -> String {
        format!(
            "{}/v4/oauth2/{}/{path}",
            get_config().keystone_url,
            self.domain_id
        )
    }

    /// `/authorize` URL of a PKCE-S256 request; returns it with the
    /// `code_verifier`, `state` and `nonce`.
    fn authorize_url(&self) -> (String, String, String, String) {
        let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = Uuid::new_v4().simple().to_string();
        let nonce = Uuid::new_v4().simple().to_string();
        let mut url = Url::parse(&self.op("authorize")).unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.rp.redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        (url.to_string(), verifier, state, nonce)
    }

    /// Users of the OP domain named `name`.
    async fn users_named(&self, name: &str) -> Result<Vec<Value>, Report> {
        let config = get_config();
        let rsp: Value = config
            .client
            .get(format!("{}/v4/users", config.keystone_url))
            .query(&[("domain_id", self.domain_id.as_str()), ("name", name)])
            .header("x-auth-token", &self.admin_token)
            .send()
            .await?
            .json()
            .await?;
        Ok(rsp["users"].as_array().cloned().unwrap_or_default())
    }

    /// Remove the OP domain; best effort.
    async fn cleanup(&self) {
        let config = get_config();
        let url = format!("{}/v3/domains/{}", config.keystone_url, self.domain_id);
        let _ = config
            .client
            .patch(&url)
            .header("x-auth-token", &self.admin_token)
            .json(&json!({"domain": {"enabled": false}}))
            .send()
            .await;
        let _ = config
            .client
            .delete(&url)
            .header("x-auth-token", &self.admin_token)
            .send()
            .await;
    }
}

/// Run a Keycloak admin sequence, retried: Keycloak drops connections while
/// several tests set up at once. The sequence must be safe to repeat.
async fn retry<F, Fut>(mut f: F) -> Result<(), Report>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), Report>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 5 => {
                attempt += 1;
                tracing::warn!("Keycloak setup failed ({e}); retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// A new domain; waits for its (asynchronously provisioned) signing keys.
async fn create_op_domain(token: &str) -> Result<String, Report> {
    let config = get_config();
    let rsp: Value = config
        .client
        .post(format!("{}/v3/domains", config.keystone_url))
        .header("x-auth-token", token)
        .json(&json!({"domain": {
            "name": format!("fed-op-{}", Uuid::new_v4().simple()),
            "enabled": true,
        }}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let domain_id = rsp["domain"]["id"]
        .as_str()
        .ok_or_else(|| eyre!("no domain id in {rsp}"))?
        .to_string();
    for _ in 0..80 {
        let status = config
            .client
            .get(format!(
                "{}/v4/oauth2/{domain_id}/.well-known/openid-configuration",
                config.keystone_url
            ))
            .send()
            .await?
            .status();
        if status == StatusCode::OK {
            return Ok(domain_id);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(eyre!("signing keys of domain {domain_id} never appeared"))
}

async fn browser() -> Result<WebDriver, Report> {
    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless()?;
    Ok(WebDriver::new(
        env::var("BROWSERDRIVER_URL").unwrap_or("http://localhost:4444".to_string()),
        caps,
    )
    .await?)
}

/// Press the login page's "Sign in with <IdP>" button and sign in at
/// Keycloak as `user`.
async fn sign_in_via_keycloak(driver: &WebDriver, user: &str) -> Result<(), Report> {
    driver
        .query(By::Css("form[action$='/federated'] button"))
        .first()
        .await?
        .click()
        .await?;
    let username = match driver.query(By::Id("username")).first().await {
        Ok(el) => el,
        Err(e) => {
            return Err(eyre!(
                "no Keycloak login form ({e}) at {}\n{}",
                driver.current_url().await?,
                driver.source().await.unwrap_or_default()
            ));
        }
    };
    username.send_keys(user).await?;
    driver
        .find(By::Id("password"))
        .await?
        .send_keys(KC_PASSWORD)
        .await?;
    driver.find(By::Id("kc-login")).await?.click().await?;
    Ok(())
}

/// Press "Allow". When the redirect target is the unresolvable RP, the click
/// itself reports Firefox's error page; that is the expected landing.
async fn allow_consent(driver: &WebDriver) -> Result<(), Report> {
    let allow = driver
        .query(By::Css("button[name=decision][value=allow]"))
        .first()
        .await?;
    match allow.click().await {
        Err(e) if e.to_string().contains("Reached error page") => Ok(()),
        res => Ok(res?),
    }
}

/// Wait until the login page shows the upstream failure.
async fn wait_for_upstream_failed(driver: &WebDriver) -> Result<(), Report> {
    for _ in 0..80 {
        if let Ok(el) = driver.find(By::Id("error")).await
            && el.text().await?.contains(UPSTREAM_FAILED)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(eyre!(
        "login page never showed the upstream failure at {}\n{}",
        driver.current_url().await?,
        driver.source().await.unwrap_or_default()
    ))
}

/// The claims of a JWT, unverified (the OP signature is covered elsewhere).
fn jwt_claims(jwt: &str) -> Result<Value, Report> {
    let payload = jwt.split('.').nth(1).ok_or_else(|| eyre!("not a JWT"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| STANDARD_NO_PAD.decode(payload))?;
    Ok(serde_json::from_slice(&raw)?)
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
#[traced_test]
async fn test_op_login_via_keycloak() {
    let f = Fixture::new(true, false, None).await.unwrap();
    let (url, verifier, state, nonce) = f.authorize_url();
    let driver = browser().await.unwrap();
    let res: Result<(), Report> = async {
        driver.goto(&url).await?;
        sign_in_via_keycloak(&driver, &f.kc_user).await?;
        allow_consent(&driver).await?;
        let back = f.rp.wait_for_redirect(&driver).await?;
        assert_eq!(query_param(&back, "state"), Some(state));
        let code = query_param(&back, "code").ok_or_else(|| eyre!("no code in {back}"))?;

        let rsp: Value = get_config()
            .client
            .post(f.op("token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", f.rp.redirect_uri.as_str()),
                ("client_id", f.client_id.as_str()),
                ("code_verifier", verifier.as_str()),
            ])
            .send()
            .await?
            .json()
            .await?;
        let id_token = rsp["id_token"]
            .as_str()
            .ok_or_else(|| eyre!("no id_token in {rsp}"))?;
        let claims = jwt_claims(id_token)?;
        assert_eq!(claims["nonce"], json!(nonce));
        // Keycloak sends no `amr`, so the OP marks the login as federated.
        assert!(
            claims["amr"]
                .as_array()
                .is_some_and(|a| a.contains(&json!("federated"))),
            "{claims}"
        );
        // The mapping created the user in the OP domain.
        let users = f.users_named(&f.kc_user).await?;
        assert_eq!(users.len(), 1, "{users:?}");
        assert_eq!(claims["sub"], users[0]["id"]);
        Ok(())
    }
    .await;
    driver.quit().await.unwrap();
    f.cleanup().await;
    res.unwrap();
}

#[tokio::test]
#[traced_test]
async fn test_op_login_via_keycloak_unmapped_user_rejected() {
    let f = Fixture::new(true, false, Some("somebody-else"))
        .await
        .unwrap();
    let (url, _, _, _) = f.authorize_url();
    let driver = browser().await.unwrap();
    let res: Result<(), Report> = async {
        driver.goto(&url).await?;
        sign_in_via_keycloak(&driver, &f.kc_user).await?;
        wait_for_upstream_failed(&driver).await?;
        assert!(
            !driver
                .current_url()
                .await?
                .as_str()
                .starts_with(&f.rp.redirect_uri)
        );
        // Nothing was provisioned for the rejected identity.
        assert!(f.users_named(&f.kc_user).await?.is_empty());
        Ok(())
    }
    .await;
    driver.quit().await.unwrap();
    f.cleanup().await;
    res.unwrap();
}

#[tokio::test]
#[traced_test]
async fn test_op_device_login_via_keycloak() {
    let f = Fixture::new(true, true, None).await.unwrap();
    let start: Value = get_config()
        .client
        .post(f.op("device_authorization"))
        .form(&[("client_id", f.client_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_code = start["user_code"].as_str().expect("user_code").to_string();
    let device_code = start["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();
    let driver = browser().await.unwrap();
    let res: Result<(), Report> = async {
        driver.goto(&f.op("device")).await?;
        driver
            .query(By::Id("user_code"))
            .first()
            .await?
            .send_keys(&user_code)
            .await?;
        driver
            .find(By::Css("button[type=submit]"))
            .await?
            .click()
            .await?;
        sign_in_via_keycloak(&driver, &f.kc_user).await?;
        allow_consent(&driver).await?;
        for _ in 0..80 {
            if driver.source().await?.contains("Device connected") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let rsp = get_config()
            .client
            .post(f.op("token"))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code.as_str()),
                ("client_id", f.client_id.as_str()),
            ])
            .send()
            .await?;
        let status = rsp.status();
        let body: Value = rsp.json().await?;
        assert!(status.is_success(), "{status}: {body}");
        assert!(body["access_token"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(f.users_named(&f.kc_user).await?.len(), 1);
        Ok(())
    }
    .await;
    driver.quit().await.unwrap();
    f.cleanup().await;
    res.unwrap();
}

/// A cookie-jar client that stays at the OP: it starts the federated
/// sign-in up to the redirect to Keycloak, without a real browser.
struct Probe {
    http: Client,
    state: String,
}

impl Probe {
    async fn new_http() -> Client {
        Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .build()
            .unwrap()
    }

    /// Open `/authorize`, press the IdP button and keep the `state` the OP
    /// sent to the upstream.
    async fn start(f: &Fixture) -> Result<Self, Report> {
        let http = Self::new_http().await;
        let (url, _, _, _) = f.authorize_url();
        let page = http.get(url).send().await?.text().await?;
        let csrf = hidden_value(&page, "csrf_token")?;
        let idp_id = hidden_value(&page, "idp_id")?;
        assert_eq!(idp_id, f.idp.id, "the login page must offer the IdP");

        let rsp = http
            .post(f.op("authorize/federated"))
            .form(&[("csrf_token", csrf.as_str()), ("idp_id", idp_id.as_str())])
            .send()
            .await?;
        assert_eq!(rsp.status(), StatusCode::SEE_OTHER);
        let location: Url = rsp
            .headers()
            .get("location")
            .ok_or_else(|| eyre!("no Location"))?
            .to_str()?
            .parse()?;
        let state = query_param(&location, "state").ok_or_else(|| eyre!("no state"))?;
        Ok(Self { http, state })
    }
}

/// Value of the hidden input `name` in `html`.
fn hidden_value(html: &str, name: &str) -> Result<String, Report> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&marker)
        .ok_or_else(|| eyre!("no `{name}` input in {html}"))?
        + marker.len();
    let len = html[start..]
        .find('"')
        .ok_or_else(|| eyre!("unterminated `{name}` input"))?;
    Ok(html[start..start + len].to_string())
}

#[tokio::test]
#[traced_test]
async fn test_op_callback_with_wrong_state_rejected() {
    let f = Fixture::new(false, false, None).await.unwrap();
    let res: Result<(), Report> = async {
        let probe = Probe::start(&f).await?;
        let rsp = probe
            .http
            .get(f.op("authorize/federated/callback"))
            .query(&[("code", "forged"), ("state", "not-the-state")])
            .send()
            .await?;
        assert_eq!(rsp.status(), StatusCode::BAD_REQUEST);
        assert!(rsp.headers().get("location").is_none());
        let body = rsp.text().await?;
        assert!(body.contains("invalid or expired sign-in"), "{body}");
        Ok(())
    }
    .await;
    f.cleanup().await;
    res.unwrap();
}

#[tokio::test]
#[traced_test]
async fn test_op_callback_with_upstream_error_shows_failure() {
    let f = Fixture::new(false, false, None).await.unwrap();
    let res: Result<(), Report> = async {
        let probe = Probe::start(&f).await?;
        let rsp = probe
            .http
            .get(f.op("authorize/federated/callback"))
            .query(&[("error", "access_denied"), ("state", probe.state.as_str())])
            .send()
            .await?;
        assert_eq!(rsp.status(), StatusCode::OK);
        assert!(rsp.headers().get("location").is_none());
        let body = rsp.text().await?;
        assert!(body.contains(UPSTREAM_FAILED), "{body}");

        // The state was spent by the failed attempt: answering the same
        // redirect again cannot sign anyone in either.
        let rsp = probe
            .http
            .get(f.op("authorize/federated/callback"))
            .query(&[("code", "replayed"), ("state", probe.state.as_str())])
            .send()
            .await?;
        assert!(rsp.headers().get("location").is_none());
        let body = rsp.text().await?;
        assert!(body.contains(UPSTREAM_FAILED), "{body}");
        Ok(())
    }
    .await;
    f.cleanup().await;
    res.unwrap();
}

#[tokio::test]
#[traced_test]
async fn test_op_callback_from_another_browser_rejected() {
    let f = Fixture::new(false, false, None).await.unwrap();
    let res: Result<(), Report> = async {
        let probe = Probe::start(&f).await?;
        // Same URL, but a browser that never started the flow: no session.
        let stranger = Probe::new_http().await;
        let rsp = stranger
            .get(f.op("authorize/federated/callback"))
            .query(&[("code", "stolen"), ("state", probe.state.as_str())])
            .send()
            .await?;
        assert_eq!(rsp.status(), StatusCode::BAD_REQUEST);
        assert!(rsp.headers().get("location").is_none());
        let body = rsp.text().await?;
        assert!(body.contains("session expired"), "{body}");
        Ok(())
    }
    .await;
    f.cleanup().await;
    res.unwrap();
}
