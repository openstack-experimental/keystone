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
//! Real-browser (WebDriver) helpers for the OAuth2 sign-in pages.
//!
//! The driver endpoint comes from `BROWSERDRIVER_URL` (default
//! `http://localhost:4444`, e.g. `geckodriver --port 4444`). The browser must
//! reach Keystone at `KEYSTONE_URL` (`http://localhost:8080`), which is also
//! the WebAuthn relying party origin of the API test server.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use eyre::{Result, eyre};
use http::Method;
use serde_json::{Value, json};
use thirtyfour::common::command::{Command, ExtensionCommand};
use thirtyfour::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a headless browser session: Chrome/Chromium by default (needs
/// chromedriver, e.g. `chromedriver --port=4444`), Firefox with
/// `BROWSER=firefox` (geckodriver; its virtual authenticator does not answer
/// `create()`, so the passkey test fails there). `BROWSER_HEADED` shows the
/// window.
pub async fn driver() -> Result<WebDriver> {
    let headed = env::var("BROWSER_HEADED").is_ok();
    let url = env::var("BROWSERDRIVER_URL").unwrap_or_else(|_| "http://localhost:4444".into());
    let res = if env::var("BROWSER").map_or(true, |b| b != "firefox") {
        let mut caps = DesiredCapabilities::chrome();
        if !headed {
            caps.add_arg("--headless=new")?;
        }
        caps.add_arg("--no-sandbox")?;
        WebDriver::new(&url, caps).await
    } else {
        let mut caps = DesiredCapabilities::firefox();
        if !headed {
            caps.set_headless()?;
        }
        WebDriver::new(&url, caps).await
    };
    res.map_err(|e| {
        eyre!("cannot start a browser session at {url} (is the webdriver running?): {e}")
    })
}

#[derive(Debug)]
struct WebauthnCommand {
    method: Method,
    endpoint: String,
    body: Option<Value>,
}

impl ExtensionCommand for WebauthnCommand {
    fn parameters_json(&self) -> Option<Value> {
        self.body.clone()
    }

    fn method(&self) -> Method {
        self.method.clone()
    }

    fn endpoint(&self) -> Arc<str> {
        self.endpoint.as_str().into()
    }
}

async fn webauthn_cmd(
    driver: &WebDriver,
    method: Method,
    endpoint: &str,
    body: Option<Value>,
) -> Result<Value> {
    let rsp = driver
        .handle()
        .cmd(Command::ExtensionCommand(Box::new(WebauthnCommand {
            method,
            endpoint: endpoint.to_string(),
            body,
        })))
        .await?;
    Ok(rsp.value_json().unwrap_or(Value::Null))
}

/// Attach a virtual CTAP2 authenticator (internal, user-verifying, resident-key
/// capable) to the session and return its id.
pub async fn add_virtual_authenticator(driver: &WebDriver) -> Result<String> {
    add_virtual_authenticator_with(
        driver,
        json!({
            "protocol": "ctap2",
            "transport": "usb",
            "hasResidentKey": true,
            "hasUserVerification": true,
            "isUserConsenting": true,
            "isUserVerified": true,
        }),
    )
    .await
}

pub async fn add_virtual_authenticator_with(driver: &WebDriver, cfg: Value) -> Result<String> {
    let value = webauthn_cmd(driver, Method::POST, "/webauthn/authenticator", Some(cfg)).await?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| eyre!("no authenticator id in {value}"))
}

pub async fn remove_virtual_authenticator(driver: &WebDriver, id: &str) -> Result<()> {
    webauthn_cmd(
        driver,
        Method::DELETE,
        &format!("/webauthn/authenticator/{id}"),
        None,
    )
    .await?;
    Ok(())
}

/// Credentials currently held by the virtual authenticator.
pub async fn authenticator_credentials(driver: &WebDriver, id: &str) -> Result<Vec<Value>> {
    let value = webauthn_cmd(
        driver,
        Method::GET,
        &format!("/webauthn/authenticator/{id}/credentials"),
        None,
    )
    .await?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

/// A loopback HTTP server standing in for the relying party's redirect URI,
/// so the browser lands on a real page after the redirect.
pub struct Callback {
    pub redirect_uri: String,
}

impl Callback {
    pub async fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        Ok(Self {
            redirect_uri: format!("http://localhost:{port}/cb"),
        })
    }

    /// Wait until the browser is at the redirect URI and return the full URL.
    pub async fn wait_for_redirect(&self, driver: &WebDriver) -> Result<url::Url> {
        let mut last = String::new();
        for _ in 0..60 {
            last = driver.current_url().await?.to_string();
            if last.starts_with(&self.redirect_uri) {
                return Ok(last.parse()?);
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

/// Value of query parameter `name` in `url`.
pub fn query_param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Wait until an element matching `by` is present.
pub async fn wait_for(driver: &WebDriver, by: By) -> Result<WebElement> {
    match driver
        .query(by)
        .wait(Duration::from_secs(15), Duration::from_millis(250))
        .first()
        .await
    {
        Ok(el) => Ok(el),
        Err(e) => Err(eyre!(
            "element not found: {e}\n{}",
            driver.source().await.unwrap_or_default()
        )),
    }
}

/// Wait until the page source contains `text`.
pub async fn wait_for_text(driver: &WebDriver, text: &str) -> Result<()> {
    let mut html = String::new();
    for _ in 0..60 {
        html = driver.source().await?;
        if html.contains(text) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(eyre!("page never showed {text:?}:\n{html}"))
}

/// Fill and submit the password form of the sign-in page.
pub async fn sign_in(driver: &WebDriver, username: &str, password: &str) -> Result<()> {
    let user = wait_for(driver, By::Id("username")).await?;
    user.send_keys(username).await?;
    driver
        .find(By::Id("password"))
        .await?
        .send_keys(password)
        .await?;
    driver
        .find(By::Css("button[type=submit]"))
        .await?
        .click()
        .await?;
    Ok(())
}

/// Press "Allow" on the consent page.
pub async fn allow_consent(driver: &WebDriver) -> Result<()> {
    wait_for(driver, By::Css("button[name=decision][value=allow]"))
        .await?
        .click()
        .await?;
    Ok(())
}

/// Register a passkey for `user_id` through the browser: the page script
/// fetches the creation options, lets the virtual authenticator create the
/// credential and posts the result back (`token` authenticates the user).
/// The browser must already be on a HTML page of the
/// Keystone origin.
pub async fn register_passkey(driver: &WebDriver, user_id: &str, token: &str) -> Result<()> {
    const SCRIPT: &str = r#"
const userId = arguments[0];
const token = arguments[1];
const done = arguments[arguments.length - 1];
const dec = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) { s += "="; }
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
  return out.buffer;
};
const enc = (buf) => {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_");
};
(async () => {
  const headers = {"Content-Type": "application/json", "X-Auth-Token": token};
  const start = await fetch(`/v4/users/${userId}/passkeys/register_start`, {
    method: "POST", headers, body: JSON.stringify({passkey: {}})});
  if (!start.ok) { throw new Error("register_start " + start.status + " " + await start.text()); }
  const pk = (await start.json()).public_key;
  const opts = {
    challenge: dec(pk.challenge),
    rp: pk.rp,
    user: {id: dec(pk.user.id), name: pk.user.name, displayName: pk.user.display_name},
    pubKeyCredParams: pk.pub_key_cred_params.map((p) => ({type: p.type_, alg: p.alg})),
    timeout: pk.timeout || undefined,
    attestation: "none",
    excludeCredentials: (pk.exclude_credentials || []).map((c) => ({type: c.type_, id: dec(c.id)})),
    authenticatorSelection: {
      residentKey: "discouraged",
      requireResidentKey: false,
      userVerification: "preferred"
    }
  };
  const cred = await navigator.credentials.create({publicKey: opts});
  const r = cred.response;
  const finish = await fetch(`/v4/users/${userId}/passkeys/register_finish`, {
    method: "POST", headers, body: JSON.stringify({
      description: "browser test passkey",
      id: cred.id,
      raw_id: enc(cred.rawId),
      type_: cred.type,
      response: {
        attestation_object: enc(r.attestationObject),
        client_data_json: enc(r.clientDataJSON)
      },
      extensions: {}
    })});
  if (!finish.ok) { throw new Error("register_finish " + finish.status + " " + await finish.text()); }
  return "ok";
})().then(done, (e) => done("error: " + e));
"#;
    let ret = driver
        .execute_async(SCRIPT, vec![json!(user_id), json!(token)])
        .await?;
    let out = ret.json().as_str().unwrap_or_default().to_string();
    if out != "ok" {
        return Err(eyre!("passkey registration failed: {:?}", ret.json()));
    }
    Ok(())
}
