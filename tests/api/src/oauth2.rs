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
//! Helpers for `/v4/oauth2/*` (ADR 0026) functional tests. There is no
//! `openstack_sdk` generated binding for these ADR-specific endpoints (only
//! standard OpenStack-API resources get SDK bindings), so this mirrors
//! `common::TestClient`'s raw `reqwest` pattern for `v3/auth/tokens`
//! directly against `/v4/oauth2/...`.

use eyre::{Result, eyre};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use crate::common::TestClient;

/// `POST /v4/oauth2/{domain_id}/clients`, authenticated as SystemAdmin.
/// Returns the created client's `client_id` and, for a confidential
/// client, its one-time `client_secret`.
pub async fn register_client(
    domain_id: &str,
    provider_id: &str,
    grant_types: Vec<GrantType>,
    allowed_scopes: Vec<String>,
    confidential: bool,
) -> Result<(String, Option<String>)> {
    let mut admin = TestClient::default()?;
    admin.auth_admin_system().await?;

    #[derive(Serialize)]
    struct CreateBody {
        oauth2_client: CreatePayload,
    }
    #[derive(Serialize)]
    struct CreatePayload {
        provider_id: String,
        confidential: bool,
        grant_types: Vec<GrantType>,
        allowed_scopes: Vec<String>,
        token_endpoint_auth_method: String,
        require_pkce: bool,
    }
    #[derive(Deserialize)]
    struct CreateResponse {
        client_secret: Option<String>,
        oauth2_client: ClientEnvelope,
    }
    #[derive(Deserialize)]
    struct ClientEnvelope {
        client_id: String,
    }

    let rsp = admin
        .client
        .post(
            admin
                .base_url
                .join(&format!("v4/oauth2/{domain_id}/clients"))?,
        )
        .json(&CreateBody {
            oauth2_client: CreatePayload {
                provider_id: provider_id.to_string(),
                confidential,
                grant_types,
                allowed_scopes,
                token_endpoint_auth_method: if confidential {
                    "client_secret_basic".to_string()
                } else {
                    "none".to_string()
                },
                require_pkce: !confidential,
            },
        })
        .send()
        .await?;

    if rsp.status() != StatusCode::CREATED && rsp.status() != StatusCode::OK {
        return Err(eyre!(
            "oauth2 client registration failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }

    let body: CreateResponse = rsp.json().await?;
    Ok((body.oauth2_client.client_id, body.client_secret))
}

/// `POST /v3/domains`, authenticated as SystemAdmin. Returns the created
/// domain's `id`. `default` (DB-seeded at bootstrap, not created through
/// this API) never fires `Oauth2KeyHook` and so never gets OAuth2 signing
/// keys provisioned -- anything needing `jwks`/`well-known`/token signing
/// to actually work must use a domain created through this call instead.
pub async fn create_test_domain(name: &str) -> Result<String> {
    let mut admin = TestClient::default()?;
    admin.auth_admin_system().await?;

    #[derive(Serialize)]
    struct CreateBody {
        domain: CreatePayload,
    }
    #[derive(Serialize)]
    struct CreatePayload {
        name: String,
        enabled: bool,
    }
    #[derive(Deserialize)]
    struct CreateResponse {
        domain: DomainEnvelope,
    }
    #[derive(Deserialize)]
    struct DomainEnvelope {
        id: String,
    }

    let rsp = admin
        .client
        .post(admin.base_url.join("v3/domains")?)
        .json(&CreateBody {
            domain: CreatePayload {
                name: name.to_string(),
                enabled: true,
            },
        })
        .send()
        .await?;

    if rsp.status() != StatusCode::CREATED && rsp.status() != StatusCode::OK {
        return Err(eyre!(
            "domain creation failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }

    let body: CreateResponse = rsp.json().await?;
    Ok(body.domain.id)
}

/// `POST /v3/users`, authenticated as SystemAdmin. Returns the created
/// user's `id`. Used to give the device-grant browser flow (`device.rs`'s
/// `/device/login`) a real username/password to sign in with.
pub async fn create_test_user(domain_id: &str, name: &str, password: &str) -> Result<String> {
    let mut admin = TestClient::default()?;
    admin.auth_admin_system().await?;

    #[derive(Serialize)]
    struct CreateBody {
        user: CreatePayload,
    }
    #[derive(Serialize)]
    struct CreatePayload {
        name: String,
        domain_id: String,
        password: String,
        enabled: bool,
    }
    #[derive(Deserialize)]
    struct CreateResponse {
        user: UserEnvelope,
    }
    #[derive(Deserialize)]
    struct UserEnvelope {
        id: String,
    }

    let rsp = admin
        .client
        .post(admin.base_url.join("v3/users")?)
        .json(&CreateBody {
            user: CreatePayload {
                name: name.to_string(),
                domain_id: domain_id.to_string(),
                password: password.to_string(),
                enabled: true,
            },
        })
        .send()
        .await?;

    if rsp.status() != StatusCode::CREATED && rsp.status() != StatusCode::OK {
        return Err(eyre!(
            "user creation failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }

    let body: CreateResponse = rsp.json().await?;
    Ok(body.user.id)
}

/// `POST /v4/oauth2/{domain_id}/device_authorization` (RFC 8628 §3.1).
/// Unauthenticated -- the endpoint itself validates `client_id`.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: u32,
}

pub async fn start_device_authorization(
    domain_id: &str,
    client_id: &str,
    scope: Option<&str>,
) -> Result<DeviceAuthorizationResponse> {
    let base_url: url::Url = env::var("KEYSTONE_URL")?.parse()?;
    let mut form = vec![("client_id", client_id.to_string())];
    if let Some(scope) = scope {
        form.push(("scope", scope.to_string()));
    }

    let rsp = Client::new()
        .post(base_url.join(&format!("v4/oauth2/{domain_id}/device_authorization"))?)
        .form(&form)
        .send()
        .await?;

    if rsp.status() != StatusCode::OK {
        return Err(eyre!(
            "device_authorization failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(rsp.json().await?)
}

/// `GET /v4/oauth2/{domain_id}/jwks/revocation` (ADR 0026 §3, §11).
/// Unauthenticated by design.
#[derive(Debug, Deserialize)]
pub struct JwksRevocationResponse {
    pub revoked_jtis: Vec<String>,
}

pub async fn get_jwks_revocation(domain_id: &str) -> Result<(StatusCode, JwksRevocationResponse)> {
    let base_url: url::Url = env::var("KEYSTONE_URL")?.parse()?;
    let rsp = Client::new()
        .get(base_url.join(&format!("v4/oauth2/{domain_id}/jwks/revocation"))?)
        .send()
        .await?;
    let status = rsp.status();
    let body: JwksRevocationResponse = rsp.json().await?;
    Ok((status, body))
}

/// `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration` (RFC 8414).
/// Unauthenticated by design.
pub async fn get_well_known(domain_id: &str) -> Result<(StatusCode, serde_json::Value)> {
    let base_url: url::Url = env::var("KEYSTONE_URL")?.parse()?;
    let rsp = Client::new()
        .get(base_url.join(&format!(
            "v4/oauth2/{domain_id}/.well-known/openid-configuration"
        ))?)
        .send()
        .await?;
    let status = rsp.status();
    let body: serde_json::Value = rsp.json().await?;
    Ok((status, body))
}

/// RFC 6749 §5.2 token endpoint error/success envelope, used generically by
/// the `/token` helpers below so callers can assert on
/// `error`/`error_description` without needing a distinct struct per grant
/// type.
pub async fn post_token_form(
    domain_id: &str,
    form: &[(&str, &str)],
) -> Result<(StatusCode, serde_json::Value)> {
    let base_url: url::Url = env::var("KEYSTONE_URL")?.parse()?;
    let rsp = Client::new()
        .post(base_url.join(&format!("v4/oauth2/{domain_id}/token"))?)
        .form(form)
        .send()
        .await?;
    let status = rsp.status();
    let request_id = rsp
        .headers()
        .get("x-openstack-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string();
    let raw_body = rsp.text().await?;
    if !status.is_success() {
        eprintln!(
            "post_token_form failed: status={status} x-openstack-request-id={request_id} \
             form={form:?} body={raw_body}"
        );
    }
    let body: serde_json::Value = serde_json::from_str(&raw_body)?;
    Ok((status, body))
}

/// Poll `/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
/// (RFC 8628 §3.4).
pub async fn poll_device_token(
    domain_id: &str,
    client_id: &str,
    device_code: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    post_token_form(
        domain_id,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Pull a `<input type="hidden" name="{field}" value="...">` value out of a
/// rendered oauth2 HTML page. There is no JSON API for the browser flow
/// (`device.rs`/`authorize.rs` render Askew templates directly), so the
/// CSRF token / any other hidden form field has to be scraped out of the
/// markup, same as a real browser's form submission would extract it.
pub fn extract_hidden_value(html: &str, field: &str) -> Option<String> {
    let needle = format!("name=\"{field}\"");
    let start = html.find(&needle)?;
    let tail = &html[start..];
    let value_marker = "value=\"";
    let value_start = tail.find(value_marker)? + value_marker.len();
    let value_end = tail[value_start..].find('"')?;
    Some(tail[value_start..value_start + value_end].to_string())
}

/// A cookie-jar-carrying HTTP session for walking the RFC 8628 §3.3 browser
/// verification flow (`GET/POST /device`, `POST /device/login`,
/// `POST /device/consent`) end-to-end, mirroring what a real browser would
/// do: the device cookie set by `POST /device` must survive across the
/// subsequent `login`/`consent` POSTs.
pub struct DeviceBrowserSession {
    client: Client,
    base_url: Url,
    domain_id: String,
}

impl DeviceBrowserSession {
    pub fn new(domain_id: &str) -> Result<Self> {
        Ok(Self {
            client: Client::builder().cookie_store(true).build()?,
            base_url: env::var("KEYSTONE_URL")?.parse()?,
            domain_id: domain_id.to_string(),
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(self
            .base_url
            .join(&format!("v4/oauth2/{}/{path}", self.domain_id))?)
    }

    /// `GET /device`: the code-entry form.
    pub async fn get_entry(&self) -> Result<(StatusCode, String)> {
        let rsp = self.client.get(self.url("device")?).send().await?;
        let status = rsp.status();
        Ok((status, rsp.text().await?))
    }

    /// `POST /device` with `user_code`: sets the device cookie, returns the
    /// login form (or a re-rendered entry form with an error).
    pub async fn submit_user_code(&self, user_code: &str) -> Result<(StatusCode, String)> {
        let rsp = self
            .client
            .post(self.url("device")?)
            .form(&[("user_code", user_code)])
            .send()
            .await?;
        let status = rsp.status();
        Ok((status, rsp.text().await?))
    }

    /// `POST /device/login`: submit username/password + the CSRF token
    /// scraped from the login form. Returns the consent form on success (or
    /// the final result page directly, for a `pre_authorized` client).
    pub async fn submit_login(
        &self,
        csrf_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(StatusCode, String)> {
        let rsp = self
            .client
            .post(self.url("device/login")?)
            .form(&[
                ("csrf_token", csrf_token),
                ("username", username),
                ("password", password),
            ])
            .send()
            .await?;
        let status = rsp.status();
        Ok((status, rsp.text().await?))
    }

    /// `POST /device/consent`: submit the allow/deny decision + CSRF token
    /// scraped from the consent form. Returns the final result page.
    pub async fn submit_consent(
        &self,
        csrf_token: &str,
        decision: &str,
    ) -> Result<(StatusCode, String)> {
        let rsp = self
            .client
            .post(self.url("device/consent")?)
            .form(&[("csrf_token", csrf_token), ("decision", decision)])
            .send()
            .await?;
        let status = rsp.status();
        Ok((status, rsp.text().await?))
    }
}
