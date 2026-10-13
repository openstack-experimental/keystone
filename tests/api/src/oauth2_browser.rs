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
//! Helpers for live tests of the OP browser flows (`/authorize`, login, MFA,
//! consent, SSO, logout) and the `/token` grants that follow them.
//!
//! The browser is simulated with a cookie-jar `reqwest` client that does not
//! follow redirects, so tests can inspect every `Location` header and
//! `Set-Cookie` the server emits.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eyre::{Result, eyre};
use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::common::TestClient;
use crate::oauth2::{extract_hidden_value, get_well_known, post_token_form};

/// The redirect URI used by every browser-flow test client.
pub const REDIRECT_URI: &str = "https://rp.example.com/callback";
/// Registered `post_logout_redirect_uri` for browser-flow test clients.
pub const POST_LOGOUT_URI: &str = "https://rp.example.com/bye";
/// Password of every user created through [`create_browser_user`].
pub const PASSWORD: &str = "S3cur3P@ssw0rd!";

pub fn base_url() -> Result<Url> {
    Ok(std::env::var("KEYSTONE_URL")?.parse()?)
}

/// Generate a PKCE `(code_verifier, S256 code_challenge)` pair (RFC 7636).
pub fn pkce() -> (String, String) {
    let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Create a fresh domain and wait until its OAuth2 signing keys are
/// provisioned (`Oauth2KeyHook` runs asynchronously after domain creation).
pub async fn create_ready_domain(prefix: &str) -> Result<String> {
    let domain_id =
        crate::oauth2::create_test_domain(&format!("{prefix}-{}", Uuid::new_v4().simple())).await?;
    wait_for_domain_keys(&domain_id).await?;
    Ok(domain_id)
}

/// Poll the discovery document until the domain's keys exist.
pub async fn wait_for_domain_keys(domain_id: &str) -> Result<()> {
    for _ in 0..80 {
        if let Ok((StatusCode::OK, _)) = get_well_known(domain_id).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(eyre!(
        "OAuth2 signing keys for domain {domain_id} never appeared"
    ))
}

/// Create a user with [`PASSWORD`] and a unique name; returns `(id, name)`.
pub async fn create_browser_user(domain_id: &str) -> Result<(String, String)> {
    let name = format!("browser-user-{}", Uuid::new_v4().simple());
    let id = crate::oauth2::create_test_user(domain_id, &name, PASSWORD).await?;
    Ok((id, name))
}

/// `POST /v4/oauth2/{domain}/clients` as system admin with a raw JSON body
/// merged over sane defaults. Returns the raw status and parsed response.
pub async fn create_client_raw(domain_id: &str, extra: Value) -> Result<(StatusCode, Value)> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let mut payload = json!({
        "provider_id": format!("browser-{}", Uuid::new_v4().simple()),
        "name": "browser test client",
        "confidential": false,
        "grant_types": ["authorization_code"],
        "allowed_scopes": ["openid", "profile", "email"],
        "token_endpoint_auth_method": "none",
        "require_pkce": true,
        "redirect_uris": [REDIRECT_URI],
        "post_logout_redirect_uris": [POST_LOGOUT_URI],
    });
    if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    let rsp = admin
        .client
        .post(
            admin
                .base_url
                .join(&format!("v4/oauth2/{domain_id}/clients"))?,
        )
        .json(&json!({ "oauth2_client": payload }))
        .send()
        .await?;
    let status = rsp.status();
    let body = rsp.json().await.unwrap_or(Value::Null);
    Ok((status, body))
}

/// A registered browser-flow client.
#[derive(Clone, Debug)]
pub struct BrowserClient {
    pub client_id: String,
    pub provider_id: String,
    pub client_secret: Option<String>,
}

/// Register a client (public by default, see [`create_client_raw`]) and
/// return its identifiers; fails on any non-2xx.
pub async fn create_browser_client(domain_id: &str, extra: Value) -> Result<BrowserClient> {
    let (status, body) = create_client_raw(domain_id, extra).await?;
    if !status.is_success() {
        return Err(eyre!("client registration failed with {status}: {body}"));
    }
    let c = &body["oauth2_client"];
    Ok(BrowserClient {
        client_id: c["client_id"]
            .as_str()
            .ok_or_else(|| eyre!("no client_id in {body}"))?
            .to_string(),
        provider_id: c["provider_id"].as_str().unwrap_or_default().to_string(),
        client_secret: body["client_secret"].as_str().map(str::to_string),
    })
}

/// Query of a `GET /authorize` request.
#[derive(Clone, Debug)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    /// `None` omits the parameter entirely.
    pub code_challenge: Option<String>,
    pub code_challenge_method: String,
    /// Extra raw pairs (`prompt`, `max_age`, ...).
    pub extra: Vec<(String, String)>,
}

impl AuthorizeParams {
    /// Parameters for a standard PKCE-S256 request; returns the matching
    /// `code_verifier` too.
    pub fn new(client_id: &str) -> (Self, String) {
        let (verifier, challenge) = pkce();
        (
            Self {
                client_id: client_id.to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: Uuid::new_v4().simple().to_string(),
                nonce: Some(Uuid::new_v4().simple().to_string()),
                code_challenge: Some(challenge),
                code_challenge_method: "S256".to_string(),
                extra: Vec::new(),
            },
            verifier,
        )
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.extra.push((key.to_string(), value.to_string()));
        self
    }

    pub fn pairs(&self) -> Vec<(String, String)> {
        let mut v = vec![
            ("response_type".to_string(), "code".to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("scope".to_string(), self.scope.clone()),
            ("state".to_string(), self.state.clone()),
            (
                "code_challenge_method".to_string(),
                self.code_challenge_method.clone(),
            ),
        ];
        if let Some(c) = &self.code_challenge {
            v.push(("code_challenge".to_string(), c.clone()));
        }
        if let Some(n) = &self.nonce {
            v.push(("nonce".to_string(), n.clone()));
        }
        v.extend(self.extra.iter().cloned());
        v
    }
}

/// One HTTP response from the simulated browser.
#[derive(Debug)]
pub struct BrowserResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl BrowserResponse {
    pub fn location(&self) -> Option<String> {
        self.headers
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// Query parameter `name` of the `Location` header.
    pub fn location_param(&self, name: &str) -> Option<String> {
        let loc = self.location()?;
        let url = Url::parse(&loc).ok()?;
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    pub fn csrf(&self) -> Result<String> {
        extract_hidden_value(&self.body, "csrf_token")
            .ok_or_else(|| eyre!("no csrf_token in {}: {}", self.status, self.body))
    }

    /// True when the page is the consent dialog.
    pub fn is_consent(&self) -> bool {
        self.status == StatusCode::OK && self.body.contains("name=\"decision\"")
    }

    /// True when the page is the username/password login form.
    pub fn is_login(&self) -> bool {
        self.status == StatusCode::OK && self.body.contains("name=\"password\"")
    }

    /// True when the page is the TOTP second-factor form.
    pub fn is_mfa(&self) -> bool {
        self.status == StatusCode::OK && self.body.contains("name=\"passcode\"")
    }
}

/// A cookie-jar browser for the `/v4/oauth2/{domain}/authorize*` flow.
pub struct AuthorizeBrowser {
    client: Client,
    jar: std::sync::Arc<reqwest::cookie::Jar>,
    base: Url,
    domain_id: String,
}

impl AuthorizeBrowser {
    pub fn new(domain_id: &str) -> Result<Self> {
        let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
        Ok(Self {
            client: Client::builder()
                .cookie_provider(jar.clone())
                .redirect(Policy::none())
                .build()?,
            jar,
            base: base_url()?,
            domain_id: domain_id.to_string(),
        })
    }

    /// A browser pre-loaded with one cookie (replaying a cookie stolen from
    /// or minted for another domain).
    pub fn with_cookie(domain_id: &str, name: &str, value: &str) -> Result<Self> {
        let browser = Self::new(domain_id)?;
        browser
            .jar
            .add_cookie_str(&format!("{name}={value}; Path=/"), &browser.base);
        Ok(browser)
    }

    /// Current value of cookie `name` in the jar.
    pub async fn cookie_value(&self, name: &str) -> Result<String> {
        use reqwest::cookie::CookieStore;
        let header = self
            .jar
            .cookies(&self.base)
            .ok_or_else(|| eyre!("cookie jar is empty"))?;
        header
            .to_str()?
            .split("; ")
            .find_map(|kv| kv.strip_prefix(&format!("{name}=")).map(str::to_string))
            .ok_or_else(|| eyre!("cookie {name} not set"))
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(self
            .base
            .join(&format!("v4/oauth2/{}/{path}", self.domain_id))?)
    }

    async fn finish(rsp: reqwest::Response) -> Result<BrowserResponse> {
        let status = rsp.status();
        let headers = rsp.headers().clone();
        let body = rsp.text().await?;
        Ok(BrowserResponse {
            status,
            headers,
            body,
        })
    }

    pub async fn get(&self, path: &str, query: &[(String, String)]) -> Result<BrowserResponse> {
        let mut url = self.url(path)?;
        url.query_pairs_mut().extend_pairs(query);
        Self::finish(self.client.get(url).send().await?).await
    }

    pub async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<BrowserResponse> {
        Self::finish(self.client.post(self.url(path)?).form(form).send().await?).await
    }

    /// `GET /authorize`.
    pub async fn authorize(&self, params: &AuthorizeParams) -> Result<BrowserResponse> {
        self.get("authorize", &params.pairs()).await
    }

    /// `POST /authorize/login`.
    pub async fn login(
        &self,
        csrf: &str,
        username: &str,
        password: &str,
    ) -> Result<BrowserResponse> {
        self.post(
            "authorize/login",
            &[
                ("csrf_token", csrf),
                ("username", username),
                ("password", password),
            ],
        )
        .await
    }

    /// `POST /authorize/mfa` with a TOTP passcode.
    pub async fn mfa(&self, csrf: &str, passcode: &str) -> Result<BrowserResponse> {
        self.post(
            "authorize/mfa",
            &[
                ("csrf_token", csrf),
                ("factor", "totp"),
                ("passcode", passcode),
            ],
        )
        .await
    }

    /// `POST /authorize/consent`.
    pub async fn consent(
        &self,
        csrf: &str,
        decision: &str,
        remember: bool,
    ) -> Result<BrowserResponse> {
        let mut form = vec![("csrf_token", csrf), ("decision", decision)];
        if remember {
            form.push(("remember", "1"));
        }
        self.post("authorize/consent", &form).await
    }

    /// `GET /logout` with the given query.
    pub async fn logout(&self, query: &[(&str, &str)]) -> Result<BrowserResponse> {
        let q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        self.get("logout", &q).await
    }

    /// Drive an authorization request to its terminal response, answering
    /// whichever of login / consent the server asks for. Returns the final
    /// response (a 303 redirect with `code` or `error`, or an error page).
    pub async fn complete(
        &self,
        params: &AuthorizeParams,
        username: &str,
        password: &str,
        remember: bool,
    ) -> Result<BrowserResponse> {
        let mut rsp = self.authorize(params).await?;
        if rsp.is_login() {
            rsp = self.login(&rsp.csrf()?, username, password).await?;
        }
        if rsp.is_consent() {
            rsp = self.consent(&rsp.csrf()?, "allow", remember).await?;
        }
        Ok(rsp)
    }

    /// Like [`Self::complete`] but requires a redirect carrying `code` and
    /// returns it.
    pub async fn obtain_code(
        &self,
        params: &AuthorizeParams,
        username: &str,
        password: &str,
    ) -> Result<String> {
        let rsp = self.complete(params, username, password, false).await?;
        rsp.location_param("code").ok_or_else(|| {
            eyre!(
                "no code in response {}: location={:?} body={}",
                rsp.status,
                rsp.location(),
                rsp.body
            )
        })
    }
}

/// Exchange an authorization code at `/token` (public client + PKCE).
pub async fn exchange_code(
    domain_id: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
) -> Result<(StatusCode, Value)> {
    exchange_code_for(domain_id, client_id, code, verifier, REDIRECT_URI).await
}

/// [`exchange_code`] for a client registered with another `redirect_uri`.
pub async fn exchange_code_for(
    domain_id: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<(StatusCode, Value)> {
    post_token_form(
        domain_id,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ],
    )
    .await
}

/// `grant_type=refresh_token` for a public client.
pub async fn refresh(
    domain_id: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<(StatusCode, Value)> {
    post_token_form(
        domain_id,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ],
    )
    .await
}

/// `grant_type=client_credentials` with HTTP Basic client authentication.
pub async fn client_credentials_token(
    domain_id: &str,
    client_id: &str,
    secret: &str,
    scope: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut form = vec![("grant_type", "client_credentials")];
    if let Some(s) = scope {
        form.push(("scope", s));
    }
    let rsp = Client::new()
        .post(base_url()?.join(&format!("v4/oauth2/{domain_id}/token"))?)
        .basic_auth(client_id, Some(secret))
        .form(&form)
        .send()
        .await?;
    let status = rsp.status();
    let headers = rsp.headers().clone();
    let body = rsp.json().await.unwrap_or(Value::Null);
    Ok((status, headers, body))
}

/// Decode the (unverified) claims of a JWT.
pub fn jwt_claims(jwt: &str) -> Result<Value> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| eyre!("not a JWT: {jwt}"))?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

/// Decode the (unverified) header of a JWT.
pub fn jwt_header(jwt: &str) -> Result<Value> {
    let header = jwt
        .split('.')
        .next()
        .ok_or_else(|| eyre!("not a JWT: {jwt}"))?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?)
}

/// HMAC-SHA1 (RFC 2104). `hmac` and `sha1` here use incompatible `digest`
/// majors, so do it by hand like `keystone-core` does.
fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..20].copy_from_slice(&sha1::Sha1::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = sha1::Sha1::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = sha1::Sha1::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// RFC 6238 TOTP (6 digits, 30 s, SHA-1) for a Base32 `seed` at `unix`.
pub fn totp_code(seed_b32: &str, unix: u64) -> Result<String> {
    let key = data_encoding::BASE32_NOPAD.decode(
        seed_b32
            .trim_end_matches('=')
            .to_ascii_uppercase()
            .as_bytes(),
    )?;
    let hash = hmac_sha1(&key, &(unix / 30).to_be_bytes());
    let off = (hash[19] & 0x0f) as usize;
    let bin = (u32::from(hash[off] & 0x7f) << 24)
        | (u32::from(hash[off + 1]) << 16)
        | (u32::from(hash[off + 2]) << 8)
        | u32::from(hash[off + 3]);
    Ok(format!("{:06}", bin % 1_000_000))
}

/// TOTP passcode valid right now.
pub fn totp_now(seed_b32: &str) -> Result<String> {
    totp_code(
        seed_b32,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )
}

/// A passcode that is certainly not valid now (neither the current nor the
/// previous window).
pub fn totp_wrong(seed_b32: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let ok: Vec<String> = [now, now.saturating_sub(30)]
        .iter()
        .map(|t| totp_code(seed_b32, *t))
        .collect::<Result<_>>()?;
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| !ok.contains(c))
        .ok_or_else(|| eyre!("no wrong code"))
}

/// Enroll a TOTP credential for `user_id` (`POST /v3/credentials`) and
/// return its Base32 seed.
pub async fn enroll_totp(user_id: &str) -> Result<String> {
    let seed = data_encoding::BASE32_NOPAD.encode(Uuid::new_v4().as_bytes());
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .post(admin.base_url.join("v3/credentials")?)
        .json(&json!({"credential": {
            "type": "totp",
            "user_id": user_id,
            "blob": json!({"seed": seed, "digits": 6, "period": 30}).to_string(),
        }}))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "totp enroll failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(seed)
}

/// Bind a mapping ruleset to the OAuth2 client `provider_id` so the
/// `client_credentials` grant can resolve a security context: the client's
/// ephemeral identity gets the `reader` role on `domain_id` (ADR 0026 §5).
pub async fn bind_client_credentials_ruleset(domain_id: &str, provider_id: &str) -> Result<()> {
    use openstack_keystone_api_types::v3::role::RoleRef;
    use openstack_keystone_api_types::v4::mapping::ruleset::{
        Authorization, DomainResolutionMode, IdentityBinding, IdentitySource, MappingRule,
        MappingRuleSetCreate, MatchCriteria,
    };

    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;

    let roles: Value = admin
        .client
        .get(admin.base_url.join("v3/roles?name=reader")?)
        .send()
        .await?
        .json()
        .await?;
    let role = roles["roles"]
        .get(0)
        .ok_or_else(|| eyre!("`reader` role not found: {roles}"))?;
    let role_ref = RoleRef {
        domain_id: None,
        id: role["id"].as_str().unwrap_or_default().to_string(),
        name: role["name"].as_str().unwrap_or_default().to_string(),
    };

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(format!("oauth2-cc-{}", Uuid::new_v4().simple())),
        domain_id: Some(domain_id.to_string()),
        source: IdentitySource::OAuth2Client {
            provider_id: provider_id.to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![MappingRule {
            name: "oauth2-cc-rule".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "${claims.oauth2_client.client_id}".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![Authorization::Domain {
                domain_id: domain_id.to_string(),
                roles: vec![role_ref],
            }],
            groups: vec![],
        }],
    };
    let rsp = admin
        .client
        .post(admin.base_url.join("v4/mappings/rulesets")?)
        .json(&json!({ "mapping": ruleset }))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "ruleset creation failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

/// Password-authenticate a user and return a Keystone token scoped to
/// `scope_domain` (or unscoped when `None`).
pub async fn user_token(
    domain_id: &str,
    username: &str,
    password: &str,
    scope_domain: Option<&str>,
) -> Result<String> {
    let mut body = json!({"auth": {"identity": {
        "methods": ["password"],
        "password": {"user": {
            "name": username,
            "domain": {"id": domain_id},
            "password": password,
        }},
    }}});
    if let Some(d) = scope_domain {
        body["auth"]["scope"] = json!({"domain": {"id": d}});
    }
    let rsp = Client::new()
        .post(base_url()?.join("v3/auth/tokens")?)
        .json(&body)
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "password auth failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    rsp.headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| eyre!("no x-subject-token header"))
}

/// Create a user holding `role_name` on a fresh project of `domain_id` and
/// return a token scoped to that project (domain-scoped role grants are not
/// available through the v3 API; only `admin` holds domain scopes).
pub async fn project_role_token(domain_id: &str, role_name: &str) -> Result<String> {
    let (_, username, project_id) = project_role_user(domain_id, role_name).await?;
    project_token(domain_id, &username, &project_id).await
}

/// Create a user holding `role_name` on a fresh project of `domain_id`;
/// returns `(user_id, username, project_id)`.
pub async fn project_role_user(
    domain_id: &str,
    role_name: &str,
) -> Result<(String, String, String)> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let (user_id, username) = create_browser_user(domain_id).await?;

    let project: Value = admin
        .client
        .post(admin.base_url.join("v3/projects")?)
        .json(&json!({"project": {
            "name": format!("oauth2-proj-{}", Uuid::new_v4().simple()),
            "domain_id": domain_id,
        }}))
        .send()
        .await?
        .json()
        .await?;
    let project_id = project["project"]["id"]
        .as_str()
        .ok_or_else(|| eyre!("project creation failed: {project}"))?
        .to_string();

    let roles: Value = admin
        .client
        .get(admin.base_url.join(&format!("v3/roles?name={role_name}"))?)
        .send()
        .await?
        .json()
        .await?;
    let role_id = roles["roles"][0]["id"]
        .as_str()
        .ok_or_else(|| eyre!("role {role_name} not found: {roles}"))?;
    let rsp = admin
        .client
        .put(admin.base_url.join(&format!(
            "v3/projects/{project_id}/users/{user_id}/roles/{role_id}"
        ))?)
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!("role grant failed with {}", rsp.status()));
    }

    Ok((user_id, username, project_id))
}

/// Password-authenticate `username` scoped to `project_id`.
pub async fn project_token(domain_id: &str, username: &str, project_id: &str) -> Result<String> {
    let rsp = Client::new()
        .post(base_url()?.join("v3/auth/tokens")?)
        .json(&json!({"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": username, "domain": {"id": domain_id}, "password": PASSWORD,
            }}},
            "scope": {"project": {"id": project_id}},
        }}))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "project-scoped auth failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    rsp.headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| eyre!("no x-subject-token header"))
}

/// `PATCH /v3/users/{id}` as system admin.
pub async fn patch_user(user_id: &str, user: Value) -> Result<()> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .patch(admin.base_url.join(&format!("v3/users/{user_id}"))?)
        .json(&json!({ "user": user }))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "user update failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

/// `DELETE /v3/users/{id}` as system admin.
pub async fn delete_user(user_id: &str) -> Result<()> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .delete(admin.base_url.join(&format!("v3/users/{user_id}"))?)
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!("user delete failed with {}", rsp.status()));
    }
    Ok(())
}

/// `PATCH /v3/domains/{id}` as system admin.
pub async fn patch_domain(domain_id: &str, domain: Value) -> Result<()> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .patch(admin.base_url.join(&format!("v3/domains/{domain_id}"))?)
        .json(&json!({ "domain": domain }))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!("domain update failed with {}", rsp.status()));
    }
    Ok(())
}

/// Self-service password change (`POST /v3/users/{id}/password`).
pub async fn change_password(user_id: &str, old: &str, new: &str) -> Result<()> {
    let rsp = Client::new()
        .post(base_url()?.join(&format!("v3/users/{user_id}/password"))?)
        .json(&json!({"user": {"original_password": old, "password": new}}))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "password change failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

/// Run `probe` every 200 ms (up to ~5 s) until it returns `Some`; used for
/// effects delivered asynchronously by lifecycle hooks.
pub async fn eventually<T, F, Fut>(mut probe: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    for _ in 0..25 {
        if let Some(v) = probe().await? {
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(eyre!("condition not reached in time"))
}

/// Call the per-user consents API. `method` is `GET` or `DELETE`;
/// `client_id` selects `/consents/{client_id}` for `DELETE`.
pub async fn consents_call(
    method: reqwest::Method,
    user_id: &str,
    client_id: Option<&str>,
    token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let path = match client_id {
        Some(c) => format!("v4/users/{user_id}/oauth2/consents/{c}"),
        None => format!("v4/users/{user_id}/oauth2/consents"),
    };
    let mut rb = Client::new().request(method, base_url()?.join(&path)?);
    if let Some(t) = token {
        rb = rb.header("x-auth-token", t);
    }
    let rsp = rb.send().await?;
    let status = rsp.status();
    let body = rsp.text().await.unwrap_or_default();
    Ok((status, serde_json::from_str(&body).unwrap_or(Value::Null)))
}

/// Create an application credential for `user_id` with the user's
/// project-scoped `token` and return a token obtained through it (a
/// delegated token).
pub async fn app_cred_token(user_id: &str, token: &str) -> Result<String> {
    let secret = Uuid::new_v4().simple().to_string();
    let rsp = Client::new()
        .post(base_url()?.join(&format!("v3/users/{user_id}/application_credentials"))?)
        .header("x-auth-token", token)
        .json(&json!({"application_credential": {
            "name": format!("oauth2-ac-{}", Uuid::new_v4().simple()),
            "secret": secret,
        }}))
        .send()
        .await?;
    let status = rsp.status();
    let body: Value = rsp.json().await?;
    if !status.is_success() {
        return Err(eyre!(
            "application credential creation failed with {status}: {body}"
        ));
    }
    let id = body["application_credential"]["id"]
        .as_str()
        .ok_or_else(|| eyre!("no application credential id in {body}"))?;
    let rsp = Client::new()
        .post(base_url()?.join("v3/auth/tokens")?)
        .json(&json!({"auth": {"identity": {
            "methods": ["application_credential"],
            "application_credential": {"id": id, "secret": secret},
        }}}))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "application credential auth failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    rsp.headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| eyre!("no x-subject-token header"))
}

/// Enable or disable a client (`PUT /v4/oauth2/{domain}/clients/{id}`) as
/// system admin.
pub async fn set_client_enabled(domain_id: &str, provider_id: &str, enabled: bool) -> Result<()> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .put(
            admin
                .base_url
                .join(&format!("v4/oauth2/{domain_id}/clients/{provider_id}"))?,
        )
        .json(&json!({"oauth2_client": {"enabled": enabled}}))
        .send()
        .await?;
    if !rsp.status().is_success() {
        return Err(eyre!(
            "client update failed with {}: {}",
            rsp.status(),
            rsp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}
