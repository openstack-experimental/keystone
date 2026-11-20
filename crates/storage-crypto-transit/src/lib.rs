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
// Crypto inventory: STO-14; see doc/src/contributor/crypto-inventory.md
//! # OpenBao Transit KEK provider
//!
//! [`TransitKek`] is a [`KekProvider`] that wraps the storage DEK with a
//! Transit key (`POST /v1/<mount>/encrypt/<key>`, `.../decrypt/<key>`), so the
//! KEK never enters this process. [`TransitSiteKey`] is the private-key side
//! of the per-site wrap of ADR 0045 §11.2: it asks an `rsa-*` Transit key to
//! decrypt a blob made by `wrap_dek_for_site` (Transit decrypts RSA with
//! OAEP-SHA-256 and no label).
//!
//! The cryptography runs inside OpenBao. Its FIPS status is the status of
//! that OpenBao build and of the TLS link to it, which uses the process-wide
//! rustls provider.
//!
//! Requests are made on the caller's runtime, one at a time. Failures that
//! come from OpenBao being unreachable are reported as
//! [`CryptoError::KekUnavailable`], which
//! [`CryptoError::is_transient`] recognises so callers can retry. Redirects
//! are never followed, so a standby cannot make the client replay the token
//! and the DEK to another host.
//!
//! The caller must have installed a default rustls crypto provider.
//!
//! [`SiteKeyUnwrapper`]: openstack_keystone_storage_crypto::site_wrap::SiteKeyUnwrapper

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use openstack_keystone_storage_crypto::error::CryptoError;
use openstack_keystone_storage_crypto::kek::KekProvider;
use openstack_keystone_storage_crypto::site_wrap::SiteKeyUnwrapper;
use reqwest::Client;
use reqwest::header::HeaderValue;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

/// Binding context prefixed to the DEK before it is encrypted, matching the
/// associated data of the other KEK providers. Transit has no AD for
/// non-derived keys, so it is checked after decryption.
const DEK_WRAP_AD: &[u8] = b"keystone-dek-wrap-v1";

/// How a request authenticates to OpenBao.
pub enum TransitAuth {
    /// A fixed token.
    Token(SecretString),
    /// JWT auth: the contents of `jwt` (for example a JWT-SVID) are exchanged
    /// for a token at `auth/<mount>/login`, again after a `403`.
    Jwt {
        /// Mount of the JWT auth method (usually `jwt`).
        mount: String,
        /// Role to log in as.
        role: String,
        /// Reads the current JWT; called on every login.
        jwt: Box<dyn Fn() -> Result<SecretString, CryptoError> + Send + Sync>,
    },
    /// TLS certificate auth: the login request itself is an mTLS handshake
    /// with the client identity `identity` returns, for example the node's
    /// X.509-SVID. The identity is fetched again on every login, so rotated
    /// SVIDs are picked up; ordinary Transit calls use the issued token and
    /// no client certificate.
    Cert {
        /// Mount of the certificate auth method (usually `cert`).
        mount: String,
        /// Certificate role to log in as; `None` lets OpenBao try all roles.
        role: Option<String>,
        /// PEM: the certificate chain, leaf first, followed by the private
        /// key.
        identity: Box<dyn Fn() -> Result<Zeroizing<Vec<u8>>, CryptoError> + Send + Sync>,
    },
}

/// Connection parameters.
pub struct TransitParams {
    /// Base URL of OpenBao.
    pub address: Url,
    /// Authentication.
    pub auth: TransitAuth,
    /// PEM CA bundle. When set, it is the only trust root for OpenBao.
    pub ca_pem: Option<Vec<u8>>,
    /// Transit mount.
    pub mount: String,
    /// Enterprise namespace.
    pub namespace: Option<String>,
    /// Per-request timeout.
    pub timeout: Duration,
}

fn transit_err(msg: impl Into<String>) -> CryptoError {
    CryptoError::Transit(msg.into())
}

fn unavailable(msg: impl Into<String>) -> CryptoError {
    CryptoError::KekUnavailable(msg.into())
}

/// Request state shared by every operation. One request at a time, which also
/// serialises logins.
struct TransitClient {
    session: tokio::sync::Mutex<Session>,
    mount: String,
}

impl TransitClient {
    fn new(params: TransitParams) -> Result<Self, CryptoError> {
        let http = build_http(&params, None)?;
        let mount = params.mount.clone();
        Ok(Self {
            session: tokio::sync::Mutex::new(Session {
                http,
                params,
                token: None,
            }),
            mount,
        })
    }

    /// POST `body` to `v1/<mount>/<op>/<key>` and return the `data` member.
    async fn call(&self, op: &str, key: &str, body: Value) -> Result<Value, CryptoError> {
        if key.is_empty() {
            return Err(transit_err("empty key name"));
        }
        let mut session = self.session.lock().await;
        let mut segments = vec!["v1"];
        segments.extend(mount_segments(&self.mount));
        segments.push(op);
        segments.push(key);
        let url = session.endpoint(&segments)?;
        let resp = session.post(url, &body).await?;
        resp.get("data")
            .cloned()
            .ok_or_else(|| transit_err("response has no `data`"))
    }
}

/// The non-empty path segments of a mount such as `transit` or `team/transit`.
fn mount_segments(mount: &str) -> impl Iterator<Item = &str> {
    mount.split('/').filter(|s| !s.is_empty())
}

/// HTTP client for `params`, presenting `identity` (PEM) when given.
///
/// Redirects are never followed: a standby or a misconfigured endpoint must
/// not make the client replay the token and the DEK to another host. When a
/// CA bundle is configured only that bundle is trusted.
fn build_http(params: &TransitParams, identity: Option<&[u8]>) -> Result<Client, CryptoError> {
    let mut builder = Client::builder()
        .timeout(params.timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = &params.ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem)
            .map_err(|e| transit_err(format!("invalid CA bundle: {e}")))?;
        builder = builder.tls_certs_only(certs);
    }
    if let Some(pem) = identity {
        builder = builder.identity(
            reqwest::Identity::from_pem(pem)
                .map_err(|e| transit_err(format!("invalid client identity: {e}")))?,
        );
    }
    builder
        .build()
        .map_err(|e| transit_err(format!("HTTP client: {e}")))
}

struct Session {
    http: Client,
    params: TransitParams,
    token: Option<SecretString>,
}

impl Session {
    /// `address` with `segments` appended as escaped path segments, keeping
    /// any path prefix the address has.
    fn endpoint(&self, segments: &[&str]) -> Result<Url, CryptoError> {
        let mut url = self.params.address.clone();
        url.path_segments_mut()
            .map_err(|_| transit_err("address cannot be a base URL"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    fn login_url(&self, mount: &str) -> Result<Url, CryptoError> {
        let mut segments = vec!["v1", "auth"];
        segments.extend(mount_segments(mount));
        segments.push("login");
        self.endpoint(&segments)
    }

    async fn login(&mut self) -> Result<(), CryptoError> {
        let (mount, resp) = match &self.params.auth {
            TransitAuth::Token(_) => return Ok(()),
            TransitAuth::Jwt { mount, role, jwt } => {
                let jwt = jwt()?;
                let url = self.login_url(mount)?;
                let body = json!({"role": role, "jwt": jwt.expose_secret()});
                (mount, self.send(&self.http, url, None, &body).await)
            }
            TransitAuth::Cert {
                mount,
                role,
                identity,
            } => {
                let pem = identity()?;
                let http = build_http(&self.params, Some(&pem))?;
                let url = self.login_url(mount)?;
                let body = match role {
                    Some(r) => json!({"name": r}),
                    None => json!({}),
                };
                (mount, self.send(&http, url, None, &body).await)
            }
        };
        let resp = resp.map_err(|e| match e {
            CryptoError::TransitForbidden => unavailable(format!(
                "login to auth/{} was denied (HTTP 403)",
                mount.trim_matches('/')
            )),
            other => other,
        })?;
        let token = resp
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .ok_or_else(|| transit_err("login response has no client_token"))?;
        self.token = Some(SecretString::from(token.to_owned()));
        Ok(())
    }

    async fn send(
        &self,
        http: &Client,
        url: Url,
        token: Option<&SecretString>,
        body: &Value,
    ) -> Result<Value, CryptoError> {
        let mut req = http
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(t) = token {
            let mut value = HeaderValue::from_str(t.expose_secret())
                .map_err(|_| transit_err("token is not a valid header value"))?;
            value.set_sensitive(true);
            req = req.header("X-Vault-Token", value);
        }
        if let Some(ns) = &self.params.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| unavailable(format!("request failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| unavailable(format!("reading response: {e}")))?;
        if status == reqwest::StatusCode::FORBIDDEN {
            return Err(CryptoError::TransitForbidden);
        }
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(unavailable(format!("HTTP {status}: {}", truncate(&text))));
        }
        if status.is_redirection() {
            return Err(transit_err(format!(
                "HTTP {status}: redirects are not followed; point the address at the active node"
            )));
        }
        if !status.is_success() {
            // The body can name the key and mount but never carries secrets.
            return Err(transit_err(format!("HTTP {status}: {}", truncate(&text))));
        }
        serde_json::from_str(&text).map_err(|e| transit_err(format!("invalid JSON: {e}")))
    }

    /// POST `body` to `url`, logging in first when there is no token and once
    /// more when the token is rejected.
    async fn post(&mut self, url: Url, body: &Value) -> Result<Value, CryptoError> {
        if self.token.is_none() {
            match &self.params.auth {
                TransitAuth::Token(t) => self.token = Some(t.clone()),
                TransitAuth::Jwt { .. } | TransitAuth::Cert { .. } => self.login().await?,
            }
        }
        match self
            .send(&self.http, url.clone(), self.token.as_ref(), body)
            .await
        {
            Err(CryptoError::TransitForbidden)
                if !matches!(self.params.auth, TransitAuth::Token(_)) =>
            {
                tracing::debug!("Transit token rejected, logging in again");
                self.login().await?;
                self.send(&self.http, url, self.token.as_ref(), body)
                    .await
                    .map_err(|e| match e {
                        // A fresh token is still refused: the policy may be
                        // fixed at any time, so this is not a permanent error.
                        CryptoError::TransitForbidden => {
                            unavailable("permission denied (HTTP 403) with a fresh token")
                        }
                        other => other,
                    })
            }
            other => other.map_err(forbidden_to_message),
        }
    }
}

/// PEM encoding of a certificate chain (DER, leaf first) followed by a PKCS#8
/// DER private key, as [`TransitAuth::Cert`] expects.
pub fn pem_identity(chain_der: &[&[u8]], pkcs8_key_der: &[u8]) -> Zeroizing<Vec<u8>> {
    fn block(out: &mut Vec<u8>, label: &str, der: &[u8]) {
        out.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
        let b64 = B64.encode(der);
        for line in b64.as_bytes().chunks(64) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    }
    let mut out = Zeroizing::new(Vec::new());
    for der in chain_der {
        block(&mut out, "CERTIFICATE", der);
    }
    block(&mut out, "PRIVATE KEY", pkcs8_key_der);
    out
}

fn forbidden_to_message(e: CryptoError) -> CryptoError {
    match e {
        CryptoError::TransitForbidden => transit_err("permission denied (HTTP 403)"),
        other => other,
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

/// KEK held in an OpenBao Transit key (ADR 0016-v2 §2.5, ADR 0045 §11.2).
pub struct TransitKek {
    client: Arc<TransitClient>,
    key: String,
}

impl TransitKek {
    /// Connect to OpenBao and use the Transit key `key_name`. Nothing is sent
    /// until the first wrap or unwrap.
    pub fn new(params: TransitParams, key_name: impl Into<String>) -> Result<Self, CryptoError> {
        Ok(Self {
            client: Arc::new(TransitClient::new(params)?),
            key: key_name.into(),
        })
    }

    /// The private-key side of the per-site wrap, on `key_name` (an `rsa-*`
    /// Transit key) at `key_version`, sharing this provider's connection.
    pub fn site_key(&self, key_name: impl Into<String>, key_version: u32) -> TransitSiteKey {
        TransitSiteKey {
            client: self.client.clone(),
            key: key_name.into(),
            version: key_version,
        }
    }
}

#[async_trait::async_trait]
impl KekProvider for TransitKek {
    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let mut plain = Zeroizing::new(Vec::with_capacity(DEK_WRAP_AD.len() + 32));
        plain.extend_from_slice(DEK_WRAP_AD);
        plain.extend_from_slice(dek);
        let data = self
            .client
            .call(
                "encrypt",
                &self.key,
                json!({"plaintext": B64.encode(&*plain)}),
            )
            .await?;
        data.get("ciphertext")
            .and_then(Value::as_str)
            .map(|c| c.as_bytes().to_vec())
            .ok_or_else(|| transit_err("encrypt response has no ciphertext"))
    }

    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let ciphertext = std::str::from_utf8(wrapped).map_err(|_| CryptoError::WrappedDekSize)?;
        if !ciphertext.starts_with("vault:v") {
            return Err(CryptoError::WrappedDekSize);
        }
        let data = self
            .client
            .call("decrypt", &self.key, json!({"ciphertext": ciphertext}))
            .await?;
        let plain = decode_plaintext(&data)?;
        let dek = plain
            .strip_prefix(DEK_WRAP_AD)
            .ok_or(CryptoError::WrappedDekSize)?;
        let mut out = Zeroizing::new([0u8; 32]);
        if dek.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        out.copy_from_slice(dek);
        Ok(out)
    }
}

/// Decrypts per-site blobs with an RSA Transit key.
pub struct TransitSiteKey {
    client: Arc<TransitClient>,
    key: String,
    version: u32,
}

#[async_trait::async_trait]
impl SiteKeyUnwrapper for TransitSiteKey {
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let data = self.client.call(
            "decrypt",
            &self.key,
            json!({"ciphertext": format!("vault:v{}:{}", self.version, B64.encode(ciphertext))}),
        )
        .await?;
        decode_plaintext(&data)
    }
}

fn decode_plaintext(data: &Value) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let b64 = data
        .get("plaintext")
        .and_then(Value::as_str)
        .ok_or_else(|| transit_err("decrypt response has no plaintext"))?;
    B64.decode(b64)
        .map(Zeroizing::new)
        .map_err(|_| transit_err("plaintext is not base64"))
}

#[cfg(test)]
mod tests;
