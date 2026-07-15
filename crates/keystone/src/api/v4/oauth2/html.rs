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
//! Server-rendered HTML helpers shared by every human-facing OAuth2 flow
//! (`authorize`'s `authorization_code` login/consent, `device`'s RFC 8628
//! verification page): security headers, the login/consent/error
//! templates, and CSRF token derivation (ADR 0026 §8).

use askama::Template;
use axum::{
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

#[derive(Template)]
#[template(path = "oauth2/login.html")]
pub(super) struct LoginTemplate<'a> {
    pub(super) client_id: &'a str,
    pub(super) csrf_token: &'a str,
    pub(super) error: Option<&'a str>,
    pub(super) action: String,
}

#[derive(Template)]
#[template(path = "oauth2/consent.html")]
pub(super) struct ConsentTemplate<'a> {
    pub(super) client_id: &'a str,
    pub(super) scopes: &'a [String],
    pub(super) csrf_token: &'a str,
    pub(super) action: String,
}

#[derive(Template)]
#[template(path = "oauth2/error.html")]
pub(super) struct ErrorTemplate<'a> {
    pub(super) message: &'a str,
}

/// ADR 0026 §8: defense-in-depth headers on every server-rendered OP
/// response (HTML pages and the redirects between them alike).
pub(super) fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );
    response
}

pub(super) fn error_page(status: StatusCode, message: &str) -> Response {
    let body = ErrorTemplate { message }
        .render()
        .unwrap_or_else(|_| message.to_string());
    security_headers((status, Html(body)).into_response())
}

pub(super) fn too_many_requests(retry_after: u64) -> Response {
    let mut response = error_page(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, retry_after.into());
    response
}

pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// CSRF token derivation (ADR 0026 §8): `HMAC-SHA256(secret, parts.concat())`.
/// `parts` are typically attacker-choosable (whoever initiates the flow may
/// not be the victim), so the secret -- generated server-side and never
/// sent to the client in cleartext -- is what an attacker crafting a link
/// or code for a victim to use cannot supply.
pub(super) fn compute_csrf_token(secret: &str, parts: &[&str]) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    for part in parts {
        mac.update(part.as_bytes());
    }
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}
