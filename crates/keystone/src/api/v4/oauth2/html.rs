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

use axum::{
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::renderer::{ConsentCtx, DeviceEntryCtx, DeviceResultCtx, ErrorCtx, LoginCtx, renderer};

/// Wrap a rendered page into a `200` response with the security headers, or
/// fall back to the error page when the (operator-supplied) template fails
/// at render time.
fn page(rendered: Result<String, minijinja::Error>) -> Response {
    match rendered {
        Ok(body) => security_headers((StatusCode::OK, Html(body)).into_response()),
        Err(e) => {
            tracing::error!("OAuth2 page template failed to render: {e}");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

pub(super) fn login_page(ctx: &LoginCtx) -> Response {
    page(renderer().render_login(ctx))
}

pub(super) fn consent_page(ctx: &ConsentCtx) -> Response {
    page(renderer().render_consent(ctx))
}

pub(super) fn device_entry_page(ctx: &DeviceEntryCtx) -> Response {
    page(renderer().render_device_entry(ctx))
}

pub(super) fn device_result_page(ctx: &DeviceResultCtx) -> Response {
    page(renderer().render_device_result(ctx))
}

/// Operator stylesheets and logos load from this origin (or `data:` images);
/// scripts and framing stay blocked. `form-action` is deliberately not set:
/// browsers apply it to the redirect that answers a form POST, which would
/// block the redirect back to the relying party's `redirect_uri`.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; style-src 'self'; img-src 'self' data:; \
     script-src 'none'; frame-ancestors 'none'";

/// ADR 0026 §8: defense-in-depth headers on every server-rendered OP
/// response (HTML pages and the redirects between them alike).
pub(super) fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
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
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    no_store(response)
}

/// RFC 6749 §5.1: token (and other credential-bearing) responses must not
/// be stored by browsers or shared caches. Also applied to HTML pages and
/// redirects since they carry CSRF tokens and authorization codes.
pub(super) fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub(super) fn error_page(status: StatusCode, message: &str) -> Response {
    let body = renderer()
        .render_error(&ErrorCtx {
            message: message.to_string(),
        })
        .unwrap_or_else(|_| "internal error".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_headers_disable_caching_and_referrer() {
        let response = security_headers(StatusCode::OK.into_response());
        let headers = response.headers();
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["pragma"], "no-cache");
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }

    #[test]
    fn test_csp_allows_assets_but_not_scripts() {
        let response = security_headers(StatusCode::OK.into_response());
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("style-src 'self'"));
        assert!(csp.contains("img-src 'self' data:"));
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_error_page_has_no_store() {
        let response = error_page(StatusCode::BAD_REQUEST, "bad");
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
