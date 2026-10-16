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
//! `/v4/auth/tokens` helpers.
//!
//! `crates/keystone/src/api/v4/auth/token/mod.rs` re-mounts the v3 router
//! and `.../types.rs` re-exports the v3 types, so the wire contract matches
//! v3 — only the version prefix differs.
//!
//! These are raw `reqwest` calls rather than `openstack_sdk` endpoints:
//! `TestClient` hardcodes `v3/auth/tokens`, and the show/revoke operations
//! need an `x-subject-token` header distinct from the caller's
//! `x-auth-token`, which the SDK's session layer owns.

use std::env;

use eyre::{Result, WrapErr, eyre};
use reqwest::Response;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use openstack_keystone_api_types::scope::Scope;
use openstack_keystone_api_types::v3::auth::token::{
    AuthRequest, AuthRequestInner, Identity, TokenResponse,
};

fn base_url() -> Result<Url> {
    Ok(env::var("KEYSTONE_URL")
        .wrap_err("KEYSTONE_URL must be set")?
        .parse()?)
}

/// `POST /v4/auth/tokens`, returning the raw response so callers can assert
/// on rejection statuses themselves.
pub async fn authenticate_v4_raw(identity: Identity, scope: Option<Scope>) -> Result<Response> {
    let body = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    Ok(crate::common::http_client()
        .post(base_url()?.join("v4/auth/tokens")?)
        .json(&serde_json::to_value(body)?)
        .send()
        .await?)
}

/// `POST /v4/auth/tokens` for a successful authentication, returning the
/// issued token body and its `X-Subject-Token` secret.
pub async fn authenticate_v4(
    identity: Identity,
    scope: Option<Scope>,
) -> Result<(TokenResponse, SecretString)> {
    let rsp = authenticate_v4_raw(identity, scope).await?;
    if rsp.status() != reqwest::StatusCode::CREATED {
        let status = rsp.status();
        let body = rsp.text().await.unwrap_or_default();
        return Err(eyre!("v4 authentication failed with {status}: {body}"));
    }
    let subject = SecretString::from(
        rsp.headers()
            .get("x-subject-token")
            .ok_or_else(|| eyre!("X-Subject-Token header missing from /v4/auth/tokens"))?
            .to_str()?,
    );
    Ok((rsp.json().await?, subject))
}

/// `GET /v4/auth/tokens`: `caller` presents `x-auth-token`, `subject` is the
/// token being validated.
pub async fn validate_token_v4(caller: &SecretString, subject: &SecretString) -> Result<Response> {
    Ok(crate::common::http_client()
        .get(base_url()?.join("v4/auth/tokens")?)
        .header("x-auth-token", caller.expose_secret())
        .header("x-subject-token", subject.expose_secret())
        .send()
        .await?)
}

/// `DELETE /v4/auth/tokens`, same header split as [`validate_token_v4`].
pub async fn revoke_token_v4(caller: &SecretString, subject: &SecretString) -> Result<Response> {
    Ok(crate::common::http_client()
        .delete(base_url()?.join("v4/auth/tokens")?)
        .header("x-auth-token", caller.expose_secret())
        .header("x-subject-token", subject.expose_secret())
        .send()
        .await?)
}
