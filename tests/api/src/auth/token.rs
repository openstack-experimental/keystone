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

use std::borrow::Cow;

use eyre::{Result, eyre};
use reqwest::header::HeaderValue;
use secrecy::{ExposeSecret, SecretString};

use crate::common::*;
use openstack_keystone_api_types::scope::Scope;
use openstack_keystone_api_types::v3::auth::token::{
    AuthRequest, AuthRequestInner, Identity, IdentityBuilder, Token, TokenAuthBuilder,
    TokenResponse,
};
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::api::RawQueryAsync;
use openstack_sdk::api::rest_endpoint_prelude::*;

/// Perform token check request.
fn sensitive_header(secret: &SecretString) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(secret.expose_secret())?;
    header.set_sensitive(true);
    Ok(header)
}

pub async fn check_token(
    tc: &TestClient,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    let header = sensitive_header(subject_token)?;
    Ok(tc
        .client
        .get(tc.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", header)
        .send()
        .await?)
}

/// `POST /v3/auth/tokens` for an arbitrary identity method (password, token,
/// application_credential, a WASM auth-plugin method, ...) — generic sibling
/// of `k8s_auth::auth::K8sAuthenticationRequest`, which only covers the
/// k8s-specific endpoint.
struct AuthTokenRequest {
    identity: Identity,
    scope: Option<Scope>,
}

/// Check a token with an explicit (or missing) authentication token.
///
/// This bypasses any default header on `tc.client`, so 401 tests can prove
/// that a missing or invalid `X-Auth-Token` fails closed.
pub async fn check_token_with_auth(
    tc: &TestClient,
    auth_token: Option<&SecretString>,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    subject_request(tc, http::Method::GET, auth_token, subject_token).await
}

/// Revoke a token using the caller authentication configured on `tc`.
pub async fn revoke_token(
    tc: &TestClient,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    let header = sensitive_header(subject_token)?;
    Ok(tc
        .client
        .delete(tc.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", header)
        .send()
        .await?)
}

/// Revoke a token with an explicit (or missing) authentication token.
pub async fn revoke_token_with_auth(
    tc: &TestClient,
    auth_token: Option<&SecretString>,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    subject_request(tc, http::Method::DELETE, auth_token, subject_token).await
}

async fn subject_request(
    tc: &TestClient,
    method: http::Method,
    auth_token: Option<&SecretString>,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    let mut request = reqwest::Client::new()
        .request(method, tc.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", sensitive_header(subject_token)?);
    if let Some(auth_token) = auth_token {
        request = request.header("x-auth-token", sensitive_header(auth_token)?);
    }
    Ok(request.send().await?)
}

/// Authenticate an arbitrary identity through raw HTTP.
///
/// Unlike [`auth_token`], this returns non-success responses directly so
/// negative auth-method tests can assert the exact status without inspecting
/// an error string.
pub async fn authenticate_identity(
    tc: &TestClient,
    identity: Identity,
    scope: Option<Scope>,
) -> Result<reqwest::Response> {
    let request = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    Ok(reqwest::Client::new()
        .post(tc.base_url.join("v3/auth/tokens")?)
        .json(&request)
        .send()
        .await?)
}

/// The token remains a `SecretString` throughout request construction. The
/// returned response lets negative tests assert the exact HTTP status without
/// including the credential in an error or panic value.
pub async fn authenticate_by_token(
    tc: &TestClient,
    token: &SecretString,
    scope: Option<Scope>,
) -> Result<reqwest::Response> {
    let identity = IdentityBuilder::default()
        .methods(vec!["token".into()])
        .token(TokenAuthBuilder::default().id(token.clone()).build()?)
        .build()?;
    authenticate_identity(tc, identity, scope).await
}

impl RestEndpoint for AuthTokenRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "auth/tokens".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let auth = AuthRequest {
            auth: AuthRequestInner {
                identity: self.identity.clone(),
                scope: self.scope.clone(),
            },
        };
        Ok(Some(("application/json", serde_json::to_vec(&auth)?)))
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Sends the identity/scope and returns the issued `Token` plus its
/// `X-Subject-Token` secret. Mirrors `k8s_auth::auth::k8s_auth`'s raw-response
/// handling: callers that expect rejection must match on the `Result`
/// themselves instead of using `?`, since `raw_query_async` may surface a
/// non-2xx as `Ok(response)` or `Err` depending on status code.
pub async fn auth_token(
    client: &AsyncOpenStack,
    identity: Identity,
    scope: Option<Scope>,
) -> Result<(Token, SecretString)> {
    let rsp: http::Response<bytes::Bytes> = AuthTokenRequest { identity, scope }
        .raw_query_async_ll(client, Some(false))
        .await?;

    if rsp.status() != http::StatusCode::CREATED {
        return Err(eyre!(
            "Authentication failed with {}: {}",
            rsp.status(),
            String::from_utf8_lossy(rsp.body())
        ));
    }

    let token = SecretString::from(
        rsp.headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("X-Subject-Token header missing"))?
            .to_str()?,
    );
    let token_info: TokenResponse = serde_json::from_slice(rsp.body())?;
    Ok((token_info.token, token))
}
