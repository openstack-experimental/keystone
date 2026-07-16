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
    AuthRequest, AuthRequestInner, Identity, Token, TokenResponse,
};
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::api::RawQueryAsync;
use openstack_sdk::api::rest_endpoint_prelude::*;

/// Perform token check request.
pub async fn check_token(
    tc: &TestClient,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    let mut hdr = HeaderValue::from_str(subject_token.expose_secret())?;
    hdr.set_sensitive(true);
    Ok(tc
        .client
        .get(tc.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", hdr)
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
