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
//! Common functionality used in the functional tests.

use eyre::{Report, eyre};
use reqwest::{Client, StatusCode};

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;

/// Get the password auth identity struct
pub fn get_password_auth<U, P, DID>(
    username: U,
    password: P,
    domain_id: DID,
) -> Result<PasswordAuth, Report>
where
    U: AsRef<str>,
    P: AsRef<str>,
    DID: AsRef<str>,
{
    PasswordAuthBuilder::default()
        .user(
            UserPasswordBuilder::default()
                .name(username.as_ref())
                .password(password.as_ref())
                .domain(DomainBuilder::default().id(domain_id.as_ref()).build()?)
                .build()?,
        )
        .build()
        .map_err(Into::into)
}

/// Authenticate using the passed password auth and the scope.
pub async fn auth<U>(
    keystone_url: U,
    password_auth: PasswordAuth,
    scope: Option<Scope>,
) -> Result<String, Report>
where
    U: AsRef<str> + std::fmt::Display,
{
    let identity = IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(password_auth)
        .build()?;
    let auth_request = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    let client = Client::new();
    let rsp = client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&serde_json::to_value(auth_request)?)
        .send()
        .await?;

    tracing::debug!("Authentication response: {:?}", rsp);

    if rsp.status() != StatusCode::OK {
        return Err(eyre!("Authentication failed with {}", rsp.status()));
    }

    Ok(rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
        .to_str()?
        .into())
    //.unwrap()
}

/// Authenticate using the token.
pub async fn auth_with_token<U, S>(
    keystone_url: U,
    token: S,
    scope: Option<Scope>,
) -> Result<String, Report>
where
    S: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
{
    let identity = IdentityBuilder::default()
        .methods(vec!["token".into()])
        .token(TokenAuthBuilder::default().id(token.as_ref()).build()?)
        .build()?;
    let auth_request = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    let client = Client::new();
    let rsp = client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&serde_json::to_value(auth_request)?)
        .send()
        .await?;
    Ok(rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
        .to_str()?
        .to_string())
}

/// Perform token check request.
pub async fn check_token<U, S1, S2>(
    client: &Client,
    keystone_url: U,
    auth_token: S1,
    subject_token: S2,
) -> Result<reqwest::Response, reqwest::Error>
where
    S1: AsRef<str> + std::fmt::Display,
    S2: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
{
    client
        .get(format!("{}/v3/auth/tokens", keystone_url.as_ref()))
        .header("x-auth-token", auth_token.as_ref())
        .header("x-subject-token", subject_token.as_ref())
        .send()
        .await
}
