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

use eyre::{Report, Result, eyre};
use reqwest::{
    Client, ClientBuilder, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::env;

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;
use openstack_keystone::api::v3::role::types::{Role, RoleList};

/// Get the password auth identity struct
pub fn get_password_auth<U, P, DID>(
    username: U,
    password: P,
    domain_id: DID,
) -> Result<PasswordAuth>
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
pub async fn auth(
    password_auth: PasswordAuth,
    scope: Option<Scope>,
) -> Result<(TokenResponse, String)> {
    let identity = IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(password_auth)
        .build()?;
    let auth_request = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    let client = Client::new();
    let rsp = client
        .post(build_url("v3/auth/tokens"))
        .json(&serde_json::to_value(auth_request)?)
        .send()
        .await?;

    tracing::debug!("Authentication response: {:?}", rsp);

    if rsp.status() != StatusCode::OK {
        return Err(eyre!("Authentication failed with {}", rsp.status()));
    }

    let token: String = rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
        .to_str()?
        .into();
    let rsp: TokenResponse = rsp.json().await?;
    Ok((rsp, token))
}

/// Authenticate using the token.
pub async fn auth_with_token<S>(token: S, scope: Option<Scope>) -> Result<String, Report>
where
    S: AsRef<str> + std::fmt::Display,
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
        .post(build_url("v3/auth/tokens"))
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
pub async fn check_token<S>(
    client: &Client,
    subject_token: S,
) -> Result<reqwest::Response, reqwest::Error>
where
    S: AsRef<str> + std::fmt::Display,
{
    client
        .get(build_url("v3/auth/tokens"))
        .header("x-subject-token", subject_token.as_ref())
        .send()
        .await
}

/// Authenticate using the passed password auth and the scope.
pub async fn get_auth_client<A: AsRef<str>>(auth_token: A) -> Result<Client> {
    Ok(ClientBuilder::new()
        .default_headers(HeaderMap::from_iter([(
            HeaderName::from_static("x-auth-token"),
            HeaderValue::from_str(auth_token.as_ref())?,
        )]))
        .build()?)
}

/// Authenticate as an admin and return the token with the info
pub async fn get_admin_auth(_client: &Client) -> Result<(TokenResponse, String)> {
    auth(
        get_password_auth(
            "admin",
            env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
            "default",
        )
        .expect("can't prepare password auth"),
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .name("admin")
                .domain(DomainBuilder::default().id("default").build()?)
                .build()?,
        )),
    )
    .await
}

pub fn build_url<U>(relative: U) -> String
where
    U: AsRef<str> + std::fmt::Display,
{
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    format!("{}/{}", keystone_url, relative)
}

/// List roles.
pub async fn list_roles(client: &Client) -> Result<Vec<Role>> {
    Ok(client
        .get(build_url("v3/roles"))
        .send()
        .await?
        .json::<RoleList>()
        .await?
        .roles)
}
