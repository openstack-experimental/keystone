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

use eyre::{OptionExt, Result, WrapErr, eyre};
use reqwest::{
    Client, ClientBuilder, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use url::Url;

use openstack_keystone_api_types::scope::*;
use openstack_keystone_api_types::v3::auth::token::*;

pub struct TestClient {
    pub client: Client,
    pub base_url: Url,
    pub auth: Option<TokenResponse>,
    pub token: Option<SecretString>,
}

impl TestClient {
    pub fn default() -> Result<Self> {
        Ok(Self {
            client: Client::new(),
            base_url: env::var("KEYSTONE_URL")
                .wrap_err("KEYSTONE_URL must be set")?
                .parse()?,
            auth: None,
            token: None,
        })
    }

    pub fn with_base_url<U: AsRef<str>>(base_url: Option<U>) -> Result<Self> {
        if let Some(base_url) = base_url {
            Ok(Self {
                client: Client::new(),
                base_url: base_url.as_ref().parse()?,
                auth: None,
                token: None,
            })
        } else {
            Self::default()
        }
    }

    pub async fn auth(&mut self, identity: Identity, scope: Option<Scope>) -> Result<&mut Self> {
        let new = self;
        let auth_request = AuthRequest {
            auth: AuthRequestInner { identity, scope },
        };
        let rsp = new
            .client
            .post(new.base_url.join("v3/auth/tokens")?)
            .json(&serde_json::to_value(auth_request)?)
            .send()
            .await?;

        if rsp.status() != StatusCode::OK {
            return Err(eyre!("Authentication failed with {}", rsp.status()));
        }

        let token = rsp
            .headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
            .to_str()?
            .to_string();

        new.token = Some(SecretString::from(token.clone()));
        new.auth = Some(rsp.json().await?);
        let mut token = HeaderValue::from_str(&token)?;
        token.set_sensitive(true);
        new.client = ClientBuilder::new()
            .default_headers(HeaderMap::from_iter([(
                HeaderName::from_static("x-auth-token"),
                token,
            )]))
            .build()?;
        Ok(new)
    }

    /// Authenticate using the passed password auth and the scope.
    pub async fn auth_password(
        &mut self,
        password_auth: PasswordAuth,
        scope: Option<Scope>,
    ) -> Result<&mut Self> {
        let new = self;
        let identity = IdentityBuilder::default()
            .methods(vec!["password".into()])
            .password(password_auth)
            .build()?;
        new.auth(identity, scope).await?;
        Ok(new)
    }

    pub async fn auth_admin(&mut self) -> Result<&mut Self> {
        let new = self;
        new.auth_password(
            get_password_auth(
                "admin",
                env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
                "default",
            )?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .name("admin")
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;
        Ok(new)
    }

    pub async fn auth_token<S>(&mut self, token: S, scope: Option<Scope>) -> Result<&mut Self>
    where
        S: AsRef<str> + std::fmt::Display,
    {
        let new = self;
        let identity = IdentityBuilder::default()
            .methods(vec!["token".into()])
            .token(TokenAuthBuilder::default().id(token.as_ref()).build()?)
            .build()?;
        new.auth(identity, scope).await?;
        Ok(new)
    }

    pub async fn rescope(&mut self, scope: Option<Scope>) -> Result<&mut Self> {
        let new = self;

        let identity = IdentityBuilder::default()
            .methods(vec!["token".into()])
            .token(
                TokenAuthBuilder::default()
                    .id(new
                        .token
                        .as_ref()
                        .ok_or_eyre("must be authenticated")?
                        .expose_secret())
                    .build()?,
            )
            .build()?;

        let auth_request = AuthRequest {
            auth: AuthRequestInner { identity, scope },
        };
        let rsp = new
            .client
            .post(new.base_url.join("v3/auth/tokens")?)
            .json(&serde_json::to_value(auth_request)?)
            .send()
            .await?;

        if rsp.status() != StatusCode::OK {
            return Err(eyre!("Authentication failed with {}", rsp.status()));
        }

        let token = rsp
            .headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
            .to_str()?
            .to_string();

        new.token = Some(SecretString::from(token.clone()));
        new.auth = Some(rsp.json().await?);
        let mut token = HeaderValue::from_str(&token)?;
        token.set_sensitive(true);
        new.client = ClientBuilder::new()
            .default_headers(HeaderMap::from_iter([(
                HeaderName::from_static("x-auth-token"),
                token,
            )]))
            .build()?;
        Ok(new)
    }
}

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
