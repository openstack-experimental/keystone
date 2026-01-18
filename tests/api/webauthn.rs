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
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use eyre::{Result, eyre};
use reqwest::{
    ClientBuilder, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use secrecy::SecretString;
use tracing::info;
use url::Url;

use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};

use openstack_keystone::webauthn::api::types::auth::*;
use openstack_keystone::webauthn::api::types::register::*;

use crate::common::*;

mod register;
mod roundtrip;

pub async fn start_registration<U: AsRef<str>>(
    tc: &TestClient,
    user_id: U,
    req: PasskeyCreate,
) -> Result<UserPasskeyRegistrationStartResponse> {
    Ok(tc
        .client
        .post(
            tc.base_url
                .join(format!("v4/users/{}/passkeys/register_start", user_id.as_ref()).as_str())?,
        )
        .json(&UserPasskeyRegistrationStartRequest { passkey: req })
        .send()
        .await?
        .json::<UserPasskeyRegistrationStartResponse>()
        .await?)
}

pub async fn finish_registration<U: AsRef<str>>(
    tc: &TestClient,
    user_id: U,
    req: UserPasskeyRegistrationFinishRequest,
) -> Result<PasskeyResponse> {
    Ok(tc
        .client
        .post(
            tc.base_url
                .join(format!("v4/users/{}/passkeys/register_finish", user_id.as_ref()).as_str())?,
        )
        .json(&req)
        .send()
        .await?
        .json::<PasskeyResponse>()
        .await?)
}

pub async fn start_auth<U: AsRef<str>>(
    tc: &TestClient,
    user_id: U,
) -> Result<PasskeyAuthenticationStartResponse> {
    Ok(tc
        .client
        .post(tc.base_url.join("v4/auth/passkey/start")?)
        .json(&PasskeyAuthenticationStartRequest {
            passkey: PasskeyUserAuthenticationRequest {
                user_id: user_id.as_ref().into(),
            },
        })
        .send()
        .await?
        .json::<PasskeyAuthenticationStartResponse>()
        .await?)
}

pub async fn finish_auth(
    tc: &TestClient,
    data: PasskeyAuthenticationFinishRequest,
) -> Result<reqwest::Response> {
    Ok(tc
        .client
        .post(tc.base_url.join("v4/auth/passkey/finish")?)
        .json(&data)
        .send()
        .await?)
}

pub async fn register_user_passkey<B, U: AsRef<str>, D: Into<String>>(
    tc: &TestClient,
    user_id: U,
    origin: Url,
    authenticator: &mut WebauthnAuthenticator<B>,
    description: Option<D>,
) -> Result<()>
where
    B: AuthenticatorBackend,
{
    let reg_challenge = start_registration(tc, user_id.as_ref(), PasskeyCreate::default()).await?;
    info!("registration challenge data: {:?}", reg_challenge);

    let reg_result = authenticator.do_registration(
        origin.clone(),
        webauthn_authenticator_rs::prelude::CreationChallengeResponse {
            public_key: reg_challenge.public_key.try_into()?,
        },
    )?;
    info!("registration challenge response: {:?}", reg_result);

    let mut finish_req: UserPasskeyRegistrationFinishRequest = reg_result.into();
    if let Some(val) = description {
        finish_req.description = Some(val.into());
    }
    let reg_finish_response = finish_registration(tc, user_id.as_ref(), finish_req).await?;
    info!("registration finish response: {:?}", reg_finish_response);
    Ok(())
}

impl TestClient {
    pub async fn auth_passkey<B: AuthenticatorBackend, U: AsRef<str>>(
        self,
        user_id: U,
        origin: Url,
        authenticator: &mut WebauthnAuthenticator<B>,
    ) -> Result<Self> {
        let mut new = self;
        let auth_challenge = start_auth(&new, user_id.as_ref()).await?;
        info!("start auth challenge: {:?}", auth_challenge);

        let auth_challenge_response = authenticator.do_authentication(
            origin,
            webauthn_authenticator_rs::prelude::RequestChallengeResponse {
                public_key: auth_challenge.public_key.try_into()?,
                mediation: auth_challenge.mediation.map(Into::into),
            },
        )?;

        info!("auth challenge response: is {:?}", auth_challenge_response);
        let rsp = finish_auth(
            &new,
            PasskeyAuthenticationFinishRequest {
                id: auth_challenge_response.id,
                extensions: auth_challenge_response.extensions.into(),
                raw_id: URL_SAFE.encode(auth_challenge_response.raw_id),
                response: auth_challenge_response.response.into(),
                type_: auth_challenge_response.type_,
                user_id: user_id.as_ref().to_string(),
            },
        )
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
