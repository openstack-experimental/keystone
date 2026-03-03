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
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use derive_builder::Builder;
use eyre::{Context, Result, eyre};
use reqwest::StatusCode;
use tracing::info;
use url::Url;

use openstack_keystone_api_types::webauthn::register::*;
use openstack_keystone_api_types::webauthn::{PublicKeyCredentialCreationOptions, auth::*};
use openstack_sdk_core::{
    AsyncOpenStack,
    api::{QueryAsync, RawQueryAsync},
};
use openstack_sdk_core::{api::rest_endpoint_prelude::*, types::identity::v3::AuthResponse};
use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};

mod register;
mod roundtrip;

#[derive(Builder, Default, Clone, Debug)]
#[builder(setter(strip_option, into))]
struct PasskeyRegisterStartRequest<'a> {
    passkey: PasskeyCreate,
    user_id: Cow<'a, str>,
}

impl RestEndpoint for PasskeyRegisterStartRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/passkeys/register_start", self.user_id.as_ref()).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("passkey", serde_json::to_value(&self.passkey)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("public_key".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

async fn start_registration<U: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    req: PasskeyCreate,
) -> Result<PublicKeyCredentialCreationOptions> {
    Ok(PasskeyRegisterStartRequestBuilder::default()
        .user_id(user_id.as_ref())
        .passkey(req)
        .build()?
        .query_async(client.as_ref())
        .await?)
}

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
struct PasskeyRegisterFinishRequest<'a> {
    passkey: UserPasskeyRegistrationFinishRequest,
    user_id: Cow<'a, str>,
}

impl RestEndpoint for PasskeyRegisterFinishRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/passkeys/register_finish", self.user_id.as_ref()).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        Ok(Some((
            "application/json",
            serde_json::to_value(&self.passkey)?
                .to_string()
                .into_bytes(),
        )))
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("passkey".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

async fn finish_registration<U: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    req: UserPasskeyRegistrationFinishRequest,
) -> Result<Passkey> {
    Ok(PasskeyRegisterFinishRequestBuilder::default()
        .user_id(user_id.as_ref())
        .passkey(req)
        .build()?
        .query_async(client.as_ref())
        .await?)
}

#[derive(Builder, Default, Clone, Debug)]
#[builder(setter(strip_option, into))]
struct PasskeyAuthStartRequest<'a> {
    user_id: Cow<'a, str>,
}

impl RestEndpoint for PasskeyAuthStartRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "auth/passkey/start".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("user_id", serde_json::to_value(&self.user_id)?);
        params.into_body_with_root_key("passkey")
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

async fn start_auth<U: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
) -> Result<PasskeyAuthenticationStartResponse> {
    Ok(PasskeyAuthStartRequestBuilder::default()
        .user_id(user_id.as_ref())
        .build()?
        .query_async(client.as_ref())
        .await?)
}

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
struct PasskeyAuthFinishRequest {
    passkey: PasskeyAuthenticationFinishRequest,
}

impl RestEndpoint for PasskeyAuthFinishRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "auth/passkey/finish".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        Ok(Some((
            "application/json",
            serde_json::to_value(&self.passkey)?
                .to_string()
                .into_bytes(),
        )))
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

async fn finish_auth(
    client: &Arc<AsyncOpenStack>,
    data: PasskeyAuthenticationFinishRequest,
) -> Result<http::Response<bytes::Bytes>> {
    Ok(PasskeyAuthFinishRequestBuilder::default()
        .passkey(data)
        .build()?
        .raw_query_async(client.as_ref())
        .await?)
}

async fn register_user_passkey<B, U: AsRef<str>, D: Into<String>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    origin: Url,
    authenticator: &mut WebauthnAuthenticator<B>,
    description: Option<D>,
) -> Result<()>
where
    B: AuthenticatorBackend,
{
    let reg_challenge = start_registration(client, user_id.as_ref(), PasskeyCreate::default())
        .await
        .wrap_err("start registration")?;
    info!("registration challenge data: {:?}", reg_challenge);

    let reg_result = authenticator
        .do_registration(
            origin.clone(),
            webauthn_authenticator_rs::prelude::CreationChallengeResponse {
                public_key: reg_challenge.try_into()?,
            },
        )
        .wrap_err("do registration")?;
    info!("registration challenge response: {:?}", reg_result);

    let mut finish_req: UserPasskeyRegistrationFinishRequest = reg_result.into();
    if let Some(val) = description {
        finish_req.description = Some(val.into());
    }
    let reg_finish_response = finish_registration(client, user_id.as_ref(), finish_req)
        .await
        .wrap_err("finish registration")?;
    info!("registration finish response: {:?}", reg_finish_response);
    Ok(())
}

async fn auth_passkey<B: AuthenticatorBackend, U: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    origin: Url,
    authenticator: &mut WebauthnAuthenticator<B>,
) -> Result<AuthResponse> {
    let auth_challenge = start_auth(client, user_id.as_ref()).await?;
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
        client,
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

    let _token = rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
        .to_str()?
        .to_string();

    let token_info: AuthResponse = serde_json::from_slice(rsp.body())?;

    Ok(token_info)
}
