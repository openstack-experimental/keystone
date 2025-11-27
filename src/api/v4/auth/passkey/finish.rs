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

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use tracing::debug;

use crate::api::v4::auth::passkey::types::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, HmacGetSecretOutput,
    PasskeyAuthenticationFinishRequest,
};
use crate::api::{
    error::{KeystoneApiError, WebauthnError},
    v4::auth::token::types::{Token as ApiResponseToken, TokenResponse},
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::token::TokenApi;

/// Finish user passkey authentication.
///
/// Exchange the challenge signed with one of the users passkeys or security
/// devices for the unscoped Keystone API token.
#[utoipa::path(
    post,
    path = "/finish",
    operation_id = "/auth/passkey/finish:post",
    request_body = PasskeyAuthenticationFinishRequest,
    responses(
        (status = OK, description = "Authentication Token object", body = TokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        )
        ),
    ),
    tags = ["passkey", "auth"]
)]
#[tracing::instrument(
    name = "api::user_webauthn_credential_login_finish",
    level = "debug",
    skip(state, req)
)]
pub(super) async fn finish(
    State(state): State<ServiceState>,
    Json(req): Json<PasskeyAuthenticationFinishRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let user_id = req.user_id.clone();
    // TODO: Wrap all errors into the Unauthorized, but log the error
    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_webauthn_credential_authentication_state(&state, &user_id)
        .await?
    {
        // We explicitly try to deserealize the request data directly into the
        // underlying webauthn_rs type.
        match state
            .webauthn
            .finish_passkey_authentication(&req.try_into()?, &s)
        {
            Ok(_auth_result) => {
                // Here should the DB update happen (last_used, ...)
            }
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                return Err(WebauthnError::Unknown)?;
            }
        };
        state
            .provider
            .get_identity_provider()
            .delete_user_webauthn_credential_authentication_state(&state, &user_id)
            .await?;
    }
    let authed_info = AuthenticatedInfo::builder()
        .user_id(user_id.clone())
        .user(
            state
                .provider
                .get_identity_provider()
                .get_user(&state, &user_id)
                .await
                .map(|x| {
                    x.ok_or_else(|| KeystoneApiError::NotFound {
                        resource: "user".into(),
                        identifier: user_id,
                    })
                })??,
        )
        // Unless Keystone support passkey auth method we use x509 (which it technically IS).
        .methods(vec!["x509".into()])
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    let token =
        state
            .provider
            .get_token_provider()
            .issue_token(authed_info, AuthzInfo::Unscoped, None)?;

    let api_token = TokenResponse {
        token: ApiResponseToken::from_provider_token(&state, &token).await?,
    };
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}

impl TryFrom<HmacGetSecretOutput> for webauthn_rs_proto::extensions::HmacGetSecretOutput {
    type Error = KeystoneApiError;
    fn try_from(val: HmacGetSecretOutput) -> Result<Self, Self::Error> {
        Ok(Self {
            output1: URL_SAFE.decode(val.output1)?.into(),
            output2: val
                .output2
                .map(|s2| URL_SAFE.decode(s2))
                .transpose()?
                .map(Into::into),
        })
    }
}

impl TryFrom<AuthenticationExtensionsClientOutputs>
    for webauthn_rs_proto::extensions::AuthenticationExtensionsClientOutputs
{
    type Error = KeystoneApiError;
    fn try_from(val: AuthenticationExtensionsClientOutputs) -> Result<Self, Self::Error> {
        Ok(Self {
            appid: val.appid,
            hmac_get_secret: val.hmac_get_secret.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<AuthenticatorAssertionResponseRaw>
    for webauthn_rs_proto::auth::AuthenticatorAssertionResponseRaw
{
    type Error = KeystoneApiError;
    fn try_from(val: AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticator_data: URL_SAFE.decode(val.authenticator_data)?.into(),
            client_data_json: URL_SAFE.decode(val.client_data_json)?.into(),
            signature: URL_SAFE.decode(val.signature)?.into(),
            user_handle: val
                .user_handle
                .map(|uh| URL_SAFE.decode(uh))
                .transpose()?
                .map(Into::into),
        })
    }
}

impl TryFrom<PasskeyAuthenticationFinishRequest> for webauthn_rs::prelude::PublicKeyCredential {
    type Error = KeystoneApiError;
    fn try_from(req: PasskeyAuthenticationFinishRequest) -> Result<Self, Self::Error> {
        Ok(webauthn_rs::prelude::PublicKeyCredential {
            id: req.id,
            extensions: req.extensions.try_into()?,
            raw_id: URL_SAFE.decode(req.raw_id)?.into(),
            response: req.response.try_into()?,
            type_: req.type_,
        })
    }
}
