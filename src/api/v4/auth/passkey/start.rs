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

use axum::{Json, extract::State, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use tracing::debug;
use webauthn_rs::prelude::*;

use super::types::*;
use crate::api::error::{KeystoneApiError, WebauthnError};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Start passkey authentication for the user.
///
/// Initiate a passkey login for the user. The user must have at least one
/// passkey previously registered. When the user does not exist a fake challenge
/// is being returned to prevent id scanning.
#[utoipa::path(
    post,
    path = "/start",
    operation_id = "/auth/passkey/start:post",
    responses(
        (status = OK, description = "Challenge that must be signed with any of the user passkeys", body = PasskeyAuthenticationStartResponse),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tags = ["passkey", "auth"]
)]
#[tracing::instrument(
    name = "api::user_webauthn_credential_authentication_start",
    level = "debug",
    skip(state)
)]
pub(super) async fn start(
    State(state): State<ServiceState>,
    Json(req): Json<PasskeyAuthenticationStartRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // TODO: Check user existence and simulate the response when the user does not
    // exist.
    state
        .provider
        .get_identity_provider()
        .delete_user_webauthn_credential_authentication_state(&state, &req.passkey.user_id)
        .await?;
    let allow_credentials: Vec<Passkey> = state
        .provider
        .get_identity_provider()
        .list_user_webauthn_credentials(&state, &req.passkey.user_id)
        .await?
        .into_iter()
        .collect();
    let res = match state
        .webauthn
        .start_passkey_authentication(allow_credentials.as_ref())
    {
        Ok((rcr, auth_state)) => {
            state
                .provider
                .get_identity_provider()
                .save_user_webauthn_credential_authentication_state(
                    &state,
                    &req.passkey.user_id,
                    auth_state,
                )
                .await?;
            Json(PasskeyAuthenticationStartResponse::from(rcr))
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown)?;
        }
    };

    Ok(res)
}

impl From<webauthn_rs_proto::extensions::HmacGetSecretInput> for HmacGetSecretInput {
    fn from(val: webauthn_rs_proto::extensions::HmacGetSecretInput) -> Self {
        Self {
            output1: URL_SAFE.encode(val.output1),
            output2: val.output2.map(|s2| URL_SAFE.encode(s2)),
        }
    }
}

impl From<webauthn_rs_proto::extensions::RequestAuthenticationExtensions>
    for RequestAuthenticationExtensions
{
    fn from(val: webauthn_rs_proto::extensions::RequestAuthenticationExtensions) -> Self {
        Self {
            appid: val.appid,
            hmac_get_secret: val.hmac_get_secret.map(Into::into),
            uvm: val.uvm,
        }
    }
}

impl From<webauthn_rs_proto::options::AuthenticatorTransport> for AuthenticatorTransport {
    fn from(val: webauthn_rs_proto::options::AuthenticatorTransport) -> Self {
        match val {
            webauthn_rs_proto::options::AuthenticatorTransport::Ble => Self::Ble,
            webauthn_rs_proto::options::AuthenticatorTransport::Hybrid => Self::Hybrid,
            webauthn_rs_proto::options::AuthenticatorTransport::Internal => Self::Internal,
            webauthn_rs_proto::options::AuthenticatorTransport::Nfc => Self::Nfc,
            webauthn_rs_proto::options::AuthenticatorTransport::Test => Self::Test,
            webauthn_rs_proto::options::AuthenticatorTransport::Unknown => Self::Unknown,
            webauthn_rs_proto::options::AuthenticatorTransport::Usb => Self::Usb,
        }
    }
}
impl From<webauthn_rs_proto::options::UserVerificationPolicy> for UserVerificationPolicy {
    fn from(val: webauthn_rs_proto::options::UserVerificationPolicy) -> Self {
        match val {
            webauthn_rs_proto::options::UserVerificationPolicy::Required => Self::Required,
            webauthn_rs_proto::options::UserVerificationPolicy::Preferred => Self::Preferred,
            webauthn_rs_proto::options::UserVerificationPolicy::Discouraged_DO_NOT_USE => {
                Self::DiscouragedDoNotUse
            }
        }
    }
}

impl From<webauthn_rs_proto::options::PublicKeyCredentialHints> for PublicKeyCredentialHint {
    fn from(val: webauthn_rs_proto::options::PublicKeyCredentialHints) -> Self {
        match val {
            webauthn_rs_proto::options::PublicKeyCredentialHints::ClientDevice => {
                Self::ClientDevice
            }
            webauthn_rs_proto::options::PublicKeyCredentialHints::Hybrid => Self::Hybrid,
            webauthn_rs_proto::options::PublicKeyCredentialHints::SecurityKey => Self::SecurityKey,
        }
    }
}

impl From<webauthn_rs_proto::options::AllowCredentials> for AllowCredentials {
    fn from(val: webauthn_rs_proto::options::AllowCredentials) -> Self {
        Self {
            id: URL_SAFE.encode(val.id),
            transports: val
                .transports
                .map(|tr| tr.into_iter().map(Into::into).collect::<Vec<_>>()),
            type_: val.type_,
        }
    }
}

impl From<webauthn_rs_proto::auth::PublicKeyCredentialRequestOptions>
    for PublicKeyCredentialRequestOptions
{
    fn from(val: webauthn_rs_proto::auth::PublicKeyCredentialRequestOptions) -> Self {
        Self {
            allow_credentials: val
                .allow_credentials
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            challenge: URL_SAFE.encode(val.challenge),
            extensions: val.extensions.map(Into::into),
            hints: val
                .hints
                .map(|hints| hints.into_iter().map(Into::into).collect::<Vec<_>>()),
            rp_id: val.rp_id,
            timeout: val.timeout,
            user_verification: val.user_verification.into(),
        }
    }
}

impl From<webauthn_rs::prelude::RequestChallengeResponse> for PasskeyAuthenticationStartResponse {
    fn from(val: webauthn_rs::prelude::RequestChallengeResponse) -> Self {
        Self {
            public_key: val.public_key.into(),
            mediation: val.mediation.map(|med| match med {
                webauthn_rs_proto::auth::Mediation::Conditional => Mediation::Conditional,
            }),
        }
    }
}
