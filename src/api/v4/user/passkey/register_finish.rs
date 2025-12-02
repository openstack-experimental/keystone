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

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use mockall_double::double;
use tracing::debug;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::{KeystoneApiError, WebauthnError};
use crate::api::v4::user::types::passkey::{
    AuthenticatorTransport, CredentialProtectionPolicy, PasskeyResponse,
    UserPasskeyRegistrationFinishRequest,
};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Finish passkey registration for the user.
#[utoipa::path(
    post,
    path = "/register_finish",
    operation_id = "/user/passkey/register:finish",
    request_body = UserPasskeyRegistrationFinishRequest,
    params(
      ("user_id" = String, Path, description = "The ID of the user.")
    ),
    responses(
        (status = CREATED, description = "Passkey successfully registered", body = PasskeyResponse),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tags = ["users", "passkey"]
)]
#[tracing::instrument(
    name = "api::user_webauthn_credential_register_finish",
    level = "debug",
    skip(state, policy, req),
    err(Debug)
)]
pub(super) async fn finish(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    mut policy: Policy,
    Json(req): Json<UserPasskeyRegistrationFinishRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&state, &user_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: user_id.clone(),
            })
        })??;

    policy
        .enforce(
            "identity/user/passkey/register/finish",
            &user_auth,
            serde_json::to_value(&user)?,
            None,
        )
        .await?;

    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_webauthn_credential_registration_state(&state, &user_id)
        .await?
    {
        let credential_description = req.description.clone();
        let passkey = match state
            .webauthn
            .finish_passkey_registration(&req.try_into()?, &s)
        {
            Ok(sk) => {
                state
                    .provider
                    .get_identity_provider()
                    .create_user_webauthn_credential(
                        &state,
                        &user_id,
                        &sk,
                        credential_description.as_deref(),
                    )
                    .await?
            }
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                return Err(WebauthnError::Unknown)?;
            }
        };
        state
            .provider
            .get_identity_provider()
            .delete_user_webauthn_credential_registration_state(&state, &user_id)
            .await?;
        Ok((StatusCode::CREATED, Json(PasskeyResponse::from(passkey))).into_response())
    } else {
        return Err(WebauthnError::Unknown)?;
    }
}

impl TryFrom<UserPasskeyRegistrationFinishRequest>
    for webauthn_rs::prelude::RegisterPublicKeyCredential
{
    type Error = KeystoneApiError;
    fn try_from(val: UserPasskeyRegistrationFinishRequest) -> Result<Self, Self::Error> {
        Ok(webauthn_rs::prelude::RegisterPublicKeyCredential {
            id: val.id,
            raw_id: URL_SAFE.decode(val.raw_id)?.into(),
            type_: val.type_,
            response: webauthn_rs_proto::attest::AuthenticatorAttestationResponseRaw {
                attestation_object: URL_SAFE.decode(val.response.attestation_object)?.into(),
                client_data_json: URL_SAFE.decode(val.response.client_data_json)?.into(),
                transports: val.response.transports.map(|i| {
                    i.into_iter()
                        .map(|t| match t {
                            AuthenticatorTransport::Ble => webauthn_rs_proto::options::AuthenticatorTransport::Ble,
                            AuthenticatorTransport::Hybrid => webauthn_rs_proto::options::AuthenticatorTransport::Hybrid,
                            AuthenticatorTransport::Internal => webauthn_rs_proto::options::AuthenticatorTransport::Internal,
                            AuthenticatorTransport::Nfc => webauthn_rs_proto::options::AuthenticatorTransport::Nfc,
                            AuthenticatorTransport::Test => webauthn_rs_proto::options::AuthenticatorTransport::Test,
                            AuthenticatorTransport::Unknown => webauthn_rs_proto::options::AuthenticatorTransport::Unknown,
                            AuthenticatorTransport::Usb => webauthn_rs_proto::options::AuthenticatorTransport::Usb,

                        })
                        .collect::<Vec<_>>()
                }),
            },
            extensions: webauthn_rs_proto::extensions::RegistrationExtensionsClientOutputs {
                appid: val.extensions.appid,
                cred_props: val
                    .extensions
                    .cred_props
                    .map(|x| webauthn_rs_proto::extensions::CredProps { rk: x.rk }),
                hmac_secret: val.extensions.hmac_secret,
                cred_protect: val.extensions.cred_protect.map(|x| {
                    match x {
                        CredentialProtectionPolicy::UserVerificationOptional => webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptional,
                        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
                        CredentialProtectionPolicy::UserVerificationRequired => webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationRequired
                    }
                }),
                min_pin_length: val.extensions.min_pin_length,
            },
        })
    }
}
