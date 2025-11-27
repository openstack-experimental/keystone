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
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use mockall_double::double;
use tracing::debug;
use webauthn_rs::prelude::*;

use crate::api::auth::Auth;
use crate::api::error::{KeystoneApiError, WebauthnError};
use crate::api::v4::user::types::passkey::{
    AttestationConveyancePreference, AttestationFormat, AuthenticatorAttachment,
    AuthenticatorSelectionCriteria, AuthenticatorTransport, CredProtect,
    CredentialProtectionPolicy, PubKeyCredParams, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialHints, RelyingParty,
    RequestRegistrationExtensions, ResidentKeyRequirement, User,
    UserPasskeyRegistrationStartRequest, UserPasskeyRegistrationStartResponse,
    UserVerificationPolicy,
};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Start passkey registration for the user.
///
/// Generate a challenge that the user must sign with the passkey or security
/// device. Signed challenge must be sent to the
/// `/v4/users/{user_id}/passkey/register_finish` endpoint.
#[utoipa::path(
    post,
    path = "/register_start",
    operation_id = "/user/passkey/register:start",
    request_body = UserPasskeyRegistrationStartRequest,
    params(
      ("user_id" = String, Path, description = "The ID of the user.")
    ),
    responses(
        (status = CREATED, description = "Passkey successfully registered", body = UserPasskeyRegistrationStartResponse ),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tags = ["users", "passkey"]
)]
#[tracing::instrument(
    name = "api::user_webauthn_credential_register_start",
    level = "debug",
    skip(state, policy),
    err(Debug)
)]
pub(super) async fn start(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<UserPasskeyRegistrationStartRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
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
            "identity/user/passkey/register/start",
            &user_auth,
            serde_json::to_value(&user)?,
            None,
        )
        .await?;

    state
        .provider
        .get_identity_provider()
        .delete_user_webauthn_credential_registration_state(&state, &user_id)
        .await?;
    let res = match state.webauthn.start_passkey_registration(
        Uuid::parse_str(&user_id)?,
        // user_name
        &user.name,
        // TODO: user display name
        &user.name,
        None,
    ) {
        Ok((ccr, reg_state)) => {
            state
                .provider
                .get_identity_provider()
                .save_user_webauthn_credential_registration_state(&state, &user_id, reg_state)
                .await?;
            Json(UserPasskeyRegistrationStartResponse::try_from(ccr)?)
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown)?;
        }
    };

    Ok(res)
}

impl TryFrom<webauthn_rs::prelude::CreationChallengeResponse>
    for UserPasskeyRegistrationStartResponse
{
    type Error = KeystoneApiError;
    fn try_from(val: webauthn_rs::prelude::CreationChallengeResponse) -> Result<Self, Self::Error> {
        Ok(UserPasskeyRegistrationStartResponse {
            public_key: PublicKeyCredentialCreationOptions {
                attestation: val.public_key.attestation.map(|att| match att {
                    webauthn_rs_proto::options::AttestationConveyancePreference::Direct => {
                        AttestationConveyancePreference::Direct
                    }
                    webauthn_rs_proto::options::AttestationConveyancePreference::Indirect => {
                        AttestationConveyancePreference::Indirect
                    }
                    webauthn_rs_proto::options::AttestationConveyancePreference::None => {
                        AttestationConveyancePreference::None
                    }
                }),
                attestation_formats: val
                    .public_key
                    .attestation_formats
                    .map(|afs| {
                        afs.into_iter().map(|fmt| match fmt {
                            webauthn_rs_proto::options::AttestationFormat::AndroidKey => {
                                AttestationFormat::AndroidKey
                            }
                            webauthn_rs_proto::options::AttestationFormat::AndroidSafetyNet => {
                                AttestationFormat::AndroidSafetyNet
                            }
                            webauthn_rs_proto::options::AttestationFormat::AppleAnonymous => {
                                AttestationFormat::AppleAnonymous
                            }
                            webauthn_rs_proto::options::AttestationFormat::FIDOU2F => {
                                AttestationFormat::FIDOU2F
                            }
                            webauthn_rs_proto::options::AttestationFormat::None => {
                                AttestationFormat::None
                            }
                            webauthn_rs_proto::options::AttestationFormat::Packed => {
                                AttestationFormat::Packed
                            }
                            webauthn_rs_proto::options::AttestationFormat::Tpm => {
                                AttestationFormat::Tpm
                            }
                        })
                            .collect::<Vec<_>>()
                    }),
                authenticator_selection: val.public_key.authenticator_selection.map(|authn| {
                    AuthenticatorSelectionCriteria {
                        authenticator_attachment: authn.authenticator_attachment.map(|attach| {
                            match attach {
                                webauthn_rs_proto::options::AuthenticatorAttachment::CrossPlatform => AuthenticatorAttachment::CrossPlatform,
                                webauthn_rs_proto::options::AuthenticatorAttachment::Platform => AuthenticatorAttachment::Platform,
                            }
                        }),
                        require_resident_key: authn.require_resident_key,
                        resident_key: authn.resident_key.map(|rk|
                            match rk {
                                webauthn_rs_proto::options::ResidentKeyRequirement::Discouraged => ResidentKeyRequirement::Discouraged,
                                webauthn_rs_proto::options::ResidentKeyRequirement::Preferred => ResidentKeyRequirement::Preferred,
                                webauthn_rs_proto::options::ResidentKeyRequirement::Required => ResidentKeyRequirement::Required,
                            }
                        ),
                        user_verification: match authn.user_verification {
                            webauthn_rs_proto::options::UserVerificationPolicy::Preferred => UserVerificationPolicy::Preferred,
                            webauthn_rs_proto::options::UserVerificationPolicy::Required => UserVerificationPolicy::Required,
                            webauthn_rs_proto::options::UserVerificationPolicy::Discouraged_DO_NOT_USE => UserVerificationPolicy::DiscouragedDoNotUse,
                        }
                    }
                }),
                challenge: URL_SAFE.encode(&val.public_key.challenge),
                exclude_credentials: val.public_key.exclude_credentials.map(|ecs| ecs.into_iter().map(|descr| {
                    PublicKeyCredentialDescriptor{
                        type_: descr.type_,
                        id: URL_SAFE.encode(&descr.id),
                        transports: descr.transports.map(|transports| transports.into_iter().map(|tr|{
                            match tr {
                                webauthn_rs_proto::options::AuthenticatorTransport::Ble => AuthenticatorTransport::Ble,
                                webauthn_rs_proto::options::AuthenticatorTransport::Hybrid => AuthenticatorTransport::Hybrid,
                                webauthn_rs_proto::options::AuthenticatorTransport::Internal => AuthenticatorTransport::Internal,
                                webauthn_rs_proto::options::AuthenticatorTransport::Nfc => AuthenticatorTransport::Nfc,
                                webauthn_rs_proto::options::AuthenticatorTransport::Usb => AuthenticatorTransport::Usb,
                                webauthn_rs_proto::options::AuthenticatorTransport::Test => AuthenticatorTransport::Test,
                                webauthn_rs_proto::options::AuthenticatorTransport::Unknown => AuthenticatorTransport::Unknown,
                            }
                        }).collect::<Vec<_>>())
                    }
                }).collect::<Vec<_>>()),
                extensions: val.public_key.extensions.map(|ext| RequestRegistrationExtensions{
                    cred_props: ext.cred_props,
                    cred_protect: ext.cred_protect.map(|cp|
                        {
                            CredProtect {
                                credential_protection_policy: match cp.credential_protection_policy {
                                    webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptional => CredentialProtectionPolicy::UserVerificationOptional,
                                    webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
                                    webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationRequired => CredentialProtectionPolicy::UserVerificationRequired,

                                },
                                enforce_credential_protection_policy: cp.enforce_credential_protection_policy,
                            }
                        }),
                    hmac_create_secret: ext.hmac_create_secret,
                    min_pin_length: ext.min_pin_length,
                    uvm: ext.uvm,
                }),
                hints: val.public_key.hints.map(|hints| hints.into_iter().map(|hint|{
                    match hint {
                        webauthn_rs_proto::options::PublicKeyCredentialHints::ClientDevice => PublicKeyCredentialHints::ClientDevice,
                        webauthn_rs_proto::options::PublicKeyCredentialHints::Hybrid => PublicKeyCredentialHints::Hybrid,
                        webauthn_rs_proto::options::PublicKeyCredentialHints::SecurityKey => PublicKeyCredentialHints::SecurityKey,
                    } }).collect::<Vec<_>>()),
                pub_key_cred_params: val.public_key.pub_key_cred_params.into_iter().map(|pkcp| {
                    PubKeyCredParams{
                        alg: pkcp.alg,
                        type_: pkcp.type_
                    }
                }).collect::<Vec<_>>(),
                rp: RelyingParty{
                    id: val.public_key.rp.id,
                    name: val.public_key.rp.name,
                },
                timeout: val.public_key.timeout,
                user: User {
                    id: URL_SAFE.encode(&val.public_key.user.id),
                    name: val.public_key.user.name,
                    display_name: val.public_key.user.display_name,
                }
            },
        })
    }
}
