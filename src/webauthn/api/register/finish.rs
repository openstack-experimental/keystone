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
//! # Finish passkey registration process
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use tracing::debug;
use validator::Validate;

use crate::api::KeystoneApiError;
use crate::api::auth::Auth;
use crate::identity::IdentityApi;
#[double]
use crate::policy::Policy;
use crate::webauthn::{
    WebauthnApi,
    api::types::{CombinedExtensionState, register::*},
};

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
    tags = ["passkey"]
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
    State(state): State<CombinedExtensionState>,
    mut policy: Policy,
    Json(req): Json<UserPasskeyRegistrationFinishRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let user = state
        .core
        .provider
        .get_identity_provider()
        .get_user(&state.core, &user_id)
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
        .extension
        .provider
        .get_user_webauthn_credential_registration_state(&state.core, &user_id)
        .await?
    {
        let credential_description = req.description.clone();
        let passkey = match state
            .extension
            .webauthn
            .finish_passkey_registration(&req.try_into()?, &s)
        {
            Ok(sk) => {
                state
                    .extension
                    .provider
                    .create_user_webauthn_credential(
                        &state.core,
                        &user_id,
                        &sk,
                        credential_description.as_deref(),
                    )
                    .await?
            }
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                return Err(KeystoneApiError::InternalError(
                    "unexpected error in the webauthn extension".into(),
                ));
            }
        };
        state
            .extension
            .provider
            .delete_user_webauthn_credential_registration_state(&state.core, &user_id)
            .await?;
        Ok((StatusCode::CREATED, Json(PasskeyResponse::from(passkey))).into_response())
    } else {
        return Err(KeystoneApiError::InternalError(
            "unexpected error in the webauthn extension".into(),
        ));
    }
}
