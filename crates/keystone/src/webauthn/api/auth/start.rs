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

//! # Start passkey authentication process
use axum::{Json, extract::State, response::IntoResponse};
use tracing::debug;
use validator::Validate;

use crate::api::KeystoneApiError;
use crate::webauthn::{
    WebauthnApi,
    api::types::{CombinedExtensionState, auth::*},
};

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
pub async fn start(
    State(state): State<CombinedExtensionState>,
    Json(req): Json<PasskeyAuthenticationStartRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    // TODO: Check user existence and simulate the response when the user does not
    // exist.
    state
        .extension
        .provider
        .delete_user_webauthn_credential_authentication_state(&state.core, &req.passkey.user_id)
        .await?;
    let allow_credentials: Vec<webauthn_rs::prelude::Passkey> = state
        .extension
        .provider
        .list_user_webauthn_credentials(&state.core, &req.passkey.user_id)
        .await?
        .into_iter()
        .map(|x| x.data)
        .collect();
    let res = match state
        .extension
        .webauthn
        .start_passkey_authentication(allow_credentials.as_ref())
    {
        Ok((rcr, auth_state)) => {
            state
                .extension
                .provider
                .save_user_webauthn_credential_authentication_state(
                    &state.core,
                    &req.passkey.user_id,
                    auth_state,
                )
                .await?;
            Json(PasskeyAuthenticationStartResponse::from(rcr))
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(KeystoneApiError::InternalError(
                "unexpected error in the webauthn extension".into(),
            ));
        }
    };

    Ok(res)
}
