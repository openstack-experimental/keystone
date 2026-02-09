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
//! # Start passkey registration process
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;
use tracing::debug;
use uuid::Uuid;
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
    tags = ["passkey"]
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
    State(state): State<CombinedExtensionState>,
    Json(req): Json<UserPasskeyRegistrationStartRequest>,
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
            "identity/user/passkey/register/start",
            &user_auth,
            serde_json::to_value(&user)?,
            None,
        )
        .await?;

    state
        .extension
        .provider
        .delete_user_webauthn_credential_registration_state(&state.core, &user_id)
        .await?;
    let res = match state.extension.webauthn.start_passkey_registration(
        Uuid::parse_str(&user_id)?,
        // user_name
        &user.name,
        // TODO: user display name
        &user.name,
        None,
    ) {
        Ok((ccr, reg_state)) => {
            state
                .extension
                .provider
                .save_user_webauthn_credential_registration_state(&state.core, &user_id, reg_state)
                .await?;
            Json(UserPasskeyRegistrationStartResponse::try_from(ccr)?)
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
