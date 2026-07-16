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
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_core::auth::ExecutionContext;

use crate::WebauthnError;
use crate::api::types::{CombinedExtensionState, auth::*};

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
        (status = CREATED, description = "Challenge that must be signed with any of the user passkeys", body = PasskeyAuthenticationStartResponse),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tags = ["passkey", "auth"]
)]
#[tracing::instrument(
    name = "api::user_webauthn_credential_authentication_start",
    level = "debug",
    skip(state),
    err
)]
pub async fn start(
    State(state): State<CombinedExtensionState>,
    Json(req): Json<PasskeyAuthenticationStartRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let allow_credentials: Vec<webauthn_rs::prelude::Passkey> = state
        .extension
        .provider
        .list_user_webauthn_credentials(
            &ExecutionContext::internal(&state.core),
            &req.passkey.user_id,
        )
        .await?
        .into_iter()
        .map(|x| x.data)
        .collect();
    let res = match state
        .extension
        .webauthn
        .start_passkey_authentication(allow_credentials.as_ref())
    {
        Ok((mut rcr, auth_state)) => {
            if allow_credentials.is_empty() {
                // The user does not exist or has no registered passkeys. To
                // prevent user enumeration respond with deterministic decoy
                // credential IDs (stable per user_id) instead of an empty
                // `allow_credentials` list. The ceremony state is stored as
                // usual; completing it fails exactly like an attempt against
                // a real user with a credential that is not in the allow
                // list.
                rcr.public_key.allow_credentials = state
                    .extension
                    .fake_credential_generator
                    .generate(req.passkey.user_id.as_bytes())
                    .map_err(WebauthnError::from)?
                    .iter()
                    .map(|id| webauthn_rs_proto::options::AllowCredentials {
                        type_: "public-key".to_string(),
                        id: id.as_ref().into(),
                        transports: None,
                    })
                    .collect();
            }
            state
                .extension
                .provider
                .save_user_webauthn_credential_authentication_state(
                    &ExecutionContext::internal(&state.core),
                    &req.passkey.user_id,
                    &auth_state,
                )
                .await?;
            Json(PasskeyAuthenticationStartResponse::from(rcr))
        }
        Err(err) => {
            return Err(KeystoneApiError::InternalError(format!(
                "unexpected error in the webauthn extension: {:?}",
                err
            )));
        }
    };

    Ok((StatusCode::CREATED, res))
}
