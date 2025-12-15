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

//! # Finish passkey authentication process
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tracing::debug;
use validator::Validate;

use crate::api::{
    KeystoneApiError,
    v4::auth::token::types::{Token as ApiResponseToken, TokenResponse},
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::identity::IdentityApi;
use crate::token::TokenApi;
use crate::webauthn::{
    WebauthnApi,
    api::types::{CombinedExtensionState, auth::*},
};

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
pub async fn finish(
    State(state): State<CombinedExtensionState>,
    Json(req): Json<PasskeyAuthenticationFinishRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let user_id = req.user_id.clone();
    // TODO: Wrap all errors into the Unauthorized, but log the error
    if let Some(s) = state
        .extension
        .provider
        .get_user_webauthn_credential_authentication_state(&state.core, &user_id)
        .await?
    {
        // We explicitly try to deserealize the request data directly into the
        // underlying webauthn_rs type.
        match state
            .extension
            .webauthn
            .finish_passkey_authentication(&req.try_into()?, &s)
        {
            Ok(_auth_result) => {
                // Here should the DB update happen (last_used, ...)
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
            .delete_user_webauthn_credential_authentication_state(&state.core, &user_id)
            .await?;
    }
    let authed_info = AuthenticatedInfo::builder()
        .user_id(user_id.clone())
        .user(
            state
                .core
                .provider
                .get_identity_provider()
                .get_user(&state.core, &user_id)
                .await
                .map(|x| {
                    x.ok_or_else(|| KeystoneApiError::NotFound {
                        resource: "user".into(),
                        identifier: user_id,
                    })
                })??,
        )
        // Unless Keystone support passkey auth method we use x509 (which it technically is close to).
        .methods(vec!["x509".into()])
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    let token = state.core.provider.get_token_provider().issue_token(
        authed_info,
        AuthzInfo::Unscoped,
        None,
    )?;

    let api_token = TokenResponse {
        token: ApiResponseToken::from_provider_token(&state.core, &token).await?,
    };
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .core
                .provider
                .get_token_provider()
                .encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}
