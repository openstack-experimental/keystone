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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use tracing::debug;
use validator::Validate;

use crate::{
    WebauthnError,
    api::types::{CombinedExtensionState, auth::*},
};
use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_api_types::v3::auth::token::TokenResponse;
use openstack_keystone_core::auth::*;

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
    skip(state, req),
    err
)]
pub async fn finish(
    State(state): State<CombinedExtensionState>,
    Json(req): Json<PasskeyAuthenticationFinishRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let user_id = req.user_id.clone();

    let Some(s) = state
        .extension
        .provider
        .get_user_webauthn_credential_authentication_state(&state.core, &user_id)
        .await?
    else {
        return Err(KeystoneApiError::UnauthorizedNoContext);
    };

    // Consume the challenge state unconditionally before verification so that
    // it cannot be replayed regardless of whether the ceremony succeeds or fails
    // (WebAuthn Level 3 §6.3.3 step 21).
    state
        .extension
        .provider
        .delete_user_webauthn_credential_authentication_state(&state.core, &user_id)
        .await?;

    // We explicitly try to deserealize the request data directly into the
    // underlying webauthn_rs type.
    let auth_result = match state
        .extension
        .webauthn
        .finish_passkey_authentication(&req.try_into().map_err(WebauthnError::from)?, &s)
    {
        Ok(r) => r,
        Err(e) => {
            debug!("finish_passkey_authentication -> {:?}", e);
            return Err(KeystoneApiError::unauthorized(e, None::<String>));
        }
    };

    // As per https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion 21:
    //
    // If the Credential Counter is greater than 0 you MUST assert that the counter
    // is greater than the stored counter. If the counter is equal or less than this
    // MAY indicate a cloned credential and you SHOULD invalidate and reject that
    // credential as a result.
    //
    // From this AuthenticationResult you should update the Credential’s Counter
    // value if it is valid per the above check. If you wish you may use the content
    // of the AuthenticationResult for extended validations (such as the presence of
    // the user verification flag).
    let cred_id = URL_SAFE_NO_PAD.encode(auth_result.cred_id());
    let mut credential = state
        .extension
        .provider
        .get_user_webauthn_credential(&state.core, &user_id, &cred_id)
        .await?
        .ok_or(WebauthnError::CredentialNotFound(cred_id))?;

    let now = Utc::now();
    if auth_result.counter() > 0 {
        if auth_result.counter() <= credential.counter {
            return Err(WebauthnError::CounterVerification.into());
        }
        credential.counter = auth_result.counter();
    }

    credential.last_used_at = Some(now);
    credential.updated_at = Some(now);
    // Integrate auth_result into the saved passkey data. Ignore the result since we
    // want to update the last_used_at anyway.
    credential.data.update_credential(&auth_result);

    // Persist updated data.
    state
        .extension
        .provider
        .update_user_webauthn_credential(
            &state.core,
            &user_id,
            &credential.credential_id,
            &credential,
        )
        .await?;

    let user = state
        .core
        .provider
        .get_identity_provider()
        .get_user(&state.core, &user_id)
        .await?
        .ok_or(KeystoneApiError::Conflict("user not found".into()))?;
    let auth = AuthenticationResultBuilder::default()
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .context(AuthenticationContext::WebauthN)
        .build()?;
    let ctx = SecurityContext::try_from(auth)?;

    let vsc = state
        .core
        .provider
        .get_token_provider()
        .issue_token_context(&state.core, &ctx, &ScopeInfo::Unscoped)
        .await?;

    let api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .core
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response())
}
