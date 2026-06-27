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
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::application_credential::{ApplicationCredential, ApplicationCredentialResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Show application credential details.
#[utoipa::path(
    get,
    path = "/{application_credential_id}",
    params(),
    responses(
        (status = OK, description = "Single application credential", body = ApplicationCredentialResponse),
        (status = 404, description = "Application credential not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1")))),
        (status = 403, description = "Forbidden", example = json!(KeystoneApiError::Forbidden)),
        (status = 401, description = "Unauthorized", example = json!(KeystoneApiError::Unauthorized))
    ),
    tag="application_credentials"
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(application_credential_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_application_credential_provider()
        .get_application_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            &application_credential_id,
        )
        .await?
        .ok_or(KeystoneApiError::NotFound)?;

    state
        .policy_enforcer
        .enforce(
            "identity/application_credential/show",
            &user_auth,
            json!({"user_id": current.user_id}),
            None,
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(ApplicationCredentialResponse {
            application_credential: current.into(),
        }),
    ))
}
