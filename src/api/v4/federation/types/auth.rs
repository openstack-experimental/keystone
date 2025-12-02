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
//! Federated auth OIDC auth types.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Request for initializing the federated authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct IdentityProviderAuthRequest {
    /// Redirect URI to include in the auth request.
    #[validate(url)]
    pub redirect_uri: String,
    /// IDP mapping id.
    #[validate(length(max = 64))]
    pub mapping_id: Option<String>,
    /// IDP mapping name.
    #[validate(length(max = 64))]
    pub mapping_name: Option<String>,
    /// Authentication scope.
    #[validate(nested)]
    pub scope: Option<crate::api::types::Scope>,
}

/// Authentication initialization response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct IdentityProviderAuthResponse {
    /// Url the client must open in the browser to continue the authentication.
    #[validate(url)]
    pub auth_url: String,
}

/// Authentication callback request the user is sending to complete the
/// authentication request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AuthCallbackParameters {
    /// Authentication state.
    pub state: String,
    /// Authorization code.
    pub code: String,
}

impl IntoResponse for IdentityProviderAuthResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
