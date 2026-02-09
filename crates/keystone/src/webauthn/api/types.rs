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
//! # Webauthn API types
use axum::{extract::FromRequestParts, http::request::Parts};
use mockall_double::double;
use std::sync::Arc;
use webauthn_rs::Webauthn;

use crate::api::KeystoneApiError;
use crate::api::auth::Auth;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

use crate::webauthn::{WebauthnError, driver::SqlDriver};

mod allow_credentials;
mod attestation_conveyance_preference;
mod attestation_format;
pub mod auth;
mod authentication_extensions_client_outputs;
mod authenticator_assertion_response_raw;
mod authenticator_attachment;
mod authenticator_selection_criteria;
mod authenticator_transport;
mod cred_protect;
mod credential_protection_policy;
mod hmac_get_secret_input;
mod hmac_get_secret_output;
mod pub_key_cred_params;
mod public_key_credential_creation_options;
mod public_key_credential_descriptor;
mod public_key_credential_hints;
mod public_key_credential_request_options;
pub mod register;
mod relying_party;
mod request_authentication_extensions;
mod request_registration_extension;
mod resident_key_requirement;
mod user;
mod user_verification_policy;

/// WebAuthN extension state.
#[derive()]
pub struct ExtensionState {
    /// Provider.
    pub provider: SqlDriver,
    /// WebAuthN provider.
    pub webauthn: Webauthn,
}

/// Combined state of core Keystone and WebAuthN extension.
#[derive(Clone)]
pub struct CombinedExtensionState {
    /// Core Keystone state.
    pub core: ServiceState,
    /// Extension state.
    pub extension: Arc<ExtensionState>,
}

impl FromRequestParts<CombinedExtensionState> for Policy {
    type Rejection = KeystoneApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &CombinedExtensionState,
    ) -> Result<Self, Self::Rejection> {
        Policy::from_request_parts(parts, &state.core).await
    }
}

impl FromRequestParts<CombinedExtensionState> for Auth {
    type Rejection = KeystoneApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &CombinedExtensionState,
    ) -> Result<Self, Self::Rejection> {
        Auth::from_request_parts(parts, &state.core).await
    }
}

impl From<WebauthnError> for KeystoneApiError {
    fn from(value: WebauthnError) -> Self {
        match value {
            WebauthnError::AuthenticationInfo { source } => source.into(),
            ref err @ WebauthnError::Conflict { .. } => Self::Conflict(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<uuid::Error> for KeystoneApiError {
    fn from(value: uuid::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}
