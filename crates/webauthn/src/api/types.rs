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
use std::sync::Arc;
use webauthn_rs::Webauthn;
use webauthn_rs::fake::{FakePasskeyDistribution, WebauthnFakeCredentialGenerator};

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::auth::Auth;
use openstack_keystone_core::keystone::ServiceState;

use crate::{WebauthnApi, WebauthnError};

pub mod auth;
pub mod register;

/// WebAuthN extension state.
#[derive()]
pub struct ExtensionState {
    /// Provider.
    pub provider: Box<dyn WebauthnApi>,
    /// WebAuthN provider.
    pub webauthn: Webauthn,
    /// Generator of deterministic decoy credential IDs, used to answer
    /// authentication start requests for unknown users (or users without
    /// passkeys) indistinguishably from real ones (user enumeration
    /// prevention).
    pub fake_credential_generator: WebauthnFakeCredentialGenerator<FakePasskeyDistribution>,
}

/// Combined state of core Keystone and WebAuthN extension.
#[derive(Clone)]
pub struct CombinedExtensionState {
    /// Core Keystone state.
    pub core: ServiceState,
    /// Extension state.
    pub extension: Arc<ExtensionState>,
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
            WebauthnError::Conflict(ref msg) => Self::Conflict(msg.clone()),
            WebauthnError::CounterVerification => {
                Self::unauthorized(WebauthnError::CounterVerification, None::<String>)
            }
            WebauthnError::CredentialNotFound(id) => Self::NotFound {
                resource: "passkey".into(),
                identifier: id,
            },
            WebauthnError::StateNotFound => Self::UnauthorizedNoContext,
            other => Self::InternalError(other.to_string()),
        }
    }
}
