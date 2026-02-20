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

pub mod auth;
pub mod register;

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

impl From<openstack_keystone_api_types::webauthn::error::WebauthnError> for KeystoneApiError {
    fn from(value: openstack_keystone_api_types::webauthn::error::WebauthnError) -> Self {
        match value {
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<uuid::Error> for KeystoneApiError {
    fn from(value: uuid::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}
