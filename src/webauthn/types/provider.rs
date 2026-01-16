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

//! # WebAuthN provider interface
use async_trait::async_trait;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::keystone::ServiceState;
use crate::webauthn::{WebauthnError, types::WebauthnCredential};

/// WebAuthN extension provider interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WebauthnApi: Send + Sync {
    /// Create passkey.
    async fn create_user_webauthn_credential(
        &self,
        state: &ServiceState,
        passkey: WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError>;

    /// Get webauthn credential of the user by the credential_id.
    async fn get_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError>;

    /// Delete passkey registration state of a user
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError>;

    /// Delete passkey registration state of a user
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError>;

    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError>;

    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError>;

    async fn list_user_webauthn_credentials<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<WebauthnCredential>, WebauthnError>;

    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth: PasskeyAuthentication,
    ) -> Result<(), WebauthnError>;

    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: PasskeyRegistration,
    ) -> Result<(), WebauthnError>;

    /// Update credential data.
    async fn update_user_webauthn_credential(
        &self,
        state: &ServiceState,
        internal_id: i32,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError>;
}
