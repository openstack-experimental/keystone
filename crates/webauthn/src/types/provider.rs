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

use openstack_keystone_core::auth::ExecutionContext;

use crate::{WebauthnError, types::WebauthnCredential};

/// WebAuthN extension provider interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WebauthnApi: Send + Sync {
    /// Cleanup expired Webauthn states.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn cleanup<'a>(&self, exec: &ExecutionContext<'a>) -> Result<(), WebauthnError>;

    /// Create passkey.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `passkey`: The credential to create.
    ///
    /// # Returns
    /// A `Result` containing the created `WebauthnCredential`, or a
    /// `WebauthnError`.
    async fn create_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        passkey: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError>;

    /// Get webauthn credential of the user by the credential_id.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `WebauthnCredential` if
    /// found, or an `Error`.
    async fn get_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError>;

    /// Delete credential for the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn delete_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), WebauthnError>;

    /// Delete credential authentication state for the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError>;

    /// Delete credential registration state for the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError>;

    /// Get authentication state for the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `PasskeyAuthentication` if
    /// found, or an `Error`.
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError>;

    /// Get credential registration state for the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `PasskeyRegistration` if
    /// found, or an `Error`.
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError>;

    /// List credentials of the user.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    ///
    /// # Returns
    /// A `Result` containing a `Vec` of `WebauthnCredential`, or a
    /// `WebauthnError`.
    async fn list_user_webauthn_credentials<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Vec<WebauthnCredential>, WebauthnError>;

    /// Save the authentication state.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    /// - `auth`: The authentication state to save.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        auth: &PasskeyAuthentication,
    ) -> Result<(), WebauthnError>;

    /// Save credential registration state.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    /// - `reg_state`: The registration state to save.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `WebauthnError`.
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), WebauthnError>;

    /// Update credential data.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `user_id`: The user ID.
    /// - `credential_id`: The credential ID.
    /// - `credential`: The updated credential data.
    ///
    /// # Returns
    /// A `Result` containing the updated `WebauthnCredential`, or a
    /// `WebauthnError`.
    async fn update_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError>;
}
