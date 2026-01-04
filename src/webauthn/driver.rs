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

pub mod credential;
pub mod state;

use async_trait::async_trait;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::keystone::ServiceState;
use crate::webauthn::{
    WebauthnError,
    types::{WebauthnApi, WebauthnCredential},
};

/// Sql driver for the WebAuthN extension.
#[derive(Default)]
pub struct SqlDriver {}

#[async_trait]
impl WebauthnApi for SqlDriver {
    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential: &Passkey,
        description: Option<&'a str>,
    ) -> Result<WebauthnCredential, WebauthnError> {
        credential::create(&state.db, user_id, credential, description, None).await
    }

    /// Delete webauthn credential auth state for a user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError> {
        state::delete(&state.db, user_id).await
    }

    /// Delete webauthn credential registration state for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), WebauthnError> {
        state::delete(&state.db, user_id).await
    }

    /// Get webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
        state::get_auth(&state.db, user_id).await
    }

    /// Get webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError> {
        state::get_register(&state.db, user_id).await
    }

    /// List user webauthn credentials.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Passkey>, WebauthnError> {
        credential::list(&state.db, user_id).await
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth_state: PasskeyAuthentication,
    ) -> Result<(), WebauthnError> {
        state::create_auth(&state.db, user_id, auth_state).await
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: PasskeyRegistration,
    ) -> Result<(), WebauthnError> {
        state::create_register(&state.db, user_id, reg_state).await
    }
}

#[cfg(test)]
mod tests {}
