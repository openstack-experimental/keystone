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

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::SqlDriverRegistration;
use openstack_keystone_core::db::create_table;
use openstack_keystone_core::error::DatabaseError;
use openstack_keystone_core::keystone::ServiceState;

use crate::{
    WebauthnError,
    types::{WebauthnApi, WebauthnCredential},
};

pub mod credential;
mod model;
pub mod state;

/// Sql driver for the WebAuthN extension.
#[derive(Default)]
pub struct SqlDriver {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlDriver = SqlDriver {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl WebauthnApi for SqlDriver {
    /// Cleanup expired Webauthn states.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn cleanup(&self, state: &ServiceState) -> Result<(), WebauthnError> {
        state::delete_expired(&state.db).await
    }

    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential(
        &self,
        state: &ServiceState,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        credential::create(&state.db, credential).await
    }

    /// Get webauthn credential of the user by the credential_id.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError> {
        credential::find(&state.db, user_id, credential_id).await
    }

    /// Delete credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        _user_id: &'a str,
        credential_id: &'a str,
    ) -> Result<(), WebauthnError> {
        credential::delete(&state.db, credential_id).await?;
        Ok(())
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
    ) -> Result<Vec<WebauthnCredential>, WebauthnError> {
        credential::list(&state.db, user_id).await
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth_state: &PasskeyAuthentication,
    ) -> Result<(), WebauthnError> {
        state::create_auth(&state.db, user_id, auth_state).await
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), WebauthnError> {
        state::create_register(&state.db, user_id, reg_state).await
    }

    /// Update credential data.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential_id: &'a str,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        credential::update(&state.db, credential_id, credential).await
    }
}

#[async_trait]
impl openstack_keystone_core::SqlDriver for SqlDriver {
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(
            connection,
            schema,
            crate::driver::sql::model::prelude::WebauthnCredential,
        )
        .await?;
        create_table(
            connection,
            schema,
            crate::driver::sql::model::prelude::WebauthnState,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
