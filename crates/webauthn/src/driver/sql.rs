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
use sea_orm_migration::MigrationTrait;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::SqlDriver as CoreSqlDriver;
use openstack_keystone_core::SqlDriverRegistration;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::db::create_table;
use openstack_keystone_core::error::DatabaseError;

use crate::{
    WebauthnError,
    driver::sql::state::StateType,
    types::{WebauthnApi, WebauthnCredential},
};

pub mod credential;
pub mod migration;
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
    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn cleanup<'a>(&self, exec: &ExecutionContext<'a>) -> Result<(), WebauthnError> {
        state::delete_expired(&exec.state().db).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn create_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        credential::create(&exec.state().db, credential).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, WebauthnError> {
        credential::find(&exec.state().db, user_id, credential_id).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), WebauthnError> {
        credential::delete(&exec.state().db, user_id, credential_id).await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError> {
        state::delete(&exec.state().db, user_id, StateType::Auth).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<(), WebauthnError> {
        state::delete(&exec.state().db, user_id, StateType::Register).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
        state::get_auth(&exec.state().db, user_id).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Option<PasskeyRegistration>, WebauthnError> {
        state::get_register(&exec.state().db, user_id).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Vec<WebauthnCredential>, WebauthnError> {
        credential::list(&exec.state().db, user_id).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn save_user_webauthn_credential_authentication_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        auth_state: &PasskeyAuthentication,
    ) -> Result<(), WebauthnError> {
        state::create_auth(&exec.state().db, user_id, auth_state).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn save_user_webauthn_credential_registration_state<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        reg_state: &PasskeyRegistration,
    ) -> Result<(), WebauthnError> {
        state::create_register(&exec.state().db, user_id, reg_state).await
    }

    #[tracing::instrument(level = "debug", skip(self, exec))]
    async fn update_user_webauthn_credential<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        user_id: &str,
        credential_id: &str,
        credential: &WebauthnCredential,
    ) -> Result<WebauthnCredential, WebauthnError> {
        credential::update(&exec.state().db, user_id, credential_id, credential).await
    }
}

#[async_trait]
impl CoreSqlDriver for SqlDriver {
    /// Setup the database tables for the WebAuthN extension.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` containing `()` on success, or a `DatabaseError`.
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

    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        migration::migrations()
    }
}

#[cfg(test)]
mod tests {}
