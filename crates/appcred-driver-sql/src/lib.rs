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
//! # OpenStack Keystone Application Credential SQL driver

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::application_credential::*;

mod application_credential;
pub mod entity;

/// SQL backend provider implementing the ApplicationCredentialBackend
/// interface.
#[derive(Default)]
pub struct SqlBackend {}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl ApplicationCredentialBackend for SqlBackend {
    /// Create a standalone access rule owned by a user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `rule`: The access rule to create (its `user_id` identifies the
    ///   owner).
    ///
    /// # Returns
    /// A `Result` containing the created `AccessRule` or an `Error`.
    async fn create_access_rule(
        &self,
        state: &ServiceState,
        rule: AccessRuleCreate,
    ) -> Result<AccessRule, ApplicationCredentialProviderError> {
        application_credential::access_rule::create(&state.db, rule).await
    }

    /// Create a new application credential.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `rec`: The application credential to create.
    ///
    /// # Returns
    /// A `Result` containing the `ApplicationCredentialCreateResponse` or an
    /// `Error`.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(application_credential::create(&config, &state.db, rec).await?)
    }

    /// Delete a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// A `Result` containing `()` or an `Error`.
    async fn delete_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<(), ApplicationCredentialProviderError> {
        application_credential::access_rule::delete(&state.db, user_id, id).await
    }

    /// Delete an application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the application credential to delete.
    ///
    /// # Returns
    /// - `Result<(), ApplicationCredentialProviderError>` - Unit on success, or
    ///   an error.
    async fn delete_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ApplicationCredentialProviderError> {
        application_credential::delete(&state.db, id).await
    }
    /// Get a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `AccessRule` if found, or an
    /// `Error`.
    async fn get_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError> {
        application_credential::access_rule::get(&state.db, user_id, id).await
    }

    /// Get a single application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the application credential.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `ApplicationCredential` if
    /// found, or an `Error`.
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::get(&state.db, id).await?)
    }

    /// List all access rules owned by a user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user owning the access rules.
    ///
    /// # Returns
    /// A `Result` containing a `Vec` of `AccessRule` or an `Error`.
    async fn list_access_rules<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError> {
        application_credential::access_rule::list(&state.db, user_id).await
    }

    /// List application credentials.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing application credentials.
    ///
    /// # Returns
    /// A `Result` containing a `Vec` of `ApplicationCredential` or an `Error`.
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::list(&state.db, params).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Setup the database tables.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` containing `()` or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::AccessRule).await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::ApplicationCredential,
        )
        .await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::ApplicationCredentialRole,
        )
        .await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::ApplicationCredentialAccessRule,
        )
        .await?;
        Ok(())
    }
}
