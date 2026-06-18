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
//! # OpenStack Keystone SQL driver for the K8s auth provider

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};
use sea_orm_migration::MigrationTrait;

use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::k8s_auth::error::K8sAuthProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::k8s_auth::*;

pub mod entity;
mod instance;
pub mod migration;

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

/// Sql Database K8s auth backend.
#[derive(Default)]
pub struct SqlBackend {}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

#[async_trait]
impl K8sAuthBackend for SqlBackend {
    /// Register new K8s auth.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `config`: The configuration for creating a new K8s auth instance.
    ///
    /// # Returns
    /// A `Result` containing the created `K8sAuthInstance`, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        config: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        Ok(instance::create(&state.db, config).await?)
    }

    /// Delete K8s auth.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the K8s auth instance to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        Ok(instance::delete(&state.db, id).await?)
    }

    /// Get K8s auth instance.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the K8s auth instance to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `K8sAuthInstance` if found,
    /// or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        Ok(instance::get(&state.db, id).await?)
    }

    /// List K8s auth auth_instances.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `params`: The parameters for listing K8s auth instances.
    ///
    /// # Returns
    /// A `Result` containing a vector of `K8sAuthInstance`s, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        Ok(instance::list(&state.db, params).await?)
    }

    /// Update K8s auth instance.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the K8s auth instance to update.
    /// - `data`: The updated data for the K8s auth instance.
    ///
    /// # Returns
    /// A `Result` containing the updated `K8sAuthInstance`, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        Ok(instance::update(&state.db, id, data).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(
            connection,
            schema,
            crate::entity::prelude::KubernetesAuthInstance,
        )
        .await?;
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        crate::migration::migrations()
    }
}

#[cfg(test)]
mod tests {}
