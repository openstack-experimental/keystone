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
//! # OpenStack Keystone SQL driver for the policy store provider
//!
//! Persists the legacy `/v3/policies` documents in the `policy` table, whose
//! schema matches python keystone's so an existing database works unchanged.
//! This has nothing to do with OPA authorization — see
//! `openstack_keystone_core::policy_store` for the distinction.

use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::error::DatabaseError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core::policy_store::backend::PolicyStoreBackend;
use openstack_keystone_core::{SqlDriver, SqlDriverRegistration, db::create_table};
use openstack_keystone_core_types::policy_store::*;

pub mod entity;
mod policy;

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
inventory::submit! {
    BackendRegistration::<dyn PolicyStoreBackend> {
        name: "sql",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(SqlBackend::default()) as Arc<dyn PolicyStoreBackend>)
        }),
    }
}

#[async_trait]
impl PolicyStoreBackend for SqlBackend {
    /// Create a new policy.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `policy`: The policy creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Policy`, or a
    /// `PolicyStoreProviderError`.
    // `skip_all`: `policy` carries the document (`blob`) and arbitrary
    // caller-supplied `extra` properties, which `Debug` would otherwise render
    // into the span.
    #[tracing::instrument(level = "debug", skip_all, fields(policy_type = %policy.r#type))]
    async fn create_policy(
        &self,
        state: &ServiceState,
        policy: PolicyCreate,
    ) -> Result<Policy, PolicyStoreProviderError> {
        policy::create(&state.db.connection(), policy).await
    }

    /// Delete a policy by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PolicyStoreProviderError`.
    #[tracing::instrument(level = "debug", skip_all, fields(policy_id = %id))]
    async fn delete_policy(
        &self,
        state: &ServiceState,
        id: &str,
    ) -> Result<(), PolicyStoreProviderError> {
        policy::delete(&state.db.connection(), id).await
    }

    /// Get a single policy by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Policy` if found, or a
    /// `PolicyStoreProviderError`.
    #[tracing::instrument(level = "debug", skip_all, fields(policy_id = %id))]
    async fn get_policy(
        &self,
        state: &ServiceState,
        id: &str,
    ) -> Result<Option<Policy>, PolicyStoreProviderError> {
        policy::get(&state.db.connection(), id).await
    }

    /// List policies.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `params`: Parameters for filtering the policy list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Policy` objects or a
    /// `PolicyStoreProviderError`.
    #[tracing::instrument(level = "debug", skip_all)]
    async fn list_policies(
        &self,
        state: &ServiceState,
        params: &PolicyListParameters,
    ) -> Result<Vec<Policy>, PolicyStoreProviderError> {
        policy::list(&state.db.connection(), params).await
    }

    /// Update an existing policy.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The unique identifier of the policy.
    /// - `policy`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Policy`, or a
    /// `PolicyStoreProviderError`.
    // `skip_all` for the same reason as `create_policy`.
    #[tracing::instrument(level = "debug", skip_all, fields(policy_id = %id))]
    async fn update_policy(
        &self,
        state: &ServiceState,
        id: &str,
        policy: PolicyUpdate,
    ) -> Result<Policy, PolicyStoreProviderError> {
        policy::update(&state.db.connection(), id, policy).await
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Sets up the database tables for the policy store.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Policy).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::sea_query::PostgresQueryBuilder;
    use sea_orm::{DatabaseBackend, Schema};

    /// The generated schema must match python keystone's `policy` table:
    /// `id VARCHAR(64)` primary key and `type VARCHAR(255)`, not sea-orm's
    /// unconstrained default. A wider column silently diverges from an
    /// existing python-managed database.
    #[test]
    fn test_schema_column_widths_match_python_keystone() {
        let schema = Schema::new(DatabaseBackend::Postgres);
        let sql = schema
            .create_table_from_entity(crate::entity::prelude::Policy)
            .to_string(PostgresQueryBuilder);

        assert!(
            sql.contains(r#""id" varchar(64)"#),
            "expected id VARCHAR(64), got: {sql}"
        );
        assert!(
            sql.contains(r#""type" varchar(255)"#),
            "expected type VARCHAR(255), got: {sql}"
        );
        assert!(
            sql.contains(r#""blob" text NOT NULL"#),
            "expected blob TEXT NOT NULL, got: {sql}"
        );
        assert!(
            sql.contains(r#""extra" text"#),
            "expected extra TEXT, got: {sql}"
        );
    }
}
