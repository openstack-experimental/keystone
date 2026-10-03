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
//! # OpenStack Keystone SQL driver for the limit provider
//!
//! The driver works with the Python Keystone compatible `registered_limit`
//! and `limit` tables.

use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core::limit::backend::LimitBackend;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::limit::*;

pub mod entity;
mod limit;
mod registered_limit;

#[derive(Default)]
pub struct SqlBackend {}

/// Condition matching the nullable column either to the value or to NULL.
pub(crate) fn nullable_eq<C: sea_orm::ColumnTrait>(
    col: C,
    value: Option<&str>,
) -> sea_orm::sea_query::SimpleExpr {
    match value {
        Some(value) => col.eq(value),
        None => col.is_null(),
    }
}

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
    BackendRegistration::<dyn LimitBackend> {
        name: "sql",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(SqlBackend::default()) as Arc<dyn LimitBackend>)
        }),
    }
}

#[async_trait]
impl LimitBackend for SqlBackend {
    /// Create registered limits atomically.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_registered_limits<'a>(
        &self,
        state: &ServiceState,
        limits: Vec<RegisteredLimitCreate>,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
        registered_limit::create(&state.db.connection(), limits).await
    }

    /// Get a registered limit by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<RegisteredLimit>, LimitProviderError> {
        registered_limit::get(&state.db.connection(), id).await
    }

    /// List registered limits.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_registered_limits<'a>(
        &self,
        state: &ServiceState,
        params: &RegisteredLimitListParameters,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
        registered_limit::list(&state.db.connection(), params).await
    }

    /// Update a registered limit.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: RegisteredLimitUpdate,
    ) -> Result<RegisteredLimit, LimitProviderError> {
        registered_limit::update(&state.db.connection(), id, data).await
    }

    /// Delete a registered limit.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), LimitProviderError> {
        registered_limit::delete(&state.db.connection(), id).await
    }

    /// Create limits atomically.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_limits<'a>(
        &self,
        state: &ServiceState,
        limits: Vec<LimitCreate>,
    ) -> Result<Vec<Limit>, LimitProviderError> {
        limit::create(&state.db.connection(), limits).await
    }

    /// Get a limit by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Limit>, LimitProviderError> {
        limit::get(&state.db.connection(), id).await
    }

    /// List limits.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_limits<'a>(
        &self,
        state: &ServiceState,
        params: &LimitListParameters,
    ) -> Result<Vec<Limit>, LimitProviderError> {
        limit::list(&state.db.connection(), params).await
    }

    /// Update a limit.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: LimitUpdate,
    ) -> Result<Limit, LimitProviderError> {
        limit::update(&state.db.connection(), id, data).await
    }

    /// Delete a limit.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), LimitProviderError> {
        limit::delete(&state.db.connection(), id).await
    }

    /// Delete all limits of the project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_limits_by_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<(), LimitProviderError> {
        limit::delete_by_project(&state.db.connection(), project_id).await
    }

    /// Delete all limits of the domain.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_limits_by_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), LimitProviderError> {
        limit::delete_by_domain(&state.db.connection(), domain_id).await
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Sets up the database tables for the limits.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::RegisteredLimit).await?;
        create_table(connection, schema, crate::entity::prelude::Limit).await?;
        Ok(())
    }
}
