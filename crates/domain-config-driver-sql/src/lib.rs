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
//! # OpenStack Keystone SQL driver for the domain configuration provider
//!
//! Per-domain overrides of the identity backend configuration, stored the way
//! python-keystone stores them: one row per option, in two tables that differ
//! only in who may read them.
//!
//! `whitelisted_config` holds the readable options and `sensitive_config` the
//! write-only ones (today only `ldap.password`). Keeping them apart is what
//! makes the read paths safe by construction rather than by filtering: the
//! group and option scoped reads, which back the endpoints that hand options
//! to a client, only ever select from `whitelisted_config`. The whole-config
//! read is the one exception, since the identity backend has to be handed the
//! bind password; [`DomainConfig`] skips it on serialization, so it still
//! cannot reach a response.
//!
//! A third table, `config_register`, holds no option at all: it records which
//! domain holds the registration of a configuration type, the lock that keeps
//! at most one domain driving a given mechanism.
//!
//! Values are stored as their JSON encoding in a text column, matching
//! python-keystone's `JsonBlob`, so whatever type a client wrote is the type a
//! later read returns. References of the form `%(option)s` are stored verbatim
//! and resolved by [`DomainConfig::substitute`] when a consumer needs the
//! resolved value — never on a read that can reach the API.

use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::domain_config::backend::DomainConfigBackend;
use openstack_keystone_core::domain_config::error::DomainConfigProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::domain_config::*;

mod create;
mod delete;
pub mod entity;
mod get;
mod option;
mod registration;
mod update;

/// The SQL domain configuration driver.
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
    BackendRegistration::<dyn DomainConfigBackend> {
        name: "sql",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(SqlBackend::default()) as Arc<dyn DomainConfigBackend>)
        }),
    }
}

#[async_trait]
impl DomainConfigBackend for SqlBackend {
    /// Replace the whole configuration of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain to configure.
    /// - `config`: The configuration to store.
    ///
    /// # Returns
    /// A `Result` containing the stored `DomainConfig`, or an `Error`.
    async fn create_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        create::create(&state.db.connection(), domain_id, config).await
    }

    /// Get the whole configuration of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `DomainConfig` if the domain
    /// has one, or an `Error`.
    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
        get::get_config(&state.db.connection(), domain_id).await
    }

    /// Get a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to read.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `DomainConfigGroup` if the
    /// domain has a readable option stored in it, or an `Error`.
    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
        get::get_group(&state.db.connection(), domain_id, group).await
    }

    /// Get a single configuration option of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group holding the option.
    /// - `option`: The option to read.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `DomainConfigOption` if it is
    /// stored and readable, or an `Error`.
    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        get::get_option(&state.db.connection(), domain_id, group, option).await
    }

    /// Merge changes into the whole configuration of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `config`: The options to change.
    ///
    /// # Returns
    /// A `Result` containing the resulting `DomainConfig`, or an `Error`.
    async fn update_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        update::update_config(&state.db.connection(), domain_id, config).await
    }

    /// Merge changes into a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to change.
    /// - `config`: The options to change.
    ///
    /// # Returns
    /// A `Result` containing the resulting `DomainConfigGroup`, or an `Error`.
    async fn update_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        update::update_group(&state.db.connection(), domain_id, group, config).await
    }

    /// Change a single configuration option of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `option`: The option to change.
    ///
    /// # Returns
    /// A `Result` containing the stored `DomainConfigOption`, or an `Error`.
    async fn update_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError> {
        update::update_option(&state.db.connection(), domain_id, option).await
    }

    /// Delete the whole configuration of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn delete_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        delete::delete_config(&state.db.connection(), domain_id).await
    }

    /// Delete a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn delete_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError> {
        delete::delete_group(&state.db.connection(), domain_id, group).await
    }

    /// Delete a single configuration option of a domain.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group holding the option.
    /// - `option`: The option to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn delete_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        delete::delete_option(&state.db.connection(), domain_id, group, option).await
    }

    /// Try to register a domain for a configuration type.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain claiming the type.
    /// - `driver_type`: The registration type to claim.
    ///
    /// # Returns
    /// A `Result` containing `true` when the domain now holds the
    /// registration, `false` when somebody already does, or an `Error`.
    async fn obtain_registration<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        driver_type: &'a str,
    ) -> Result<bool, DomainConfigProviderError> {
        registration::obtain(&state.db.connection(), domain_id, driver_type).await
    }

    /// Read which domain holds the registration of a configuration type.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `driver_type`: The registration type to look up.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the ID of the domain holding it,
    /// or an `Error`.
    async fn read_registration<'a>(
        &self,
        state: &ServiceState,
        driver_type: &'a str,
    ) -> Result<Option<String>, DomainConfigProviderError> {
        registration::read(&state.db.connection(), driver_type).await
    }

    /// Release the registrations a domain holds.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The ID of the domain releasing them.
    /// - `driver_type`: The single type to release, or `None` for every type
    ///   the domain holds.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn release_registration<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        driver_type: Option<&'a str>,
    ) -> Result<(), DomainConfigProviderError> {
        registration::release(&state.db.connection(), domain_id, driver_type).await
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database tables.
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
        create_table(
            connection,
            schema,
            crate::entity::prelude::WhitelistedConfig,
        )
        .await?;
        create_table(connection, schema, crate::entity::prelude::SensitiveConfig).await?;
        create_table(connection, schema, crate::entity::prelude::ConfigRegister).await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use openstack_keystone_core_types::domain_config::DomainConfig;
    use serde_json::json;

    use crate::entity::{sensitive_config, whitelisted_config};

    /// A stored readable option row.
    pub fn whitelisted_row(
        domain_id: &str,
        group: &str,
        option: &str,
        value: &str,
    ) -> whitelisted_config::Model {
        whitelisted_config::Model {
            domain_id: domain_id.to_string(),
            group: group.to_string(),
            option: option.to_string(),
            value: value.to_string(),
        }
    }

    /// A stored sensitive option row.
    pub fn sensitive_row(
        domain_id: &str,
        group: &str,
        option: &str,
        value: &str,
    ) -> sensitive_config::Model {
        sensitive_config::Model {
            domain_id: domain_id.to_string(),
            group: group.to_string(),
            option: option.to_string(),
            value: value.to_string(),
        }
    }

    /// An `ldap` group carrying one readable and one sensitive option.
    pub fn ldap_config() -> DomainConfig {
        domain_config(json!({"ldap": {"url": "ldap://host", "password": "s3cr3t"}}))
    }

    /// A configuration built from a request body.
    pub fn domain_config(value: serde_json::Value) -> DomainConfig {
        DomainConfig::from_value(value).expect("a valid domain configuration")
    }

    /// The tables are part of python-keystone's initial schema, so this driver
    /// only creates them from its entities, on `keystone-manage db sync`. What
    /// that path has to get right is the columns (`group`, `option`), which are
    /// reserved words in SQL.
    mod schema {
        use sea_orm::{ConnectionTrait, DbBackend, Schema};

        use super::super::*;

        /// Store and read back one option per table, which is what proves the
        /// columns are usable and not only creatable.
        async fn assert_usable<C: ConnectionTrait>(db: &C) {
            for table in ["whitelisted_config", "sensitive_config"] {
                db.execute_unprepared(&format!(
                    r#"INSERT INTO "{table}" ("domain_id", "group", "option", "value")
                       VALUES ('did', 'ldap', 'url', '"ldap://host"')"#
                ))
                .await
                .unwrap_or_else(|err| panic!("inserting into {table}: {err}"));
                db.execute_unprepared(&format!(
                    r#"SELECT "value" FROM "{table}" WHERE "group" = 'ldap' AND "option" = 'url'"#
                ))
                .await
                .unwrap_or_else(|err| panic!("reading {table}: {err}"));
            }
        }

        #[tokio::test]
        async fn test_setup_creates_the_tables() {
            let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
            let schema = Schema::new(DbBackend::Sqlite);

            SqlBackend::default().setup(&db, &schema).await.unwrap();

            assert_usable(&db).await;
        }

        #[tokio::test]
        async fn test_the_primary_key_is_the_option_of_a_domain() {
            let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
            let schema = Schema::new(DbBackend::Sqlite);
            SqlBackend::default().setup(&db, &schema).await.unwrap();
            assert_usable(&db).await;

            assert!(
                db.execute_unprepared(
                    r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value")
                       VALUES ('did', 'ldap', 'url', '"ldap://other"')"#
                )
                .await
                .is_err(),
                "an option must be stored once per domain"
            );
            // The same option of another domain, and another option of the
            // same domain, are both fine.
            db.execute_unprepared(
                r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value")
                   VALUES ('other', 'ldap', 'url', '"ldap://other"'),
                          ('did', 'identity', 'driver', '"ldap"')"#,
            )
            .await
            .unwrap();
        }
    }
}
