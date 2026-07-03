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
//! # OpenStack Keystone Credentials SQL driver (ADR 0019)
//!
//! Persists to the `credential` table.

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};

mod credential;
pub mod entity;
pub mod error;
pub mod fernet;
pub mod migrate;
pub mod rotate;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// SQL backend provider implementing the `CredentialBackend` interface.
///
/// Deliberately zero-sized: all per-call configuration (key repository
/// path, Null Key policy) is read fresh from `state.config_manager` on each
/// call, matching the pattern used by other config-dependent backends in
/// this workspace (e.g. the Fernet token driver).
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
impl SqlDriver for SqlBackend {
    /// Create the `credential` table.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Credential).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, DbBackend, Schema};

    use super::*;

    #[tokio::test]
    async fn test_setup_creates_credential_table() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DbBackend::Sqlite);

        SqlBackend::default().setup(&db, &schema).await.unwrap();

        db.execute_unprepared("SELECT 1 FROM credential LIMIT 1")
            .await
            .unwrap();
    }
}
