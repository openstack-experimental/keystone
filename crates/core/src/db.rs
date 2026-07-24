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
//! # Internal tools for the database handling

use sea_orm::{
    ConnectionTrait, DatabaseConnection, EntityTrait, Schema, sea_query::IndexCreateStatement,
};

use crate::SqlDriverRegistration;
use crate::error::{DatabaseError, DbContextExt};

/// Create the table in the database with directly related types and indexes.
pub async fn create_table<C, E>(conn: &C, schema: &Schema, entity: E) -> Result<(), DatabaseError>
where
    C: ConnectionTrait,
    E: EntityTrait,
{
    // Create types before the table
    for ttype in schema.create_enum_from_entity(entity) {
        conn.execute(&ttype).await.context("creating types")?;
    }
    // Create the table
    conn.execute(&schema.create_table_from_entity(entity))
        .await
        .context("creating table")?;
    // Create related indexes
    for tidx in schema.create_index_from_entity(entity) {
        conn.execute(&tidx)
            .await
            .context("creating table indexes")?;
    }
    Ok(())
}

/// Create the index.
pub async fn create_index<C>(conn: &C, index: IndexCreateStatement) -> Result<(), DatabaseError>
where
    C: ConnectionTrait,
{
    conn.execute(&index).await.context("creating the index")?;
    Ok(())
}

/// Run `SqlDriver::setup` for every registered SQL driver.
///
/// This is the entry point used by the `keystone` binary and the
/// `keystone-manage` CLI to create tables and seed data for an in-memory SQLite
/// database.
///
/// # Parameters
/// - `db`: The database connection.
///
/// # Returns
/// - `Ok(())` if all drivers were set up successfully.
/// - `Err(DatabaseError)` if any driver failed.
pub async fn sync_schema(db: &DatabaseConnection) -> Result<(), DatabaseError> {
    let schema = Schema::new(db.get_database_backend());

    for (i, driver) in inventory::iter::<SqlDriverRegistration>
        .into_iter()
        .enumerate()
    {
        tracing::info!("Setting up SQL driver {}", i + 1);
        driver
            .driver
            .setup(db, &schema)
            .await
            .map_err(|e| DatabaseError::Sql {
                message: e.to_string(),
                context: "setup SQL driver".to_string(),
            })?;
    }

    Ok(())
}
