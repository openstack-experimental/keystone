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
//! # Test-only table creation
//!
//! `SqlBackend::setup()` is a deliberate no-op in production (ADR 0019: the
//! `credential` table's schema is exclusively owned by Python Keystone's
//! `alembic` migrations). Integration tests that exercise this crate
//! against a real (throwaway, in-memory) database need the table to exist,
//! so this helper creates it directly — entirely separate from the
//! production `SqlDriver::setup()` path, and never wired into
//! `sync_schema()`.

use sea_orm::{ConnectionTrait, DatabaseConnection, Schema};

use openstack_keystone_core::db::create_table;
use openstack_keystone_core::error::DatabaseError;

/// Create the `credential` table in a test database.
///
/// # Errors
/// Returns a [`DatabaseError`] if the table creation fails.
pub async fn create_credential_table(db: &DatabaseConnection) -> Result<(), DatabaseError> {
    let schema = Schema::new(db.get_database_backend());
    create_table(db, &schema, crate::entity::prelude::Credential).await
}
