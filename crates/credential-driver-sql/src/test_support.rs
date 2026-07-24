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

use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::SqlDriver;
use openstack_keystone_core::error::DatabaseError;

/// Create the `credential` table in a test database.
///
/// # Errors
/// Returns a [`DatabaseError`] if the table creation fails.
pub async fn create_credential_table(db: &DatabaseConnection) -> Result<(), DatabaseError> {
    let schema = Schema::new(db.get_database_backend());
    crate::SqlBackend::default().setup(db, &schema).await
}
