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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleImply;

use crate::entity::implied_role as db_implied_role;

/// Create a role imply rule.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
/// - `implied_role_id`: The ID of the implied role.
///
/// # Returns
/// A `Result` containing the created `RoleImply`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<RoleImply, RoleProviderError> {
    db_implied_role::ActiveModel {
        prior_role_id: Set(prior_role_id.into()),
        implied_role_id: Set(implied_role_id.into()),
    }
    .insert(db)
    .await
    .context("creating role imply rule")?
    .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_implied_role::Model {
                prior_role_id: "admin".into(),
                implied_role_id: "member".into(),
            }]])
            .into_connection();

        let created = create(&db, "admin", "member").await.unwrap();

        assert_eq!(created.id.as_deref(), Some("admin"));
        assert_eq!(created.implies_role_id.as_deref(), Some("member"));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "implied_role" ("prior_role_id", "implied_role_id") VALUES ($1, $2) RETURNING "prior_role_id", "implied_role_id""#,
                ["admin".into(), "member".into()]
            )]
        );
    }
}
