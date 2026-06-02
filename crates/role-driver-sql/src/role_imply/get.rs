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
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleImply;

use crate::entity::{implied_role as db_implied_role, prelude::ImpliedRole};

/// Get a role imply rule by prior and implied role IDs.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
/// - `implied_role_id`: The ID of the implied role.
///
/// # Returns
/// A `Result` containing an `Option` with the `RoleImply` if found, or an `Error`.
pub async fn get(
    db: &DatabaseConnection,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<Option<RoleImply>, RoleProviderError> {
    use crate::entity::implied_role::Column;

    let entry: Option<db_implied_role::Model> = ImpliedRole::find()
        .filter(Column::PriorRoleId.eq(prior_role_id))
        .filter(Column::ImpliedRoleId.eq(implied_role_id))
        .one(db)
        .await
        .context("fetching role imply rule")?;
    entry.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    fn get_implied_role_mock(prior: &str, implied: &str) -> crate::entity::implied_role::Model {
        crate::entity::implied_role::Model {
            prior_role_id: prior.into(),
            implied_role_id: implied.into(),
        }
    }

    #[tokio::test]
    async fn test_get_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_implied_role_mock("admin", "member")]])
            .into_connection();

        let result = get(&db, "admin", "member").await.unwrap().unwrap();

        assert_eq!(result.id.as_deref(), Some("admin"));
        assert_eq!(result.implies_role_id.as_deref(), Some("member"));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role" WHERE "implied_role"."prior_role_id" = $1 AND "implied_role"."implied_role_id" = $2 LIMIT $3"#,
                ["admin".into(), "member".into(), 1u64.into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<crate::entity::implied_role::Model>::new()])
            .into_connection();

        let result = get(&db, "admin", "member").await.unwrap();

        assert!(result.is_none());
    }
}
