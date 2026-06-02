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

use crate::entity::{implied_role as db_implied_role, prelude::ImpliedRole};

/// List all role imply rules.
///
/// # Parameters
/// - `db`: The database connection.
///
/// # Returns
/// A `Result` containing a list of `RoleImply`, or an `Error`.
pub async fn list(db: &DatabaseConnection) -> Result<Vec<RoleImply>, RoleProviderError> {
    let db_rules: Vec<db_implied_role::Model> = ImpliedRole::find()
        .all(db)
        .await
        .context("listing role imply rules")?;
    let results: Result<Vec<RoleImply>, _> = db_rules.into_iter().map(TryInto::try_into).collect();
    results
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
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_implied_role_mock("admin", "member"),
                get_implied_role_mock("member", "reader"),
            ]])
            .into_connection();

        let results = list(&db).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id.as_deref(), Some("admin"));
        assert_eq!(results[0].implies_role_id.as_deref(), Some("member"));
        assert_eq!(results[1].id.as_deref(), Some("member"));
        assert_eq!(results[1].implies_role_id.as_deref(), Some("reader"));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                []
            )]
        );
    }

    #[tokio::test]
    async fn test_list_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<crate::entity::implied_role::Model>::new()])
            .into_connection();

        let results = list(&db).await.unwrap();

        assert!(results.is_empty());
    }
}
