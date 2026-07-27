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
use openstack_keystone_core_types::role::Role;

use crate::entity::{prelude::Role as DbRole, role as db_role};

/// Get a role by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The role ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `Role` if found, or an `Error`.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Role>, RoleProviderError> {
    let role_select = DbRole::find_by_id(id.as_ref());

    let entry: Option<db_role::Model> = role_select.one(db).await.context("fetching role by id")?;
    match entry {
        Some(model) => {
            let mut role: Role = model.try_into()?;
            role.options = crate::role_option::list_by_role_id(db, &role.id).await?;
            Ok(Some(role))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use openstack_keystone_core_types::role::RoleBuilder;

    use super::*;
    use crate::role::tests::get_role_mock;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            RoleBuilder::default()
                .id("1")
                .domain_id("foo_domain")
                .name("foo")
                .build()
                .unwrap()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log()[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_get_merges_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_mock("1", "foo")]])
            .append_query_results([vec![crate::entity::role_option::Model {
                role_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .into_connection();

        let role = get(&db, "1").await.unwrap().unwrap();
        assert_eq!(role.options.immutable, Some(true));
    }
}
