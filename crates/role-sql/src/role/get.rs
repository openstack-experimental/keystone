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
use openstack_keystone_core::role::{RoleProviderError, types::Role};

use crate::entity::{prelude::Role as DbRole, role as db_role};

pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Role>, RoleProviderError> {
    let role_select = DbRole::find_by_id(id.as_ref());

    let entry: Option<db_role::Model> = role_select.one(db).await.context("fetching role by id")?;
    entry.map(TryInto::try_into).transpose()
}

#[cfg(test)]
pub(super) mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use openstack_keystone_core::role::types::RoleBuilder;

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
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }
}
