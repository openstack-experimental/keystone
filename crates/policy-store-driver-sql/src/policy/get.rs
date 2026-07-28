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
//! # Get policy

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core_types::policy_store::Policy;

use crate::entity::prelude::Policy as DbPolicy;

/// Fetches a single policy by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the policy.
///
/// # Returns
/// A `Result` containing an `Option` with the `Policy` if found, or an
/// `Error`.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Policy>, PolicyStoreProviderError> {
    DbPolicy::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching policy")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::Value;

    use super::super::tests::get_policy_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_policy_mock("1")]])
            .append_query_results([Vec::<crate::entity::policy::Model>::new()])
            .into_connection();

        let found = get(&db, "1").await.unwrap().unwrap();
        assert_eq!(found.id, "1");
        assert_eq!(
            found.blob,
            Value::String("{'foobar_user': 'role:compute-user'}".into())
        );

        assert!(get(&db, "missing").await.unwrap().is_none());

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "policy"."id", "policy"."type", "policy"."blob", "policy"."extra" FROM "policy" WHERE "policy"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "policy"."id", "policy"."type", "policy"."blob", "policy"."extra" FROM "policy" WHERE "policy"."id" = $1 LIMIT $2"#,
                    ["missing".into(), 1u64.into()]
                ),
            ]
        );
    }
}
