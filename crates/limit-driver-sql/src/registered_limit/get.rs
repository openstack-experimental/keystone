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
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::RegisteredLimit;

use crate::entity::prelude::RegisteredLimit as DbRegisteredLimit;
use crate::entity::registered_limit as db_registered_limit;

/// Get the registered limit by ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<RegisteredLimit>, LimitProviderError> {
    Ok(DbRegisteredLimit::find()
        .filter(db_registered_limit::Column::Id.eq(id.as_ref()))
        .one(db)
        .await
        .context("fetching registered limit")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;
    use crate::registered_limit::tests::get_mock;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1")]])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            RegisteredLimit {
                default_limit: 10,
                description: Some("descr".into()),
                id: "1".into(),
                region_id: None,
                resource_name: "cores".into(),
                service_id: "srv".into(),
            }
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "registered_limit"."internal_id", "registered_limit"."id", "registered_limit"."service_id", "registered_limit"."region_id", "registered_limit"."resource_name", "registered_limit"."default_limit", "registered_limit"."description" FROM "registered_limit" WHERE "registered_limit"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            )]
        );
    }
}
