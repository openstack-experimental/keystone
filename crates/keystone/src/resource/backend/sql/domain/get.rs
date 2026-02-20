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

use crate::db::entity::{prelude::Project as DbProject, project as db_project};
use crate::error::DbContextExt;
use crate::resource::{ResourceProviderError, types::Domain};

pub async fn get_domain_enabled<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<bool, ResourceProviderError> {
    DbProject::find_by_id(domain_id.as_ref())
        .filter(db_project::Column::IsDomain.eq(true))
        .select_only()
        .column(db_project::Column::Enabled)
        .into_tuple()
        .one(db)
        .await
        .context("fetching domain `enabled` by id")?
        .map(|x: Option<bool>| x.unwrap_or(true)) // python keystone defaults to `true` when unset
        .ok_or(ResourceProviderError::DomainNotFound(
            domain_id.as_ref().to_string(),
        ))
}

pub async fn get_domain_by_id<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<Option<Domain>, ResourceProviderError> {
    DbProject::find_by_id(domain_id.as_ref())
        .filter(db_project::Column::IsDomain.eq(true))
        .one(db)
        .await
        .context("fetching domain by id")?
        .map(TryInto::try_into)
        .transpose()
}

pub async fn get_domain_by_name<N: AsRef<str>>(
    db: &DatabaseConnection,
    domain_name: N,
) -> Result<Option<Domain>, ResourceProviderError> {
    let domain_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(true))
        .filter(db_project::Column::Name.eq(domain_name.as_ref()));

    domain_select
        .one(db)
        .await
        .context("fetching domain by name")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};
    use std::collections::BTreeMap;

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_get_by_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("1")]])
            .into_connection();

        assert_eq!(
            get_domain_by_name(&db, "name")
                .await
                .unwrap()
                .expect("entry found"),
            get_domain_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 AND "project"."name" = $2 LIMIT $3"#,
                [true.into(), "name".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("1")]])
            .into_connection();

        assert_eq!(
            get_domain_by_id(&db, "1")
                .await
                .unwrap()
                .expect("entry found"),
            get_domain_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                ["1".into(), true.into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_domain_enabled() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project::Model>::new()])
            .append_query_results([vec![
                BTreeMap::from([("enabled", Into::<Value>::into(Some(true)))]).into_mock_row(),
            ]])
            .append_query_results([vec![
                BTreeMap::from([("enabled", Into::<Value>::into(Some(false)))]).into_mock_row(),
            ]])
            .append_query_results([vec![
                BTreeMap::from([("enabled", Into::<Value>::into(None::<bool>))]).into_mock_row(),
            ]])
            .into_connection();

        assert!(get_domain_enabled(&db, "missing").await.is_err());
        assert!(get_domain_enabled(&db, "id").await.unwrap(),);
        assert!(
            !get_domain_enabled(&db, "id").await.unwrap(),
            "Some(false) should be disabled"
        );
        assert!(
            get_domain_enabled(&db, "id").await.unwrap(),
            "enabled is empty in the db considered as active"
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."enabled" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                    ["missing".into(), true.into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."enabled" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                    ["id".into(), true.into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."enabled" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                    ["id".into(), true.into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."enabled" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                    ["id".into(), true.into(), 1u64.into()]
                ),
            ]
        );
    }
}
