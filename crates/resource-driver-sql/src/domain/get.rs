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

use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{DatabaseConnection, FromQueryResult};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::{Domain, DomainRef};

use crate::entity::{prelude::Project as DbProject, project as db_project};

/// The columns of the domain row read for [`DomainRef`].
#[derive(Debug, FromQueryResult)]
struct DomainRefRow {
    id: String,
    name: String,
    enabled: Option<bool>,
}

/// Get the enabled status of a domain.
///
/// # Parameters
/// - `db`: Database connection.
/// - `domain_id`: ID of the domain.
///
/// # Returns
/// A `bool` indicating if the domain is enabled.
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

/// Get a domain by its ID.
///
/// # Parameters
/// - `db`: Database connection.
/// - `domain_id`: ID of the domain.
///
/// # Returns
/// A `Result` containing an `Option` with the `Domain` if found, or an `Error`.
pub async fn get_domain_by_id<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<Option<Domain>, ResourceProviderError> {
    // The options are keyed by the same ID: no need to wait for the domain.
    let (entry, options) = tokio::join!(
        DbProject::find_by_id(domain_id.as_ref())
            .filter(db_project::Column::IsDomain.eq(true))
            .one(db),
        crate::project_option::list_by_project_id(db, domain_id.as_ref())
    );
    match entry.context("fetching domain by id")? {
        Some(model) => {
            let mut domain: Domain = model.try_into()?;
            domain.options = options?;
            Ok(Some(domain))
        }
        None => Ok(None),
    }
}

/// Get the short representation of a domain by its ID.
///
/// A single query on the project row: the options are not loaded.
///
/// # Parameters
/// - `db`: Database connection.
/// - `domain_id`: ID of the domain.
///
/// # Returns
/// A `Result` containing an `Option` with the `DomainRef` if found, or an
/// `Error`.
pub async fn get_domain_ref_by_id<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<Option<DomainRef>, ResourceProviderError> {
    let row = DbProject::find_by_id(domain_id.as_ref())
        .filter(db_project::Column::IsDomain.eq(true))
        .select_only()
        .columns([
            db_project::Column::Id,
            db_project::Column::Name,
            db_project::Column::Enabled,
        ])
        .into_model::<DomainRefRow>()
        .one(db)
        .await
        .context("fetching the short domain by id")?;
    Ok(row.map(|row| DomainRef {
        // python keystone defaults to `true` when unset
        enabled: row.enabled.unwrap_or(true),
        id: row.id,
        name: row.name,
    }))
}

/// Get a domain by its name.
///
/// # Parameters
/// - `db`: Database connection.
/// - `domain_name`: Name of the domain.
///
/// # Returns
/// A `Result` containing an `Option` with the `Domain` if found, or an `Error`.
pub async fn get_domain_by_name<N: AsRef<str>>(
    db: &DatabaseConnection,
    domain_name: N,
) -> Result<Option<Domain>, ResourceProviderError> {
    let domain_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(true))
        .filter(db_project::Column::Name.eq(domain_name.as_ref()));

    let entry = domain_select
        .one(db)
        .await
        .context("fetching domain by name")?;
    match entry {
        Some(model) => {
            let mut domain: Domain = model.try_into()?;
            domain.options = crate::project_option::list_by_project_id(db, &domain.id).await?;
            Ok(Some(domain))
        }
        None => Ok(None),
    }
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
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .into_connection();

        assert_eq!(
            get_domain_by_name(&db, "name")
                .await
                .unwrap()
                .expect("entry found"),
            get_domain_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log()[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 AND "project"."name" = $2 LIMIT $3"#,
                [true.into(), "name".into(), 1u64.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_get_ref_is_a_single_query_without_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![BTreeMap::from([
                ("id", "1".into()),
                ("name", "name".into()),
                ("enabled", Some(true).into()),
            ])]])
            .into_connection();

        let domain = get_domain_ref_by_id(&db, "1")
            .await
            .unwrap()
            .expect("entry found");
        assert_eq!("1", domain.id);
        assert_eq!("name", domain.name);
        assert!(domain.enabled);
        let log = db.into_transaction_log();
        assert_eq!(1, log.len());
        assert_eq!(
            log[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."enabled" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                ["1".into(), true.into(), 1u64.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_get_ref_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<BTreeMap<&str, sea_orm::Value>>::new()])
            .into_connection();
        assert!(get_domain_ref_by_id(&db, "1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("1")]])
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .into_connection();

        assert_eq!(
            get_domain_by_id(&db, "1")
                .await
                .unwrap()
                .expect("entry found"),
            get_domain_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log()[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 AND "project"."is_domain" = $2 LIMIT $3"#,
                ["1".into(), true.into(), 1u64.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_get_by_id_merges_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("1")]])
            .append_query_results([vec![crate::entity::project_option::Model {
                project_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .into_connection();

        let domain = get_domain_by_id(&db, "1").await.unwrap().unwrap();
        assert_eq!(domain.options.immutable, Some(true));
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
