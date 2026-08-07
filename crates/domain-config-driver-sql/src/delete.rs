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
//! Delete the stored configuration of a domain.

use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::domain_config::*;

use crate::entity::prelude::{
    SensitiveConfig as DbSensitiveConfig, WhitelistedConfig as DbWhitelistedConfig,
};
use crate::entity::{sensitive_config, whitelisted_config};

/// Delete options of a domain from both tables.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: Restrict the delete to a single group.
/// - `option`: Restrict the delete to a single option.
///
/// # Returns
/// - `Result<u64, DomainConfigProviderError>` - How many rows were deleted
///   across both tables.
pub(crate) async fn delete_rows<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: Option<DomainConfigGroupName>,
    option: Option<&str>,
) -> Result<u64, DomainConfigProviderError> {
    let mut whitelisted = DbWhitelistedConfig::delete_many()
        .filter(whitelisted_config::Column::DomainId.eq(domain_id));
    let mut sensitive =
        DbSensitiveConfig::delete_many().filter(sensitive_config::Column::DomainId.eq(domain_id));
    if let Some(group) = group {
        whitelisted = whitelisted.filter(whitelisted_config::Column::Group.eq(group.as_str()));
        sensitive = sensitive.filter(sensitive_config::Column::Group.eq(group.as_str()));
    }
    if let Some(option) = option {
        whitelisted = whitelisted.filter(whitelisted_config::Column::Option.eq(option));
        sensitive = sensitive.filter(sensitive_config::Column::Option.eq(option));
    }
    let deleted = whitelisted
        .exec(db)
        .await
        .context("deleting domain config options")?
        .rows_affected;
    Ok(deleted
        + sensitive
            .exec(db)
            .await
            .context("deleting sensitive domain config options")?
            .rows_affected)
}

/// Delete the whole configuration of a domain.
///
/// Deleting a configuration that is not there is not an error: there is
/// nothing left to remove either way, and python-keystone's driver does not
/// report one.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful.
pub async fn delete_config(
    db: &DatabaseConnection,
    domain_id: &str,
) -> Result<(), DomainConfigProviderError> {
    let txn = db.begin().await.context("starting the transaction")?;
    delete_rows(&txn, domain_id, None, None).await?;
    txn.commit().await.context("committing the transaction")?;
    Ok(())
}

/// Delete a single configuration group of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: The group to delete.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
///   [`DomainConfigProviderError::NotFound`] when the domain has no option
///   stored in the group.
pub async fn delete_group(
    db: &DatabaseConnection,
    domain_id: &str,
    group: DomainConfigGroupName,
) -> Result<(), DomainConfigProviderError> {
    // A partial delete reports what is not there, as python-keystone's
    // `delete_config` does. The row count answers that without a preceding
    // read, and the transaction rolls back the half that did match, if any.
    let txn = db.begin().await.context("starting the transaction")?;
    if delete_rows(&txn, domain_id, Some(group), None).await? == 0 {
        return Err(DomainConfigProviderError::group_not_found(domain_id, group));
    }
    txn.commit().await.context("committing the transaction")?;
    Ok(())
}

/// Delete a single configuration option of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: The group holding the option.
/// - `option`: The option to delete.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
///   [`DomainConfigProviderError::NotFound`] when the option is not stored for
///   the domain.
pub async fn delete_option(
    db: &DatabaseConnection,
    domain_id: &str,
    group: DomainConfigGroupName,
    option: &str,
) -> Result<(), DomainConfigProviderError> {
    let txn = db.begin().await.context("starting the transaction")?;
    if delete_rows(&txn, domain_id, Some(group), Some(option)).await? == 0 {
        return Err(DomainConfigProviderError::option_not_found(
            domain_id, group, option,
        ));
    }
    txn.commit().await.context("committing the transaction")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::*;

    fn deleted(rows: u64) -> MockExecResult {
        MockExecResult {
            rows_affected: rows,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_delete_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(2), deleted(1)])
            .into_connection();

        delete_config(&db, "did").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1"#,
                    ["did".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "sensitive_config" WHERE "sensitive_config"."domain_id" = $1"#,
                    ["did".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#),
            ])]
        );
    }

    #[tokio::test]
    async fn test_delete_config_of_an_unconfigured_domain_is_not_an_error() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(0), deleted(0)])
            .into_connection();

        delete_config(&db, "did").await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_group() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(1), deleted(1)])
            .into_connection();

        delete_group(&db, "did", DomainConfigGroupName::Ldap)
            .await
            .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 AND "whitelisted_config"."group" = $2"#,
                    ["did".into(), "ldap".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "sensitive_config" WHERE "sensitive_config"."domain_id" = $1 AND "sensitive_config"."group" = $2"#,
                    ["did".into(), "ldap".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#),
            ])]
        );
    }

    #[tokio::test]
    async fn test_delete_group_that_is_not_configured() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(0), deleted(0)])
            .into_connection();

        let err = delete_group(&db, "did", DomainConfigGroupName::Ldap)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "could not find group ldap for domain did");
    }

    #[tokio::test]
    async fn test_delete_group_of_a_domain_with_only_a_sensitive_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(0), deleted(1)])
            .into_connection();

        delete_group(&db, "did", DomainConfigGroupName::Ldap)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(1), deleted(0)])
            .into_connection();

        delete_option(&db, "did", DomainConfigGroupName::Ldap, "url")
            .await
            .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 AND "whitelisted_config"."group" = $2 AND "whitelisted_config"."option" = $3"#,
                    ["did".into(), "ldap".into(), "url".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "sensitive_config" WHERE "sensitive_config"."domain_id" = $1 AND "sensitive_config"."group" = $2 AND "sensitive_config"."option" = $3"#,
                    ["did".into(), "ldap".into(), "url".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#),
            ])]
        );
    }

    #[tokio::test]
    async fn test_delete_option_that_is_not_configured() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(0), deleted(0)])
            .into_connection();

        let err = delete_option(&db, "did", DomainConfigGroupName::Ldap, "url")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "could not find option url in group ldap for domain did"
        );
    }

    #[tokio::test]
    async fn test_delete_a_sensitive_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([deleted(0), deleted(1)])
            .into_connection();

        delete_option(&db, "did", DomainConfigGroupName::Ldap, "password")
            .await
            .unwrap();
    }
}
