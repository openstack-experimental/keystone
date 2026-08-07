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
//! Replace the whole configuration of a domain.

use sea_orm::entity::*;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::domain_config::*;

use crate::entity::prelude::{
    SensitiveConfig as DbSensitiveConfig, WhitelistedConfig as DbWhitelistedConfig,
};
use crate::{delete, option};

/// Replace the whole configuration of a domain.
///
/// Backs `PUT /v3/domains/{domain_id}/config`: whatever the domain had is
/// dropped first, so an option absent from `config` is gone from both tables
/// afterwards.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain to configure.
/// - `config`: The configuration to store.
///
/// # Returns
/// - `Result<DomainConfig, DomainConfigProviderError>` - The stored
///   configuration.
pub async fn create(
    db: &DatabaseConnection,
    domain_id: &str,
    config: DomainConfigCreate,
) -> Result<DomainConfig, DomainConfigProviderError> {
    let config = config.into_inner();
    config.validate()?;
    // The values are decoded into the config sections they override, so a
    // value no option can hold is refused rather than stored for every later
    // read of the domain to trip over.
    config.validate_values()?;
    let options = config.to_options();

    let txn = db.begin().await.context("starting the transaction")?;
    // Delete-then-insert, not an upsert: this is a replace, so an option the
    // domain has stored but `config` does not carry has to be gone afterwards,
    // and an upsert would leave it behind. The delete is unfiltered for the
    // same reason — it has to reach the groups the request does not mention —
    // and it covers both tables, so a sensitive option is not left orphaned
    // behind a replaced `ldap` group. This is what python-keystone's
    // `create_config_options` does: it deletes every row of the domain from
    // `WhiteListedConfig` and `SensitiveConfig` before inserting the new
    // option list, in one transaction so a failed insert cannot leave the
    // domain unconfigured.
    delete::delete_rows(&txn, domain_id, None, None).await?;
    insert(&txn, domain_id, &options).await?;
    txn.commit().await.context("committing the transaction")?;

    // What was stored, not what was asked for, the way `update_config` answers
    // and the way python-keystone's `create_config` answers from the rows it
    // wrote. The two differ over a group the whitelist emptied, which the
    // request still carries and no read would ever report again.
    Ok(DomainConfig::from_options(options))
}

/// Insert options into the table each belongs to.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain the options belong to.
/// - `options`: The options to store.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful.
async fn insert<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    options: &[DomainConfigOption],
) -> Result<(), DomainConfigProviderError> {
    let (whitelisted, sensitive) = option::to_rows(domain_id, options)?;
    if !whitelisted.is_empty() {
        DbWhitelistedConfig::insert_many(whitelisted)
            .exec(db)
            .await
            .context("creating domain config options")?;
    }
    if !sensitive.is_empty() {
        DbSensitiveConfig::insert_many(sensitive)
            .exec(db)
            .await
            .context("creating sensitive domain config options")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::*;
    use crate::tests::{ldap_config, whitelisted_row};

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 2,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .append_query_results([vec![crate::tests::sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .into_connection();

        create(&db, "did", DomainConfigCreate(ldap_config()))
            .await
            .unwrap();

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
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) RETURNING "domain_id", "group", "option""#,
                    [
                        "did".into(),
                        "ldap".into(),
                        "url".into(),
                        r#""ldap://host""#.into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "sensitive_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) RETURNING "domain_id", "group", "option""#,
                    [
                        "did".into(),
                        "ldap".into(),
                        "password".into(),
                        r#""s3cr3t""#.into()
                    ]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#),
            ])]
        );
    }

    #[tokio::test]
    async fn test_create_of_a_group_the_whitelist_emptied_stores_nothing() {
        // python-keystone warns about the options it does not recognize, drops
        // them and succeeds; the domain ends up with the configuration it
        // asked for, which is none.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 0,
                    ..Default::default()
                },
            ])
            .into_connection();

        let config = create(
            &db,
            "did",
            DomainConfigCreate(crate::tests::domain_config(
                serde_json::json!({"ldap": {"bind_dn": "cn=admin"}}),
            )),
        )
        .await
        .unwrap();
        assert!(config.is_empty());
        // Not merely empty: the group the request carried is gone, so the
        // answer is the one a later read of the domain gives.
        assert!(config.group(DomainConfigGroupName::Ldap).is_none());

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
    async fn test_create_rolls_the_delete_back_when_the_insert_fails() {
        // What the delete-then-insert being one transaction buys: a failure
        // after the old rows are gone must not leave the domain unconfigured.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .append_query_errors([sea_orm::DbErr::Custom("connection lost".to_string())])
            .into_connection();

        create(&db, "did", DomainConfigCreate(ldap_config()))
            .await
            .unwrap_err();

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
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) RETURNING "domain_id", "group", "option""#,
                    [
                        "did".into(),
                        "ldap".into(),
                        "url".into(),
                        r#""ldap://host""#.into()
                    ]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"ROLLBACK"#),
            ])],
            "the delete is rolled back and nothing is committed"
        );
    }

    #[tokio::test]
    async fn test_create_rejects_a_value_the_option_cannot_hold() {
        // Storing it would fail every later resolution of the domain's
        // identity backend, not just a read of the option.
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = create(
            &db,
            "did",
            DomainConfigCreate(crate::tests::domain_config(
                serde_json::json!({"ldap": {"page_size": "a lot"}}),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value for option page_size in group ldap: expected an integer, got `\"a lot\"`"
        );
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_create_rejects_an_empty_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = create(&db, "did", DomainConfigCreate::default())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no options specified");
        assert_eq!(db.into_transaction_log(), []);
    }
}
