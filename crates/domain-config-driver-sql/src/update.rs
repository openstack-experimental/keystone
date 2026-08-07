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
//! Merge changes into the stored configuration of a domain.
//!
//! An update never removes an option, so every write is an upsert: an option
//! the domain already has is overwritten in place, one it does not have is
//! added.
//!
//! The state a write returns is read back from `whitelisted_config` and the
//! sensitive options *of that request*, never the ones already stored. It is
//! what a caller just supplied, the same way [`crate::create`] returns it, so
//! a caller that patches only `ldap.password` still sees a group that is not
//! empty — but a caller that patches only `ldap.url` is never handed a secret
//! it did not write, which is what the group scoped read guarantees too.

use sea_orm::entity::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::domain_config::*;

use crate::entity::prelude::{
    SensitiveConfig as DbSensitiveConfig, WhitelistedConfig as DbWhitelistedConfig,
};
use crate::entity::{sensitive_config, whitelisted_config};
use crate::{get, option};

/// Merge changes into the whole configuration of a domain.
///
/// Backs `PATCH /v3/domains/{domain_id}/config`.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `config`: The options to change.
///
/// # Returns
/// - `Result<DomainConfig, DomainConfigProviderError>` - The resulting
///   configuration.
pub async fn update_config(
    db: &DatabaseConnection,
    domain_id: &str,
    config: DomainConfigUpdate,
) -> Result<DomainConfig, DomainConfigProviderError> {
    let config = config.into_inner();
    config.validate()?;
    // The values are decoded into the config sections they override, so a
    // value no option can hold is refused rather than stored for every later
    // read of the domain to trip over.
    config.validate_values()?;
    let options = config.to_options();

    let txn = db.begin().await.context("starting the transaction")?;
    upsert(&txn, domain_id, &options).await?;
    let mut merged = get::load_whitelisted(&txn, domain_id, None, None).await?;
    txn.commit().await.context("committing the transaction")?;

    merged.extend(options.into_iter().filter(|option| option.sensitive()));
    Ok(DomainConfig::from_options(merged))
}

/// Merge changes into a single configuration group of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: The group to change.
/// - `config`: The options to change; only `group` may be populated.
///
/// # Returns
/// - `Result<DomainConfigGroup, DomainConfigProviderError>` - The resulting
///   group, or [`DomainConfigProviderError::GroupMismatch`] when the payload
///   does not address exactly the group of the request.
pub async fn update_group(
    db: &DatabaseConnection,
    domain_id: &str,
    group: DomainConfigGroupName,
    config: DomainConfigUpdate,
) -> Result<DomainConfigGroup, DomainConfigProviderError> {
    let config = config.into_inner();
    config.validate()?;
    // The values are decoded into the config sections they override, so a
    // value no option can hold is refused rather than stored for every later
    // read of the domain to trip over.
    config.validate_values()?;
    if DomainConfigGroupName::ALL
        .iter()
        .any(|name| *name != group && config.group(*name).is_some())
    {
        return Err(DomainConfigProviderError::GroupMismatch(group.to_string()));
    }
    let options = config
        .group(group)
        .ok_or_else(|| DomainConfigProviderError::GroupMismatch(group.to_string()))?
        .to_options();

    let txn = db.begin().await.context("starting the transaction")?;
    upsert(&txn, domain_id, &options).await?;
    let mut merged = get::load_whitelisted(&txn, domain_id, Some(group), None).await?;
    txn.commit().await.context("committing the transaction")?;

    merged.extend(options.into_iter().filter(|option| option.sensitive()));
    DomainConfigGroup::from_options(group, merged)
}

/// Change a single configuration option of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `option`: The option to change, carrying its group, name and value.
///
/// # Returns
/// - `Result<DomainConfigOption, DomainConfigProviderError>` - The stored
///   option, or an error when it is not one a domain can hold; see
///   [`option::assert_storable`].
pub async fn update_option(
    db: &DatabaseConnection,
    domain_id: &str,
    option: DomainConfigOption,
) -> Result<DomainConfigOption, DomainConfigProviderError> {
    option::assert_storable(&option)?;
    upsert(db, domain_id, std::slice::from_ref(&option)).await?;
    Ok(option)
}

/// Write options, overwriting the ones the domain already has.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain the options belong to.
/// - `options`: The options to store.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful.
async fn upsert<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    options: &[DomainConfigOption],
) -> Result<(), DomainConfigProviderError> {
    let (whitelisted, sensitive) = option::to_rows(domain_id, options)?;
    if !whitelisted.is_empty() {
        DbWhitelistedConfig::insert_many(whitelisted)
            .on_conflict(
                OnConflict::columns([
                    whitelisted_config::Column::DomainId,
                    whitelisted_config::Column::Group,
                    whitelisted_config::Column::Option,
                ])
                .update_column(whitelisted_config::Column::Value)
                .to_owned(),
            )
            .exec(db)
            .await
            .context("updating domain config options")?;
    }
    if !sensitive.is_empty() {
        DbSensitiveConfig::insert_many(sensitive)
            .on_conflict(
                OnConflict::columns([
                    sensitive_config::Column::DomainId,
                    sensitive_config::Column::Group,
                    sensitive_config::Column::Option,
                ])
                .update_column(sensitive_config::Column::Value)
                .to_owned(),
            )
            .exec(db)
            .await
            .context("updating sensitive domain config options")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Statement, Transaction};

    use serde_json::json;

    use super::*;
    use crate::tests::{domain_config, ldap_config, sensitive_row, whitelisted_row};

    #[tokio::test]
    async fn test_update_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .append_query_results([vec![sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let config = update_config(&db, "did", DomainConfigUpdate(ldap_config()))
            .await
            .unwrap();
        let ldap = config.group(DomainConfigGroupName::Ldap).unwrap();
        assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
        // The password of this very request, read back from nowhere.
        assert!(ldap.get("password").is_some());

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) ON CONFLICT ("domain_id", "group", "option") DO UPDATE SET "value" = "excluded"."value" RETURNING "domain_id", "group", "option""#,
                    [
                        "did".into(),
                        "ldap".into(),
                        "url".into(),
                        r#""ldap://host""#.into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "sensitive_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) ON CONFLICT ("domain_id", "group", "option") DO UPDATE SET "value" = "excluded"."value" RETURNING "domain_id", "group", "option""#,
                    [
                        "did".into(),
                        "ldap".into(),
                        "password".into(),
                        r#""s3cr3t""#.into()
                    ]
                ),
                // The read back never touches the sensitive table.
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "whitelisted_config"."domain_id", "whitelisted_config"."group", "whitelisted_config"."option", "whitelisted_config"."value" FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 ORDER BY "whitelisted_config"."group" ASC, "whitelisted_config"."option" ASC"#,
                    ["did".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#),
            ])]
        );
    }

    #[tokio::test]
    async fn test_update_config_does_not_read_back_a_stored_secret() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let config = update_config(
            &db,
            "did",
            DomainConfigUpdate(domain_config(json!({"ldap": {"url": "ldap://host"}}))),
        )
        .await
        .unwrap();
        assert!(
            config
                .group(DomainConfigGroupName::Ldap)
                .and_then(|group| group.get("password"))
                .is_none(),
            "a request that writes no secret must not be handed the stored one"
        );
    }

    #[tokio::test]
    async fn test_update_config_rejects_a_value_the_option_cannot_hold() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = update_config(
            &db,
            "did",
            DomainConfigUpdate(domain_config(json!({"ldap": {"use_tls": "maybe"}}))),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value for option use_tls in group ldap: expected a boolean, got `\"maybe\"`"
        );
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_update_config_rejects_an_empty_payload() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = update_config(&db, "did", DomainConfigUpdate::default())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no options specified");
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_update_group() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "identity",
                "driver",
                r#""ldap""#,
            )]])
            .append_query_results([vec![whitelisted_row(
                "did",
                "identity",
                "driver",
                r#""ldap""#,
            )]])
            .into_connection();

        let group = update_group(
            &db,
            "did",
            DomainConfigGroupName::Identity,
            DomainConfigUpdate(domain_config(json!({"identity": {"driver": "ldap"}}))),
        )
        .await
        .unwrap();
        assert_eq!(group.name(), DomainConfigGroupName::Identity);
        assert_eq!(group.get("driver"), Some(&json!("ldap")));
    }

    #[tokio::test]
    async fn test_update_group_does_not_read_back_a_stored_secret() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let group = update_group(
            &db,
            "did",
            DomainConfigGroupName::Ldap,
            DomainConfigUpdate(domain_config(json!({"ldap": {"url": "ldap://host"}}))),
        )
        .await
        .unwrap();
        assert_eq!(group.name(), DomainConfigGroupName::Ldap);
        assert!(
            group.get("password").is_none(),
            "a request that writes no secret must not be handed the stored one"
        );
    }

    #[tokio::test]
    async fn test_update_group_returns_the_secret_of_the_request() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .append_query_results([Vec::<whitelisted_config::Model>::new()])
            .into_connection();

        let group = update_group(
            &db,
            "did",
            DomainConfigGroupName::Ldap,
            DomainConfigUpdate(domain_config(json!({"ldap": {"password": "s3cr3t"}}))),
        )
        .await
        .unwrap();
        assert_eq!(group.name(), DomainConfigGroupName::Ldap);
        // Otherwise a patch of only the password would answer with an empty
        // group.
        assert!(group.get("password").is_some());
    }

    #[tokio::test]
    async fn test_update_group_rejects_another_group() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = update_group(
            &db,
            "did",
            DomainConfigGroupName::Identity,
            DomainConfigUpdate(ldap_config()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "trying to update group identity, so that, and only that, \
             group must be specified in the config"
        );
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_update_group_rejects_a_payload_of_another_group_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = update_group(
            &db,
            "did",
            DomainConfigGroupName::Ldap,
            DomainConfigUpdate(domain_config(json!({"identity": {"driver": "ldap"}}))),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            DomainConfigProviderError::GroupMismatch(group) if group == "ldap"
        ));
    }

    #[tokio::test]
    async fn test_update_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let stored = update_option(
            &db,
            "did",
            DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", "ldap://host"),
        )
        .await
        .unwrap();
        assert_eq!(stored.value.as_str(), Some("ldap://host"));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "whitelisted_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) ON CONFLICT ("domain_id", "group", "option") DO UPDATE SET "value" = "excluded"."value" RETURNING "domain_id", "group", "option""#,
                [
                    "did".into(),
                    "ldap".into(),
                    "url".into(),
                    r#""ldap://host""#.into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_update_a_sensitive_option_writes_the_sensitive_table_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .into_connection();

        update_option(
            &db,
            "did",
            DomainConfigOption::new(DomainConfigGroupName::Ldap, "password", "s3cr3t"),
        )
        .await
        .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "sensitive_config" ("domain_id", "group", "option", "value") VALUES ($1, $2, $3, $4) ON CONFLICT ("domain_id", "group", "option") DO UPDATE SET "value" = "excluded"."value" RETURNING "domain_id", "group", "option""#,
                [
                    "did".into(),
                    "ldap".into(),
                    "password".into(),
                    r#""s3cr3t""#.into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_update_option_rejects_an_unsupported_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let err = update_option(
            &db,
            "did",
            DomainConfigOption::new(DomainConfigGroupName::Ldap, "bind_dn", "cn=admin"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "option bind_dn in group ldap is not supported for domain specific configurations"
        );
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_update_config_stores_a_substitution_reference_verbatim() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://%(user)s:%(password)s@host""#,
            )]])
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://%(user)s:%(password)s@host""#,
            )]])
            .into_connection();

        let config = update_config(
            &db,
            "did",
            DomainConfigUpdate(domain_config(
                json!({"ldap": {"url": "ldap://%(user)s:%(password)s@host"}}),
            )),
        )
        .await
        .unwrap();
        assert_eq!(
            config
                .group(DomainConfigGroupName::Ldap)
                .and_then(|group| group.get("url")),
            Some(&json!("ldap://%(user)s:%(password)s@host"))
        );
    }
}
