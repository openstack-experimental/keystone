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
//! Read the stored configuration of a domain.
//!
//! Only [`get_config`] reads the sensitive table. The group and option scoped
//! reads back the endpoints that return options to a client, so they query
//! `whitelisted_config` alone: a secret cannot reach a response it was never
//! selected into.

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::domain_config::*;

use crate::entity::prelude::{
    SensitiveConfig as DbSensitiveConfig, WhitelistedConfig as DbWhitelistedConfig,
};
use crate::entity::{sensitive_config, whitelisted_config};
use crate::option;

/// Read the readable options of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: Restrict the read to a single group.
/// - `option`: Restrict the read to a single option.
///
/// # Returns
/// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The stored
///   options, in a stable order.
pub(crate) async fn load_whitelisted<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: Option<DomainConfigGroupName>,
    option: Option<&str>,
) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError> {
    let mut query = DbWhitelistedConfig::find()
        .filter(whitelisted_config::Column::DomainId.eq(domain_id))
        .order_by_asc(whitelisted_config::Column::Group)
        .order_by_asc(whitelisted_config::Column::Option);
    if let Some(group) = group {
        query = query.filter(whitelisted_config::Column::Group.eq(group.as_str()));
    }
    if let Some(option) = option {
        query = query.filter(whitelisted_config::Column::Option.eq(option));
    }
    option::from_whitelisted_rows(
        query
            .all(db)
            .await
            .context("reading domain config options")?,
    )
}

/// Read the sensitive options of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: Restrict the read to a single group.
/// - `option`: Restrict the read to a single option.
///
/// # Returns
/// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The stored
///   options, in a stable order.
pub(crate) async fn load_sensitive<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: Option<DomainConfigGroupName>,
    option: Option<&str>,
) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError> {
    let mut query = DbSensitiveConfig::find()
        .filter(sensitive_config::Column::DomainId.eq(domain_id))
        .order_by_asc(sensitive_config::Column::Group)
        .order_by_asc(sensitive_config::Column::Option);
    if let Some(group) = group {
        query = query.filter(sensitive_config::Column::Group.eq(group.as_str()));
    }
    if let Some(option) = option {
        query = query.filter(sensitive_config::Column::Option.eq(option));
    }
    option::from_sensitive_rows(
        query
            .all(db)
            .await
            .context("reading sensitive domain config options")?,
    )
}

/// Read every option of a domain, sensitive ones included.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: Restrict the read to a single group.
///
/// # Returns
/// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The stored
///   options, readable ones first.
pub(crate) async fn load_all<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: Option<DomainConfigGroupName>,
) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError> {
    let mut options = load_whitelisted(db, domain_id, group, None).await?;
    options.extend(load_sensitive(db, domain_id, group, None).await?);
    Ok(options)
}

/// Get the whole configuration of a domain.
///
/// The result carries the sensitive options, which the identity backend needs
/// in order to bind and which never reach a response because [`DomainConfig`]
/// skips them on serialization.
///
/// The two tables are read one after the other rather than as one snapshot,
/// the way python-keystone's `get_config_with_sensitive_info` reads them. A
/// `PUT` that commits between the two can therefore be seen half applied — an
/// old `ldap.url` next to a new `ldap.password`, say. Wrapping the pair in a
/// transaction would not close that window on its own, since `READ COMMITTED`
/// takes a fresh snapshot per statement; it takes a single query spanning both
/// tables, which is worth doing once there is a consumer to judge it against.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
///
/// # Returns
/// - `Result<Option<DomainConfig>, DomainConfigProviderError>` - The
///   configuration, or `None` when the domain has no option stored.
pub async fn get_config<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
    let options = load_all(db, domain_id, None).await?;
    if options.is_empty() {
        return Ok(None);
    }
    Ok(Some(DomainConfig::from_options(options)))
}

/// Get a single configuration group of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: The group to read.
///
/// # Returns
/// - `Result<Option<DomainConfigGroup>, DomainConfigProviderError>` - The group
///   without any sensitive option, or `None` when the domain has no readable
///   option stored in it.
pub async fn get_group<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: DomainConfigGroupName,
) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
    let options = load_whitelisted(db, domain_id, Some(group), None).await?;
    if options.is_empty() {
        return Ok(None);
    }
    Ok(Some(DomainConfigGroup::from_options(group, options)?))
}

/// Get a single configuration option of a domain.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain.
/// - `group`: The group holding the option.
/// - `option`: The option to read.
///
/// # Returns
/// - `Result<Option<DomainConfigOption>, DomainConfigProviderError>` - The
///   stored option, or `None` when it is sensitive, not stored for the domain,
///   or stored but no longer configurable (see [`option::decode`]).
pub async fn get_option<C: ConnectionTrait>(
    db: &C,
    domain_id: &str,
    group: DomainConfigGroupName,
    option: &str,
) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
    // A sensitive option is write only. Answering it from the readable table
    // would always be `None` anyway; returning early states why.
    if is_sensitive(group, option) {
        return Ok(None);
    }
    Ok(load_whitelisted(db, domain_id, Some(group), Some(option))
        .await?
        .into_iter()
        .next())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::*;
    use crate::tests::{sensitive_row, whitelisted_row};

    #[tokio::test]
    async fn test_get_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                whitelisted_row("did", "identity", "driver", r#""ldap""#),
                whitelisted_row("did", "ldap", "url", r#""ldap://host""#),
                whitelisted_row("did", "ldap", "page_size", "10"),
            ]])
            .append_query_results([vec![sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .into_connection();

        let config = get_config(&db, "did").await.unwrap().unwrap();
        let identity = config.group(DomainConfigGroupName::Identity).unwrap();
        assert_eq!(identity.get("driver"), Some(&json!("ldap")));
        let ldap = config.group(DomainConfigGroupName::Ldap).unwrap();
        assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
        assert_eq!(ldap.get("page_size"), Some(&json!(10)));
        assert_eq!(ldap.get("password"), Some(&json!("s3cr3t")));

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "whitelisted_config"."domain_id", "whitelisted_config"."group", "whitelisted_config"."option", "whitelisted_config"."value" FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 ORDER BY "whitelisted_config"."group" ASC, "whitelisted_config"."option" ASC"#,
                    ["did".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "sensitive_config"."domain_id", "sensitive_config"."group", "sensitive_config"."option", "sensitive_config"."value" FROM "sensitive_config" WHERE "sensitive_config"."domain_id" = $1 ORDER BY "sensitive_config"."group" ASC, "sensitive_config"."option" ASC"#,
                    ["did".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_get_config_of_an_unconfigured_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<whitelisted_config::Model>::new()])
            .append_query_results([Vec::<sensitive_config::Model>::new()])
            .into_connection();

        assert!(get_config(&db, "did").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_config_of_a_domain_with_only_a_sensitive_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<whitelisted_config::Model>::new()])
            .append_query_results([vec![sensitive_row(
                "did",
                "ldap",
                "password",
                r#""s3cr3t""#,
            )]])
            .into_connection();

        assert!(get_config(&db, "did").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_get_config_skips_a_stale_row() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                whitelisted_row("did", "assignment", "driver", r#""sql""#),
                whitelisted_row("did", "ldap", "url", r#""ldap://host""#),
            ]])
            .append_query_results([Vec::<sensitive_config::Model>::new()])
            .into_connection();

        let config = get_config(&db, "did").await.unwrap().unwrap();
        assert!(config.group(DomainConfigGroupName::Identity).is_none());
        assert_eq!(
            config
                .group(DomainConfigGroupName::Ldap)
                .and_then(|group| group.get("url")),
            Some(&json!("ldap://host"))
        );
    }

    /// A row of a configurable group whose option is no longer whitelisted has
    /// to read exactly like a row of a group that is no longer configurable:
    /// the domain is unconfigured, not configured with nothing. Otherwise the
    /// two spellings of the same drift answer a client differently — `404`
    /// against `200` with an empty configuration.
    #[tokio::test]
    async fn test_get_config_of_a_domain_with_only_a_stale_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "bind_dn",
                r#""cn=admin""#,
            )]])
            .append_query_results([Vec::<sensitive_config::Model>::new()])
            .into_connection();

        assert!(get_config(&db, "did").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_group_of_a_group_with_only_a_stale_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "bind_dn",
                r#""cn=admin""#,
            )]])
            .into_connection();

        assert!(
            get_group(&db, "did", DomainConfigGroupName::Ldap)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The option scoped read is the one path with no later
    /// `DomainConfig::from_options` to drop a stale row for it, so it is the
    /// one that would otherwise hand a client an option the whitelist no
    /// longer covers.
    #[tokio::test]
    async fn test_get_option_never_reads_a_stale_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "bind_dn",
                r#""cn=admin""#,
            )]])
            .into_connection();

        assert!(
            get_option(&db, "did", DomainConfigGroupName::Ldap, "bind_dn")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_get_group_does_not_read_the_sensitive_table() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let group = get_group(&db, "did", DomainConfigGroupName::Ldap)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(group.name(), DomainConfigGroupName::Ldap);
        assert_eq!(group.get("url"), Some(&json!("ldap://host")));
        assert!(group.get("password").is_none());

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "whitelisted_config"."domain_id", "whitelisted_config"."group", "whitelisted_config"."option", "whitelisted_config"."value" FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 AND "whitelisted_config"."group" = $2 ORDER BY "whitelisted_config"."group" ASC, "whitelisted_config"."option" ASC"#,
                ["did".into(), "ldap".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_group_of_an_unconfigured_group() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<whitelisted_config::Model>::new()])
            .into_connection();

        assert!(
            get_group(&db, "did", DomainConfigGroupName::Identity)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_get_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![whitelisted_row(
                "did",
                "ldap",
                "url",
                r#""ldap://host""#,
            )]])
            .into_connection();

        let option = get_option(&db, "did", DomainConfigGroupName::Ldap, "url")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(option.value.as_str(), Some("ldap://host"));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "whitelisted_config"."domain_id", "whitelisted_config"."group", "whitelisted_config"."option", "whitelisted_config"."value" FROM "whitelisted_config" WHERE "whitelisted_config"."domain_id" = $1 AND "whitelisted_config"."group" = $2 AND "whitelisted_config"."option" = $3 ORDER BY "whitelisted_config"."group" ASC, "whitelisted_config"."option" ASC"#,
                ["did".into(), "ldap".into(), "url".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_option_never_reads_a_sensitive_option() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        assert!(
            get_option(&db, "did", DomainConfigGroupName::Ldap, "password")
                .await
                .unwrap()
                .is_none()
        );
        // Not a single statement was issued for it.
        assert_eq!(db.into_transaction_log(), []);
    }
}
