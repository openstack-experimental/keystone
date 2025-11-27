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
//! List not expired revocation event records invalidating the token.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::db::entity::{
    prelude::RevocationEvent as DbRevocationEvent, revocation_event as db_revocation_event,
};
use crate::revoke::backend::error::{RevokeDatabaseError, db_err};
use crate::revoke::types::{RevocationEvent, RevocationEventListParameters};

fn build_query_filters(
    params: &RevocationEventListParameters,
) -> Result<Select<DbRevocationEvent>, RevokeDatabaseError> {
    tracing::info!("Query parameters: {:?}", params);
    let mut select = DbRevocationEvent::find();

    //if let Some(val) = &params.access_token_id {
    //    select =
    // select.filter(db_revocation_event::Column::AccessTokenId.eq(val));
    //}

    //if let Some(val) = &params.audit_chain_id {
    //    select = select.filter(db_revocation_event::Column::AuditChainId.eq(val));
    //}

    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::AuditId.is_null())
            .add_option(
                params
                    .audit_id
                    .as_ref()
                    .map(|val| db_revocation_event::Column::AuditId.eq(val)),
            ),
    );

    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::DomainId.is_null())
            .add_option(
                params
                    .domain_ids
                    .as_ref()
                    .and_then(|val| if val.is_empty() { None } else { Some(val) })
                    .map(|val| db_revocation_event::Column::DomainId.is_in(val)),
            ),
    );

    if let Some(val) = params.expires_at {
        select = select.filter(db_revocation_event::Column::ExpiresAt.eq(val));
    }

    if let Some(val) = params.issued_before {
        select = select.filter(db_revocation_event::Column::IssuedBefore.gte(val));
    }

    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::ProjectId.is_null())
            .add_option(
                params
                    .project_id
                    .as_ref()
                    .map(|val| db_revocation_event::Column::ProjectId.eq(val)),
            ),
    );

    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::RoleId.is_null())
            .add_option(
                params
                    .role_ids
                    .as_ref()
                    .and_then(|val| if val.is_empty() { None } else { Some(val) })
                    .map(|val| db_revocation_event::Column::RoleId.is_in(val)),
            ),
    );
    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::UserId.is_null())
            .add_option(
                params
                    .user_ids
                    .as_ref()
                    .and_then(|val| if val.is_empty() { None } else { Some(val) })
                    .map(|val| db_revocation_event::Column::UserId.is_in(val)),
            ),
    );

    Ok(select)
}

/// Count token revocation events.
///
/// Return not expired revocation records that invalidate the token.
pub async fn count(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<u64, RevokeDatabaseError> {
    build_query_filters(params)?
        .count(db)
        .await
        .map_err(|err| db_err(err, "counting revocation events for the token"))
}

/// List token revocation events.
///
/// Return not expired revocation records that invalidate the token.
#[allow(unused)]
pub async fn list(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<Vec<RevocationEvent>, RevokeDatabaseError> {
    let db_entities: Vec<db_revocation_event::Model> =
        build_query_filters(params)?
            .all(db)
            .await
            .map_err(|err| db_err(err, "listing revocation events for the token"))?;

    let results: Result<Vec<RevocationEvent>, _> = db_entities
        .into_iter()
        .map(TryInto::<RevocationEvent>::try_into)
        .collect();

    results
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Days, Utc};
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};
    use std::collections::BTreeMap;

    use super::super::tests::get_mock;
    use super::*;
    use crate::revoke::backend::sql::RevocationEventListParametersBuilder;

    #[tokio::test]
    async fn test_count() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([("num_items", Into::<Value>::into(3i64))]).into_mock_row(),
            ]])
            .into_connection();
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();

        assert_eq!(
            count(
                &db,
                &RevocationEventListParametersBuilder::default()
                    .audit_id("audit_id")
                    .domain_ids(vec!["domain_id1".into(), "domain_id2".into()])
                    .expires_at(time2)
                    .issued_before(time1)
                    .project_id("project_id")
                    .role_ids(vec!["rid1".into(), "rid2".into()])
                    .build()
                    .unwrap()
            )
            .await
            .unwrap(),
            3
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT COUNT(*) AS num_items FROM (SELECT "revocation_event"."id", "revocation_event"."domain_id", "revocation_event"."project_id", "revocation_event"."user_id", "revocation_event"."role_id", "revocation_event"."trust_id", "revocation_event"."consumer_id", "revocation_event"."access_token_id", "revocation_event"."issued_before", "revocation_event"."expires_at", "revocation_event"."revoked_at", "revocation_event"."audit_id", "revocation_event"."audit_chain_id" FROM "revocation_event" WHERE ("revocation_event"."audit_id" IS NULL OR "revocation_event"."audit_id" = $1) AND ("revocation_event"."domain_id" IS NULL OR "revocation_event"."domain_id" IN ($2, $3)) AND "revocation_event"."expires_at" = $4 AND "revocation_event"."issued_before" >= $5 AND ("revocation_event"."project_id" IS NULL OR "revocation_event"."project_id" = $6) AND ("revocation_event"."role_id" IS NULL OR "revocation_event"."role_id" IN ($7, $8)) AND "revocation_event"."user_id" IS NULL) AS "sub_query""#,
                [
                    "audit_id".into(),
                    "domain_id1".into(),
                    "domain_id2".into(),
                    time2.into(),
                    time1.into(),
                    "project_id".into(),
                    "rid1".into(),
                    "rid2".into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock()]])
            .into_connection();
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();
        assert_eq!(
            list(
                &db,
                &RevocationEventListParametersBuilder::default()
                    .audit_id("audit_id")
                    .domain_ids(vec!["domain_id1".into()])
                    .expires_at(time2)
                    .issued_before(time1)
                    .project_id("project_id")
                    .role_ids(vec!["rid1".into()])
                    .build()
                    .unwrap()
            )
            .await
            .unwrap(),
            vec![RevocationEvent {
                domain_id: Some("did".into()),
                project_id: Some("pid".into()),
                user_id: Some("uid".into()),
                role_id: Some("rid".into()),
                trust_id: Some("trust_id".into()),
                consumer_id: Some("consumer_id".into()),
                access_token_id: Some("access_token_id".into()),
                issued_before: DateTime::UNIX_EPOCH,
                expires_at: Some(DateTime::UNIX_EPOCH),
                revoked_at: DateTime::UNIX_EPOCH,
                audit_id: Some("audit_id".into()),
                audit_chain_id: Some("audit_chain_id".into()),
            }]
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "revocation_event"."id", "revocation_event"."domain_id", "revocation_event"."project_id", "revocation_event"."user_id", "revocation_event"."role_id", "revocation_event"."trust_id", "revocation_event"."consumer_id", "revocation_event"."access_token_id", "revocation_event"."issued_before", "revocation_event"."expires_at", "revocation_event"."revoked_at", "revocation_event"."audit_id", "revocation_event"."audit_chain_id" FROM "revocation_event" WHERE ("revocation_event"."audit_id" IS NULL OR "revocation_event"."audit_id" = $1) AND ("revocation_event"."domain_id" IS NULL OR "revocation_event"."domain_id" IN ($2)) AND "revocation_event"."expires_at" = $3 AND "revocation_event"."issued_before" >= $4 AND ("revocation_event"."project_id" IS NULL OR "revocation_event"."project_id" = $5) AND ("revocation_event"."role_id" IS NULL OR "revocation_event"."role_id" IN ($6)) AND "revocation_event"."user_id" IS NULL"#,
                [
                    "audit_id".into(),
                    "domain_id1".into(),
                    time2.into(),
                    time1.into(),
                    "project_id".into(),
                    "rid1".into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_query_mysql() {
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .audit_id("audit_id")
                .domain_ids(vec!["domain_id1".into()])
                .expires_at(time2)
                .issued_before(time1)
                .project_id("project_id")
                .role_ids(vec!["rid1".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::MySql)
        .to_string();
        assert_eq!(
            format!(
                "SELECT `revocation_event`.`id`, `revocation_event`.`domain_id`, `revocation_event`.`project_id`, `revocation_event`.`user_id`, `revocation_event`.`role_id`, `revocation_event`.`trust_id`, `revocation_event`.`consumer_id`, `revocation_event`.`access_token_id`, `revocation_event`.`issued_before`, `revocation_event`.`expires_at`, `revocation_event`.`revoked_at`, `revocation_event`.`audit_id`, `revocation_event`.`audit_chain_id` FROM `revocation_event` WHERE (`revocation_event`.`audit_id` IS NULL OR `revocation_event`.`audit_id` = 'audit_id') AND (`revocation_event`.`domain_id` IS NULL OR `revocation_event`.`domain_id` IN ('domain_id1')) AND `revocation_event`.`expires_at` = '{}' AND `revocation_event`.`issued_before` >= '{}' AND (`revocation_event`.`project_id` IS NULL OR `revocation_event`.`project_id` = 'project_id') AND (`revocation_event`.`role_id` IS NULL OR `revocation_event`.`role_id` IN ('rid1')) AND `revocation_event`.`user_id` IS NULL",
                time2.format("%F %X%.6f %:z"),
                time1.format("%F %X%.6f %:z"),
            ),
            query
        );
    }

    #[tokio::test]
    async fn test_query_postgres() {
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .audit_id("audit_id")
                .domain_ids(vec!["domain_id1".into()])
                .expires_at(time2)
                .issued_before(time1)
                .project_id("project_id")
                .role_ids(vec!["rid1".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Postgres)
        .to_string();
        assert_eq!(
            format!(
                "SELECT \"revocation_event\".\"id\", \"revocation_event\".\"domain_id\", \"revocation_event\".\"project_id\", \"revocation_event\".\"user_id\", \"revocation_event\".\"role_id\", \"revocation_event\".\"trust_id\", \"revocation_event\".\"consumer_id\", \"revocation_event\".\"access_token_id\", \"revocation_event\".\"issued_before\", \"revocation_event\".\"expires_at\", \"revocation_event\".\"revoked_at\", \"revocation_event\".\"audit_id\", \"revocation_event\".\"audit_chain_id\" FROM \"revocation_event\" WHERE (\"revocation_event\".\"audit_id\" IS NULL OR \"revocation_event\".\"audit_id\" = 'audit_id') AND (\"revocation_event\".\"domain_id\" IS NULL OR \"revocation_event\".\"domain_id\" IN ('domain_id1')) AND \"revocation_event\".\"expires_at\" = '{}' AND \"revocation_event\".\"issued_before\" >= '{}' AND (\"revocation_event\".\"project_id\" IS NULL OR \"revocation_event\".\"project_id\" = 'project_id') AND (\"revocation_event\".\"role_id\" IS NULL OR \"revocation_event\".\"role_id\" IN ('rid1')) AND \"revocation_event\".\"user_id\" IS NULL",
                time2.format("%F %X%.6f %:z"),
                time1.format("%F %X%.6f %:z"),
            ),
            query
        );
    }

    #[tokio::test]
    async fn test_query_mysql_multiple_domains() {
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .audit_id("audit_id")
                .domain_ids(vec!["domain_id1".into(), "domain_id2".into()])
                .expires_at(time2)
                .issued_before(time1)
                .project_id("project_id")
                .role_ids(vec!["rid1".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::MySql)
        .to_string();
        assert_eq!(
            format!(
                "SELECT `revocation_event`.`id`, `revocation_event`.`domain_id`, `revocation_event`.`project_id`, `revocation_event`.`user_id`, `revocation_event`.`role_id`, `revocation_event`.`trust_id`, `revocation_event`.`consumer_id`, `revocation_event`.`access_token_id`, `revocation_event`.`issued_before`, `revocation_event`.`expires_at`, `revocation_event`.`revoked_at`, `revocation_event`.`audit_id`, `revocation_event`.`audit_chain_id` FROM `revocation_event` WHERE (`revocation_event`.`audit_id` IS NULL OR `revocation_event`.`audit_id` = 'audit_id') AND (`revocation_event`.`domain_id` IS NULL OR `revocation_event`.`domain_id` IN ('domain_id1', 'domain_id2')) AND `revocation_event`.`expires_at` = '{}' AND `revocation_event`.`issued_before` >= '{}' AND (`revocation_event`.`project_id` IS NULL OR `revocation_event`.`project_id` = 'project_id') AND (`revocation_event`.`role_id` IS NULL OR `revocation_event`.`role_id` IN ('rid1')) AND `revocation_event`.`user_id` IS NULL",
                time2.format("%F %X%.6f %:z"),
                time1.format("%F %X%.6f %:z"),
            ),
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_empty() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert_eq!(
            "SELECT \"revocation_event\".\"id\", \"revocation_event\".\"domain_id\", \"revocation_event\".\"project_id\", \"revocation_event\".\"user_id\", \"revocation_event\".\"role_id\", \"revocation_event\".\"trust_id\", \"revocation_event\".\"consumer_id\", \"revocation_event\".\"access_token_id\", \"revocation_event\".\"issued_before\", \"revocation_event\".\"expires_at\", \"revocation_event\".\"revoked_at\", \"revocation_event\".\"audit_id\", \"revocation_event\".\"audit_chain_id\" FROM \"revocation_event\" WHERE \"revocation_event\".\"audit_id\" IS NULL AND \"revocation_event\".\"domain_id\" IS NULL AND \"revocation_event\".\"project_id\" IS NULL AND \"revocation_event\".\"role_id\" IS NULL AND \"revocation_event\".\"user_id\" IS NULL",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_audit_id() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .audit_id("audit_id")
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("(\"revocation_event\".\"audit_id\" IS NULL OR \"revocation_event\".\"audit_id\" = 'audit_id')"),
            "{}", query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_domain_ids_empty() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .domain_ids(Vec::new())
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND \"revocation_event\".\"domain_id\" IS NULL"),
            "{}",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_domain_ids_list() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .domain_ids(vec!["d1".into(), "d2".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND (\"revocation_event\".\"domain_id\" IS NULL OR \"revocation_event\".\"domain_id\" IN ('d1', 'd2'))"), 
            "{}", query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_project_id() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .project_id("pid")
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND (\"revocation_event\".\"project_id\" IS NULL OR \"revocation_event\".\"project_id\" = 'pid')"),
            "{}", 
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_role_ids_empty() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .role_ids(Vec::new())
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND \"revocation_event\".\"role_id\" IS NULL"),
            "{}",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_role_ids_list() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .role_ids(vec!["d1".into(), "d2".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND (\"revocation_event\".\"role_id\" IS NULL OR \"revocation_event\".\"role_id\" IN ('d1', 'd2'))"), 
            "{}", 
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_user_ids_empty() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .user_ids(Vec::new())
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND \"revocation_event\".\"user_id\" IS NULL"),
            "{}",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_user_ids_list() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .user_ids(vec!["d1".into(), "d2".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains("AND (\"revocation_event\".\"user_id\" IS NULL OR \"revocation_event\".\"user_id\" IN ('d1', 'd2'))"), 
            "{}", 
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_expires_at() {
        let time1 = Utc::now();
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .expires_at(time1)
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains(
                format!(
                    "AND \"revocation_event\".\"expires_at\" = '{}'",
                    time1.format("%F %X%.6f %:z")
                )
                .as_str()
            ),
            "{}",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_issued_before() {
        let time1 = Utc::now();
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .issued_before(time1)
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains(
                format!(
                    "AND \"revocation_event\".\"issued_before\" >= '{}'",
                    time1.format("%F %X%.6f %:z")
                )
                .as_str()
            ),
            "{}",
            query
        );
    }
}
