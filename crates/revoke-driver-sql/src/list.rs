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
use sea_orm::sea_query::{Expr, Query, UnionType};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::revoke::RevokeProviderError;
use openstack_keystone_core_types::revoke::{RevocationEvent, RevocationEventListParameters};

use crate::entity::{
    prelude::RevocationEvent as DbRevocationEvent, revocation_event as db_revocation_event,
};

/// Build the query filters for revocation events based on the provided
/// parameters.
///
/// # Parameters
/// - `params`: The parameters used to filter revocation events.
///
/// # Returns
/// A `Result` containing the `Select` query for `DbRevocationEvent`, or a
/// `RevokeProviderError`.
fn build_query_filters(
    params: &RevocationEventListParameters,
) -> Result<Select<DbRevocationEvent>, RevokeProviderError> {
    Ok(matching_filters(params)?.filter(candidate_events(params)))
}

/// The filters selecting the events that revoke the token: every dimension
/// column of the event is either `NULL` or equal to the token value.
fn matching_filters(
    params: &RevocationEventListParameters,
) -> Result<Select<DbRevocationEvent>, RevokeProviderError> {
    tracing::debug!("Query parameters: {:?}", params);
    let mut select = DbRevocationEvent::find();

    //if let Some(val) = &params.access_token_id {
    //    select =
    // select.filter(db_revocation_event::Column::AccessTokenId.eq(val));
    //}

    //if let Some(val) = &params.audit_chain_id {
    //    select =
    // select.filter(db_revocation_event::Column::AuditChainId.eq(val));
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
                    .filter(|&val| !val.is_empty())
                    .map(|val| db_revocation_event::Column::DomainId.is_in(val)),
            ),
    );

    // Trust filter
    select = select.filter(
        Condition::any()
            .add(db_revocation_event::Column::TrustId.is_null())
            .add_option(
                params
                    .trust_id
                    .as_ref()
                    .map(|val| db_revocation_event::Column::TrustId.eq(val)),
            ),
    );

    if let Some(val) = params.expires_at {
        select = select.filter(db_revocation_event::Column::ExpiresAt.eq(val.naive_utc()));
    }

    if let Some(val) = params.issued_before {
        select = select.filter(db_revocation_event::Column::IssuedBefore.gte(val.naive_utc()));
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
                    .filter(|&val| !val.is_empty())
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
                    .filter(|&val| !val.is_empty())
                    .map(|val| db_revocation_event::Column::UserId.is_in(val)),
            ),
    );

    Ok(select)
}

/// Condition selecting the events that name at least one dimension of the
/// token.
///
/// The filters of `build_query_filters` treat a `NULL` column as "matches
/// everything", which a database can only evaluate by scanning the table. An
/// event matches only when each of its non-`NULL` dimension columns equals the
/// token value, so the event has to either equal the token in one of its
/// dimensions or have none of them set. This condition states exactly that. It
/// is implied by the other filters, hence it never changes the result; it only
/// exposes one indexable branch per dimension so the database can combine the
/// per-dimension indexes instead of scanning the whole table.
fn candidate_events(params: &RevocationEventListParameters) -> Condition {
    let non_empty = |val: &Vec<String>| !val.is_empty();
    Condition::any()
        .add_option(
            params
                .audit_id
                .as_ref()
                .map(|val| db_revocation_event::Column::AuditId.eq(val)),
        )
        .add_option(
            params
                .user_ids
                .as_ref()
                .filter(|val| non_empty(val))
                .map(|val| db_revocation_event::Column::UserId.is_in(val)),
        )
        .add_option(
            params
                .project_id
                .as_ref()
                .map(|val| db_revocation_event::Column::ProjectId.eq(val)),
        )
        .add_option(
            params
                .domain_ids
                .as_ref()
                .filter(|val| non_empty(val))
                .map(|val| db_revocation_event::Column::DomainId.is_in(val)),
        )
        .add_option(
            params
                .role_ids
                .as_ref()
                .filter(|val| non_empty(val))
                .map(|val| db_revocation_event::Column::RoleId.is_in(val)),
        )
        .add_option(
            params
                .trust_id
                .as_ref()
                .map(|val| db_revocation_event::Column::TrustId.eq(val)),
        )
        .add(
            Condition::all()
                .add(db_revocation_event::Column::AuditId.is_null())
                .add(db_revocation_event::Column::UserId.is_null())
                .add(db_revocation_event::Column::ProjectId.is_null())
                .add(db_revocation_event::Column::DomainId.is_null())
                .add(db_revocation_event::Column::RoleId.is_null())
                .add(db_revocation_event::Column::TrustId.is_null()),
        )
}

/// The selects that together find the events revoking the token: one per
/// dimension the token names, each restricted by an equality on that
/// dimension, plus one for the events that name no dimension at all.
///
/// Every branch carries the full per-dimension filters, so the union returns
/// exactly the events of `matching_filters`. The equality lets the database
/// start from the matching index entries of that dimension; the plain
/// `IS NULL OR column = value` filters alone make it read every event that
/// leaves the dimension empty, which grows with the number of recent events.
fn branch_selects(
    params: &RevocationEventListParameters,
) -> Result<Vec<Select<DbRevocationEvent>>, RevokeProviderError> {
    let mut branches = Vec::new();
    let non_empty = |val: &&Vec<String>| !val.is_empty();
    if let Some(val) = &params.audit_id {
        branches
            .push(matching_filters(params)?.filter(db_revocation_event::Column::AuditId.eq(val)));
    }
    if let Some(val) = params.user_ids.as_ref().filter(non_empty) {
        branches
            .push(matching_filters(params)?.filter(db_revocation_event::Column::UserId.is_in(val)));
    }
    if let Some(val) = &params.project_id {
        branches
            .push(matching_filters(params)?.filter(db_revocation_event::Column::ProjectId.eq(val)));
    }
    if let Some(val) = params.domain_ids.as_ref().filter(non_empty) {
        branches.push(
            matching_filters(params)?.filter(db_revocation_event::Column::DomainId.is_in(val)),
        );
    }
    if let Some(val) = params.role_ids.as_ref().filter(non_empty) {
        // Events naming the user, project or audit id in addition to the
        // role (grant revocations) are found by the branches of those
        // dimensions. Excluding them keeps the database from reading every
        // such event of the role only to discard it in the filter, and lets
        // it use the `unscoped` index instead of the role one.
        branches.push(
            matching_filters(params)?.filter(
                Condition::all()
                    .add(db_revocation_event::Column::RoleId.is_in(val))
                    .add(db_revocation_event::Column::AuditId.is_null())
                    .add(db_revocation_event::Column::UserId.is_null())
                    .add(db_revocation_event::Column::ProjectId.is_null()),
            ),
        );
    }
    if let Some(val) = &params.trust_id {
        branches
            .push(matching_filters(params)?.filter(db_revocation_event::Column::TrustId.eq(val)));
    }
    branches.push(
        matching_filters(params)?.filter(
            Condition::all()
                .add(db_revocation_event::Column::AuditId.is_null())
                .add(db_revocation_event::Column::UserId.is_null())
                .add(db_revocation_event::Column::ProjectId.is_null())
                .add(db_revocation_event::Column::DomainId.is_null())
                .add(db_revocation_event::Column::RoleId.is_null())
                .add(db_revocation_event::Column::TrustId.is_null()),
        ),
    );
    Ok(branches)
}

/// Build `SELECT EXISTS (<branch> UNION ALL <branch> ...)`.
///
/// The check needs to know whether any event revokes the token, not how
/// many, so the database may stop at the first row of the first branch that
/// has one.
fn build_exists(
    params: &RevocationEventListParameters,
) -> Result<sea_orm::sea_query::SelectStatement, RevokeProviderError> {
    let mut union: Option<sea_orm::sea_query::SelectStatement> = None;
    for branch in branch_selects(params)? {
        let select = branch
            .select_only()
            .column(db_revocation_event::Column::Id)
            .into_query();
        match union.as_mut() {
            Some(union) => {
                union.union(UnionType::All, select);
            }
            None => union = Some(select),
        }
    }
    let mut outer = Query::select();
    if let Some(union) = union {
        outer.expr(Expr::exists(union));
    }
    Ok(outer)
}

/// Check whether any not expired revocation event invalidates the token.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters used to filter revocation events.
///
/// # Returns
/// A `Result` containing `true` when at least one event matches, or a
/// `RevokeProviderError`.
pub async fn exists(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<bool, RevokeProviderError> {
    let statement = db.get_database_backend().build(&build_exists(params)?);
    let row = db
        .query_one_raw(statement)
        .await
        .context("checking the token for revocation events")?;
    Ok(match row {
        // MySQL returns EXISTS as an integer, Postgres and SQLite as a
        // boolean or an integer, so read it as an integer when needed.
        Some(row) => match row.try_get_by_index::<bool>(0) {
            Ok(exists) => exists,
            Err(_) => {
                row.try_get_by_index::<i64>(0)
                    .context("reading the revocation check result")?
                    != 0
            }
        },
        None => false,
    })
}

/// Count token revocation events.
///
/// Return not expired revocation records that invalidate the token.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters used to filter revocation events.
///
/// # Returns
/// A `Result` containing the count of revocation events, or a
/// `RevokeProviderError`.
#[allow(unused)]
pub async fn count(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<u64, RevokeProviderError> {
    Ok(build_query_filters(params)?
        .count(db)
        .await
        .context("counting revocation events for the token")?)
}

/// Count the events matching the token with the plain per-dimension filters,
/// without the candidate narrowing. Used by the tests as the reference
/// result the narrowed query must reproduce.
#[cfg(test)]
pub(crate) async fn matching_count(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<u64, RevokeProviderError> {
    Ok(matching_filters(params)?
        .count(db)
        .await
        .context("counting revocation events for the token")?)
}

/// List token revocation events.
///
/// Return not expired revocation records that invalidate the token.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters used to filter revocation events.
///
/// # Returns
/// A `Result` containing a vector of `RevocationEvent` objects, or a
/// `RevokeProviderError`.
#[allow(unused)]
pub async fn list(
    db: &DatabaseConnection,
    params: &RevocationEventListParameters,
) -> Result<Vec<RevocationEvent>, RevokeProviderError> {
    let db_entities: Vec<db_revocation_event::Model> =
        build_query_filters(params)?
            .all(db)
            .await
            .context("listing revocation events for the token")?;

    let results: Vec<RevocationEvent> = db_entities
        .into_iter()
        //.map(TryInto::<RevocationEvent>::try_into)
        .map(Into::into)
        .collect();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Days, Utc};
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};
    use std::collections::BTreeMap;

    use openstack_keystone_core_types::revoke::RevocationEventListParametersBuilder;

    use super::super::tests::get_mock;
    use super::*;

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
                r#"SELECT COUNT(*) AS num_items FROM (SELECT "revocation_event"."id", "revocation_event"."domain_id", "revocation_event"."project_id", "revocation_event"."user_id", "revocation_event"."role_id", "revocation_event"."trust_id", "revocation_event"."consumer_id", "revocation_event"."access_token_id", "revocation_event"."issued_before", "revocation_event"."expires_at", "revocation_event"."revoked_at", "revocation_event"."audit_id", "revocation_event"."audit_chain_id" FROM "revocation_event" WHERE ("revocation_event"."audit_id" IS NULL OR "revocation_event"."audit_id" = $1) AND ("revocation_event"."domain_id" IS NULL OR "revocation_event"."domain_id" IN ($2, $3)) AND "revocation_event"."trust_id" IS NULL AND "revocation_event"."expires_at" = $4 AND "revocation_event"."issued_before" >= $5 AND ("revocation_event"."project_id" IS NULL OR "revocation_event"."project_id" = $6) AND ("revocation_event"."role_id" IS NULL OR "revocation_event"."role_id" IN ($7, $8)) AND "revocation_event"."user_id" IS NULL AND ("revocation_event"."audit_id" = $9 OR "revocation_event"."project_id" = $10 OR "revocation_event"."domain_id" IN ($11, $12) OR "revocation_event"."role_id" IN ($13, $14) OR ("revocation_event"."audit_id" IS NULL AND "revocation_event"."user_id" IS NULL AND "revocation_event"."project_id" IS NULL AND "revocation_event"."domain_id" IS NULL AND "revocation_event"."role_id" IS NULL AND "revocation_event"."trust_id" IS NULL))) AS "sub_query""#,
                [
                    "audit_id".into(),
                    "domain_id1".into(),
                    "domain_id2".into(),
                    time2.naive_utc().into(),
                    time1.naive_utc().into(),
                    "project_id".into(),
                    "rid1".into(),
                    "rid2".into(),
                    "audit_id".into(),
                    "project_id".into(),
                    "domain_id1".into(),
                    "domain_id2".into(),
                    "rid1".into(),
                    "rid2".into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_exists_query_has_one_branch_per_dimension() {
        let query = build_exists(
            &RevocationEventListParametersBuilder::default()
                .audit_id("audit_id")
                .project_id("project_id")
                .user_ids(vec!["user_id".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .to_string(sea_orm::sea_query::PostgresQueryBuilder);
        assert!(query.starts_with("SELECT EXISTS("), "{query}");
        // audit id, user, project and the events without dimensions.
        assert_eq!(query.matches("UNION ALL").count(), 3, "{query}");
        assert!(query.contains("\"audit_id\" = 'audit_id'"), "{query}");
        assert!(query.contains("\"user_id\" IN ('user_id')"), "{query}");
        assert!(query.contains("\"project_id\" = 'project_id'"), "{query}");
    }

    #[tokio::test]
    async fn test_exists_role_branch_excludes_events_of_other_dimensions() {
        let query = build_exists(
            &RevocationEventListParametersBuilder::default()
                .role_ids(vec!["rid1".into()])
                .build()
                .unwrap(),
        )
        .unwrap()
        .to_string(sea_orm::sea_query::PostgresQueryBuilder);
        let role_branch = "\"revocation_event\".\"role_id\" IN ('rid1') AND \
             \"revocation_event\".\"audit_id\" IS NULL AND \
             \"revocation_event\".\"user_id\" IS NULL AND \
             \"revocation_event\".\"project_id\" IS NULL UNION ALL";
        assert!(query.contains(role_branch), "{query}");
        // role branch and the events without dimensions.
        assert_eq!(query.matches("UNION ALL").count(), 1, "{query}");
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
                r#"SELECT "revocation_event"."id", "revocation_event"."domain_id", "revocation_event"."project_id", "revocation_event"."user_id", "revocation_event"."role_id", "revocation_event"."trust_id", "revocation_event"."consumer_id", "revocation_event"."access_token_id", "revocation_event"."issued_before", "revocation_event"."expires_at", "revocation_event"."revoked_at", "revocation_event"."audit_id", "revocation_event"."audit_chain_id" FROM "revocation_event" WHERE ("revocation_event"."audit_id" IS NULL OR "revocation_event"."audit_id" = $1) AND ("revocation_event"."domain_id" IS NULL OR "revocation_event"."domain_id" IN ($2)) AND "revocation_event"."trust_id" IS NULL AND "revocation_event"."expires_at" = $3 AND "revocation_event"."issued_before" >= $4 AND ("revocation_event"."project_id" IS NULL OR "revocation_event"."project_id" = $5) AND ("revocation_event"."role_id" IS NULL OR "revocation_event"."role_id" IN ($6)) AND "revocation_event"."user_id" IS NULL AND ("revocation_event"."audit_id" = $7 OR "revocation_event"."project_id" = $8 OR "revocation_event"."domain_id" IN ($9) OR "revocation_event"."role_id" IN ($10) OR ("revocation_event"."audit_id" IS NULL AND "revocation_event"."user_id" IS NULL AND "revocation_event"."project_id" IS NULL AND "revocation_event"."domain_id" IS NULL AND "revocation_event"."role_id" IS NULL AND "revocation_event"."trust_id" IS NULL))"#,
                [
                    "audit_id".into(),
                    "domain_id1".into(),
                    time2.naive_utc().into(),
                    time1.naive_utc().into(),
                    "project_id".into(),
                    "rid1".into(),
                    "audit_id".into(),
                    "project_id".into(),
                    "domain_id1".into(),
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
                "SELECT `revocation_event`.`id`, `revocation_event`.`domain_id`, `revocation_event`.`project_id`, `revocation_event`.`user_id`, `revocation_event`.`role_id`, `revocation_event`.`trust_id`, `revocation_event`.`consumer_id`, `revocation_event`.`access_token_id`, `revocation_event`.`issued_before`, `revocation_event`.`expires_at`, `revocation_event`.`revoked_at`, `revocation_event`.`audit_id`, `revocation_event`.`audit_chain_id` FROM `revocation_event` WHERE (`revocation_event`.`audit_id` IS NULL OR `revocation_event`.`audit_id` = 'audit_id') AND (`revocation_event`.`domain_id` IS NULL OR `revocation_event`.`domain_id` IN ('domain_id1')) AND `revocation_event`.`trust_id` IS NULL AND `revocation_event`.`expires_at` = '{}' AND `revocation_event`.`issued_before` >= '{}' AND (`revocation_event`.`project_id` IS NULL OR `revocation_event`.`project_id` = 'project_id') AND (`revocation_event`.`role_id` IS NULL OR `revocation_event`.`role_id` IN ('rid1')) AND `revocation_event`.`user_id` IS NULL AND (`revocation_event`.`audit_id` = 'audit_id' OR `revocation_event`.`project_id` = 'project_id' OR `revocation_event`.`domain_id` IN ('domain_id1') OR `revocation_event`.`role_id` IN ('rid1') OR (`revocation_event`.`audit_id` IS NULL AND `revocation_event`.`user_id` IS NULL AND `revocation_event`.`project_id` IS NULL AND `revocation_event`.`domain_id` IS NULL AND `revocation_event`.`role_id` IS NULL AND `revocation_event`.`trust_id` IS NULL))",
                time2.format("%F %X%.6f"),
                time1.format("%F %X%.6f"),
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
                "SELECT \"revocation_event\".\"id\", \"revocation_event\".\"domain_id\", \"revocation_event\".\"project_id\", \"revocation_event\".\"user_id\", \"revocation_event\".\"role_id\", \"revocation_event\".\"trust_id\", \"revocation_event\".\"consumer_id\", \"revocation_event\".\"access_token_id\", \"revocation_event\".\"issued_before\", \"revocation_event\".\"expires_at\", \"revocation_event\".\"revoked_at\", \"revocation_event\".\"audit_id\", \"revocation_event\".\"audit_chain_id\" FROM \"revocation_event\" WHERE (\"revocation_event\".\"audit_id\" IS NULL OR \"revocation_event\".\"audit_id\" = 'audit_id') AND (\"revocation_event\".\"domain_id\" IS NULL OR \"revocation_event\".\"domain_id\" IN ('domain_id1')) AND \"revocation_event\".\"trust_id\" IS NULL AND \"revocation_event\".\"expires_at\" = '{}' AND \"revocation_event\".\"issued_before\" >= '{}' AND (\"revocation_event\".\"project_id\" IS NULL OR \"revocation_event\".\"project_id\" = 'project_id') AND (\"revocation_event\".\"role_id\" IS NULL OR \"revocation_event\".\"role_id\" IN ('rid1')) AND \"revocation_event\".\"user_id\" IS NULL AND (\"revocation_event\".\"audit_id\" = 'audit_id' OR \"revocation_event\".\"project_id\" = 'project_id' OR \"revocation_event\".\"domain_id\" IN ('domain_id1') OR \"revocation_event\".\"role_id\" IN ('rid1') OR (\"revocation_event\".\"audit_id\" IS NULL AND \"revocation_event\".\"user_id\" IS NULL AND \"revocation_event\".\"project_id\" IS NULL AND \"revocation_event\".\"domain_id\" IS NULL AND \"revocation_event\".\"role_id\" IS NULL AND \"revocation_event\".\"trust_id\" IS NULL))",
                time2.format("%F %X%.6f"),
                time1.format("%F %X%.6f"),
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
                "SELECT `revocation_event`.`id`, `revocation_event`.`domain_id`, `revocation_event`.`project_id`, `revocation_event`.`user_id`, `revocation_event`.`role_id`, `revocation_event`.`trust_id`, `revocation_event`.`consumer_id`, `revocation_event`.`access_token_id`, `revocation_event`.`issued_before`, `revocation_event`.`expires_at`, `revocation_event`.`revoked_at`, `revocation_event`.`audit_id`, `revocation_event`.`audit_chain_id` FROM `revocation_event` WHERE (`revocation_event`.`audit_id` IS NULL OR `revocation_event`.`audit_id` = 'audit_id') AND (`revocation_event`.`domain_id` IS NULL OR `revocation_event`.`domain_id` IN ('domain_id1', 'domain_id2')) AND `revocation_event`.`trust_id` IS NULL AND `revocation_event`.`expires_at` = '{}' AND `revocation_event`.`issued_before` >= '{}' AND (`revocation_event`.`project_id` IS NULL OR `revocation_event`.`project_id` = 'project_id') AND (`revocation_event`.`role_id` IS NULL OR `revocation_event`.`role_id` IN ('rid1')) AND `revocation_event`.`user_id` IS NULL AND (`revocation_event`.`audit_id` = 'audit_id' OR `revocation_event`.`project_id` = 'project_id' OR `revocation_event`.`domain_id` IN ('domain_id1', 'domain_id2') OR `revocation_event`.`role_id` IN ('rid1') OR (`revocation_event`.`audit_id` IS NULL AND `revocation_event`.`user_id` IS NULL AND `revocation_event`.`project_id` IS NULL AND `revocation_event`.`domain_id` IS NULL AND `revocation_event`.`role_id` IS NULL AND `revocation_event`.`trust_id` IS NULL))",
                time2.format("%F %X%.6f"),
                time1.format("%F %X%.6f"),
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
            "SELECT \"revocation_event\".\"id\", \"revocation_event\".\"domain_id\", \"revocation_event\".\"project_id\", \"revocation_event\".\"user_id\", \"revocation_event\".\"role_id\", \"revocation_event\".\"trust_id\", \"revocation_event\".\"consumer_id\", \"revocation_event\".\"access_token_id\", \"revocation_event\".\"issued_before\", \"revocation_event\".\"expires_at\", \"revocation_event\".\"revoked_at\", \"revocation_event\".\"audit_id\", \"revocation_event\".\"audit_chain_id\" FROM \"revocation_event\" WHERE \"revocation_event\".\"audit_id\" IS NULL AND \"revocation_event\".\"domain_id\" IS NULL AND \"revocation_event\".\"trust_id\" IS NULL AND \"revocation_event\".\"project_id\" IS NULL AND \"revocation_event\".\"role_id\" IS NULL AND \"revocation_event\".\"user_id\" IS NULL AND (\"revocation_event\".\"audit_id\" IS NULL AND \"revocation_event\".\"user_id\" IS NULL AND \"revocation_event\".\"project_id\" IS NULL AND \"revocation_event\".\"domain_id\" IS NULL AND \"revocation_event\".\"role_id\" IS NULL AND \"revocation_event\".\"trust_id\" IS NULL)",
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
                    time1.format("%F %X%.6f")
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
                    time1.format("%F %X%.6f")
                )
                .as_str()
            ),
            "{}",
            query
        );
    }

    #[tokio::test]
    async fn test_query_sqlite_trust_id() {
        let query = build_query_filters(
            &RevocationEventListParametersBuilder::default()
                .trust_id("trust_id")
                .build()
                .unwrap(),
        )
        .unwrap()
        .build(DatabaseBackend::Sqlite)
        .to_string();
        assert!(
            query.contains(r#"AND ("revocation_event"."trust_id" IS NULL OR "revocation_event"."trust_id" = 'trust_id'"#),
            "{}",
            query
        );
    }
}
