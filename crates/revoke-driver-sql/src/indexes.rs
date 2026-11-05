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
//! Indexes of the `revocation_event` table.
//!
//! The revocation check narrows the events by the dimensions a token names
//! (audit id, user, project, domain, role, trust), see
//! `list::build_query_filters`. Each dimension needs its own index to let the
//! database combine them instead of scanning the table. The set also contains
//! the indexes of the Python Keystone schema so that a schema created by
//! `keystone-manage db sync` is complete too.
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement};
use sea_orm_migration::prelude::*;

use crate::entity::{prelude::RevocationEvent, revocation_event::Column};

/// Name of the table the indexes belong to.
const TABLE: &str = "revocation_event";

/// The indexes of the `revocation_event` table: name and the indexed columns.
pub(crate) fn definitions() -> Vec<(&'static str, Vec<Column>)> {
    vec![
        (
            "ix_revocation_event_issued_before",
            vec![Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_new_revoked_at",
            vec![Column::RevokedAt],
        ),
        (
            "ix_revocation_event_user_id_issued_before",
            vec![Column::UserId, Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_project_id_issued_before",
            vec![Column::ProjectId, Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_audit_id_issued_before",
            vec![Column::AuditId, Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_domain_id_issued_before",
            vec![Column::DomainId, Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_role_id_issued_before",
            vec![Column::RoleId, Column::IssuedBefore],
        ),
        (
            "ix_revocation_event_trust_id_issued_before",
            vec![Column::TrustId, Column::IssuedBefore],
        ),
        // Events that name none of the dimensions apply to every token. The
        // index lets the database find them without scanning the table. Only
        // the two leading columns are indexed: a MySQL index is limited to
        // 3072 bytes and the entity schema uses `VARCHAR(255)` columns, so six
        // of them do not fit. The remaining `IS NULL` checks are applied on
        // the few rows left.
        (
            "ix_revocation_event_unscoped",
            vec![Column::AuditId, Column::UserId],
        ),
    ]
}

/// Check whether the index exists on the table in the current MySQL schema.
async fn mysql_has_index(manager: &SchemaManager<'_>, name: &str) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::MySql,
            "SELECT COUNT(*) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
            [TABLE.into(), name.into()],
        ))
        .await?;
    match row {
        Some(row) => Ok(row.try_get_by_index::<i64>(0)? > 0),
        None => Ok(false),
    }
}

/// Create the indexes that do not exist yet.
///
/// The table may come from the Python Keystone schema with a part of the
/// indexes already in place. PostgreSQL and SQLite skip an existing index with
/// `IF NOT EXISTS`; MySQL has no such clause, so its indexes are looked up
/// first in `information_schema` (`SchemaManager::has_index` is not
/// implemented for MySQL).
pub(crate) async fn ensure(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let is_mysql = manager.get_database_backend() == DatabaseBackend::MySql;
    for (name, columns) in definitions() {
        if is_mysql && mysql_has_index(manager, name).await? {
            continue;
        }
        let mut index = Index::create();
        index.name(name).table(RevocationEvent);
        if !is_mysql {
            index.if_not_exists();
        }
        for column in columns {
            index.col(column);
        }
        manager.create_index(index.to_owned()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_definitions_unique_and_fit_identifier_limit() {
        let defs = definitions();
        let names: HashSet<_> = defs.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), defs.len(), "duplicate index names");
        // PostgreSQL truncates identifiers longer than 63 bytes.
        for name in names {
            assert!(name.len() <= 63, "{name} is too long");
        }
    }

    #[test]
    fn test_every_dimension_is_indexed() {
        let defs = definitions();
        for column in [
            Column::AuditId,
            Column::UserId,
            Column::ProjectId,
            Column::DomainId,
            Column::RoleId,
            Column::TrustId,
        ] {
            assert!(
                defs.iter().any(|(_, cols)| cols.first().is_some_and(
                    |first| std::mem::discriminant(first) == std::mem::discriminant(&column)
                )),
                "{column:?} is not the leading column of any index"
            );
        }
    }
}
