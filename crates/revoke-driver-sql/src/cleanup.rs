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
//! Delete the revocation events that can no longer revoke any token.
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;

use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::revoke::RevokeProviderError;

use crate::entity::{
    prelude::RevocationEvent as DbRevocationEvent, revocation_event as db_revocation_event,
};

/// Number of events deleted per statement.
///
/// The events are removed in batches to keep the locks short when a large
/// backlog has accumulated. Selecting the ids first keeps the statements
/// portable: `DELETE ... LIMIT` is not supported by every backend.
const BATCH_SIZE: u64 = 1000;

/// Delete the revocation events revoked before the given moment.
///
/// # Parameters
/// - `db`: The database connection.
/// - `revoked_before`: The events with `revoked_at` earlier than this are
///   deleted.
///
/// # Returns
/// A `Result` containing the number of the deleted events, or a
/// `RevokeProviderError`.
pub async fn delete_expired(
    db: &DatabaseConnection,
    revoked_before: DateTime<Utc>,
) -> Result<u64, RevokeProviderError> {
    let cutoff = revoked_before.naive_utc();
    let mut deleted = 0;
    loop {
        let ids: Vec<i32> = DbRevocationEvent::find()
            .select_only()
            .column(db_revocation_event::Column::Id)
            .filter(db_revocation_event::Column::RevokedAt.lt(cutoff))
            .limit(BATCH_SIZE)
            .into_tuple()
            .all(db)
            .await
            .context("selecting the expired revocation events")?;
        if ids.is_empty() {
            break;
        }
        let selected = u64::try_from(ids.len()).unwrap_or(BATCH_SIZE);
        deleted += DbRevocationEvent::delete_many()
            .filter(db_revocation_event::Column::Id.is_in(ids))
            .exec(db)
            .await
            .context("deleting the expired revocation events")?
            .rows_affected;
        if selected < BATCH_SIZE {
            break;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, MockExecResult, Transaction};

    use super::*;

    fn id_row(id: i32) -> BTreeMap<&'static str, Value> {
        BTreeMap::from([("id", Into::<Value>::into(id))])
    }

    #[tokio::test]
    async fn test_delete_expired() {
        let cutoff = Utc::now();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![id_row(1).into_mock_row(), id_row(2).into_mock_row()]])
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            }])
            .into_connection();

        assert_eq!(delete_expired(&db, cutoff).await.unwrap(), 2);

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "revocation_event"."id" FROM "revocation_event" WHERE "revocation_event"."revoked_at" < $1 LIMIT $2"#,
                    [cutoff.naive_utc().into(), BATCH_SIZE.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "revocation_event" WHERE "revocation_event"."id" IN ($1, $2)"#,
                    [1i32.into(), 2i32.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_delete_expired_nothing_to_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            .into_connection();

        assert_eq!(delete_expired(&db, Utc::now()).await.unwrap(), 0);
        // Only the select ran, no DELETE was issued.
        assert_eq!(db.into_transaction_log().len(), 1);
    }

    #[tokio::test]
    async fn test_delete_expired_loops_over_full_batches() {
        let rows = |range: std::ops::Range<i32>| -> Vec<_> {
            range.map(|id| id_row(id).into_mock_row()).collect()
        };
        let batch = i32::try_from(BATCH_SIZE).unwrap();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([rows(0..batch), rows(batch..batch + 3)])
            .append_exec_results([
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: BATCH_SIZE,
                },
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 3,
                },
            ])
            .into_connection();

        assert_eq!(
            delete_expired(&db, Utc::now()).await.unwrap(),
            BATCH_SIZE + 3
        );
        // select + delete for the full batch, select + delete for the rest.
        assert_eq!(db.into_transaction_log().len(), 4);
    }
}
