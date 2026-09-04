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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::idmapping::IdMappingProviderError;

use crate::entity::id_mapping::Column;
use crate::entity::prelude::IdMapping as DbIdMapping;

/// Delete the `IdMapping` by the public identifier.
///
/// Silent/idempotent: it is not an error for no mapping to match.
///
/// # Parameters
/// - `db`: The database connection.
/// - `public_id`: The public ID of the mapping to delete.
///
/// # Returns
/// A `Result` indicating success, or an `Error`.
pub async fn delete<P: AsRef<str>>(
    db: &DatabaseConnection,
    public_id: P,
) -> Result<(), IdMappingProviderError> {
    DbIdMapping::delete_by_id(public_id.as_ref())
        .exec(db)
        .await
        .context("deleting id mapping")?;
    Ok(())
}

/// Delete every `IdMapping` row belonging to a domain.
///
/// Silent/idempotent: it is not an error for no mapping to match.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The domain identifier.
///
/// # Returns
/// A `Result` indicating success, or an `Error`.
pub async fn delete_by_domain<D: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: D,
) -> Result<(), IdMappingProviderError> {
    DbIdMapping::delete_many()
        .filter(Column::DomainId.eq(domain_id.as_ref()))
        .exec(db)
        .await
        .context("deleting id mappings for domain")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                last_insert_id: 0,
            }])
            .into_connection();

        delete(&db, "pid").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "id_mapping" WHERE "id_mapping"."public_id" = $1"#,
                ["pid".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_is_idempotent_when_nothing_matches() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            }])
            .into_connection();

        delete(&db, "missing").await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_by_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 2,
                last_insert_id: 0,
            }])
            .into_connection();

        delete_by_domain(&db, "did").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "id_mapping" WHERE "id_mapping"."domain_id" = $1"#,
                ["did".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_by_domain_is_idempotent_when_nothing_matches() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            }])
            .into_connection();

        delete_by_domain(&db, "missing").await.unwrap();
    }
}
