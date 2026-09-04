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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::idmapping::IdMappingProviderError;
use openstack_keystone_core_types::idmapping::IdMapping;

use super::get::get_by_local_id;
use crate::entity::{id_mapping, sea_orm_active_enums::EntityType};

/// Create a new `IdMapping`.
///
/// Two concurrent creators of the *same* local entity (same `domain_id`,
/// `local_id`, `entity_type`) racing with a deterministically-generated
/// `public_id` are expected to collide on the primary key — that's not a
/// real conflict, so on a unique-constraint violation the existing row for
/// this local entity is looked up and returned instead of erroring. A
/// unique-constraint violation that does *not* resolve to this local
/// entity (a genuine `public_id` collision with an unrelated mapping) is
/// propagated as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `local_id`: The local ID.
/// - `domain_id`: The domain ID.
/// - `entity_type`: The entity type.
/// - `public_id`: The public ID to store the mapping under.
///
/// # Returns
/// A `Result` containing the created (or already-existing) `IdMapping`, or
/// an `Error`.
pub async fn create<L: AsRef<str>, D: AsRef<str>, P: AsRef<str>>(
    db: &DatabaseConnection,
    local_id: L,
    domain_id: D,
    entity_type: EntityType,
    public_id: P,
) -> Result<IdMapping, IdMappingProviderError> {
    let local_id = local_id.as_ref();
    let domain_id = domain_id.as_ref();
    let public_id = public_id.as_ref();

    let entry = id_mapping::ActiveModel {
        public_id: Set(public_id.to_string()),
        domain_id: Set(domain_id.to_string()),
        local_id: Set(local_id.to_string()),
        entity_type: Set(entity_type.clone()),
    };

    match entry
        .insert(db)
        .await
        .context("creating id mapping")
        .map_err(IdMappingProviderError::from)
    {
        Ok(model) => Ok(model.into()),
        Err(err @ IdMappingProviderError::Conflict(_)) => {
            get_by_local_id(db, local_id, domain_id, entity_type)
                .await?
                .ok_or(err)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{Database, DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_id_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_id_mapping_mock("pid", "lid")]])
            .into_connection();
        let mapping = create(&db, "lid", "did", EntityType::User, "pid")
            .await
            .unwrap();
        assert_eq!(mapping.public_id, "pid");

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "id_mapping" ("public_id", "domain_id", "local_id", "entity_type") VALUES ($1, $2, $3, CAST($4 AS "entity_type")) RETURNING "public_id", "domain_id", "local_id", CAST("entity_type" AS "text")"#,
                ["pid".into(), "did".into(), "lid".into(), "user".into()]
            ),]
        );
    }

    /// Real sqlite backend so the PK conflict is a genuine unique-constraint
    /// violation the way postgres would raise it in production —
    /// `MockDatabase` cannot synthesize one `sql_err()` actually classifies
    /// (it only recognizes errors coming from a real sqlx driver error).
    async fn test_db() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::test_support::create_id_mapping_table(&db)
            .await
            .unwrap();
        db
    }

    #[tokio::test]
    async fn test_create_conflict_same_local_entity_returns_existing_mapping() {
        let db = test_db().await;

        let created = create(&db, "lid", "did", EntityType::User, "pid")
            .await
            .unwrap();

        // Same local entity racing again with the same (deterministic)
        // public_id: the PK conflict resolves to the row already there.
        let raced = create(&db, "lid", "did", EntityType::User, "pid")
            .await
            .unwrap();
        assert_eq!(raced, created);
    }

    #[tokio::test]
    async fn test_create_conflict_different_local_entity_propagates_error() {
        let db = test_db().await;

        create(&db, "lid-1", "did", EntityType::User, "pid")
            .await
            .unwrap();

        // A different local entity claiming the same public_id is a genuine
        // collision, not a benign race - it must not be silently reported as
        // success under someone else's mapping.
        let err = create(&db, "lid-2", "did", EntityType::User, "pid")
            .await
            .unwrap_err();
        assert!(matches!(err, IdMappingProviderError::Conflict(_)));
    }
}
