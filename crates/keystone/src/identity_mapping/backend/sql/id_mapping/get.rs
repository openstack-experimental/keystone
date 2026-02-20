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

use crate::db::entity::{
    id_mapping, prelude::IdMapping as DbIdMapping, sea_orm_active_enums::EntityType,
};
use crate::error::DbContextExt;
use crate::identity_mapping::{IdentityMappingProviderError, types::IdMapping};

/// Get the `IdMapping` by the public_id.
pub async fn get_by_public_id<P: AsRef<str>>(
    db: &DatabaseConnection,
    public_id: P,
) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
    Ok(DbIdMapping::find_by_id(public_id.as_ref())
        .one(db)
        .await
        .context("searching id mapping by the public id")?
        .map(Into::into))
}

/// Get the `IdMapping` by the local data.
pub async fn get_by_local_id<L: AsRef<str>, D: AsRef<str>, E: Into<EntityType>>(
    db: &DatabaseConnection,
    local_id: L,
    domain_id: D,
    entity_type: E,
) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
    Ok(DbIdMapping::find()
        .filter(id_mapping::Column::LocalId.eq(local_id.as_ref()))
        .filter(id_mapping::Column::DomainId.eq(domain_id.as_ref()))
        .filter(id_mapping::Column::EntityType.eq(entity_type.into()))
        .one(db)
        .await
        .context("searching id mapping by the local id")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_get_by_public_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_id_mapping_mock("pid", "lid")]])
            .into_connection();
        let mapping = get_by_public_id(&db, "pid")
            .await
            .unwrap()
            .expect("id mapping was not found");
        assert_eq!(mapping.public_id, "pid");

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "id_mapping"."public_id", "id_mapping"."domain_id", "id_mapping"."local_id", CAST("id_mapping"."entity_type" AS "text") FROM "id_mapping" WHERE "id_mapping"."public_id" = $1 LIMIT $2"#,
                ["pid".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_by_local_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_id_mapping_mock("pid", "lid")]])
            .into_connection();
        let mapping = get_by_local_id(&db, "lid", "did", EntityType::User)
            .await
            .unwrap()
            .expect("id mapping was not found");
        assert_eq!(mapping.public_id, "pid");

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "id_mapping"."public_id", "id_mapping"."domain_id", "id_mapping"."local_id", CAST("id_mapping"."entity_type" AS "text") FROM "id_mapping" WHERE "id_mapping"."local_id" = $1 AND "id_mapping"."domain_id" = $2 AND "id_mapping"."entity_type" = (CAST($3 AS "entity_type")) LIMIT $4"#,
                ["lid".into(), "did".into(), "user".into(), 1u64.into()]
            ),]
        );
    }
}
