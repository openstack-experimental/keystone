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

use crate::assignment::types::Role;
use crate::db::entity::{
    prelude::{Role as DbRole, Trust as DbTrust},
    trust as db_trust,
};
use crate::error::DbContextExt;
use crate::trust::backend::error::TrustDatabaseError;
use crate::trust::types::*;

/// Get trust credential by the ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Trust>, TrustDatabaseError> {
    if let Some(ref entry) = DbTrust::find()
        .filter(db_trust::Column::Id.eq(id.as_ref()))
        .one(db)
        .await
        .context("fetching trust by id")?
    {
        let roles = entry
            .find_related(DbRole)
            .all(db)
            .await
            .context("fetching trust roles")?
            .into_iter()
            .map(TryInto::<Role>::try_into)
            .collect::<Result<Vec<Role>, _>>()?;

        let mut res: Trust = entry.try_into()?;
        if !roles.is_empty() {
            res.roles = Some(roles);
        }
        return Ok(Some(res));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;
    use crate::assignment::backend::sql::role::tests::get_role_mock;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_trust_mock("trust_id", "trustor", "trustee")]])
            .append_query_results([vec![get_role_mock("role_id")]])
            .into_connection();

        assert_eq!(
            get(&db, "trust_id").await.unwrap().unwrap(),
            Trust {
                id: "trust_id".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: Some("pid".into()),
                impersonation: false,
                roles: Some(vec![Role {
                    id: "role_id".into(),
                    domain_id: Some("foo_domain".into()),
                    name: "foo".to_owned(),
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."id" = $1 LIMIT $2"#,
                    ["trust_id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" INNER JOIN "trust_role" ON "trust_role"."role_id" = "role"."id" INNER JOIN "trust" ON "trust"."id" = "trust_role"."trust_id" WHERE "trust"."id" = $1"#,
                    ["trust_id".into()]
                ),
            ]
        );
    }
}
