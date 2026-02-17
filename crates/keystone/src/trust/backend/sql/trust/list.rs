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
//! # List trusts
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use crate::db::entity::{
    prelude::{Role as DbRole, Trust as DbTrust, TrustRole as DbTrustRole},
    trust as db_trust,
};
use crate::error::DbContextExt;
use crate::role::types::Role;
use crate::trust::backend::error::TrustDatabaseError;
use crate::trust::types::*;

/// Prepare the paginated query for listing trusts.
fn get_list_query(
    params: &TrustListParameters,
) -> Result<Cursor<SelectModel<db_trust::Model>>, TrustDatabaseError> {
    let mut select = DbTrust::find();

    if !params.include_deleted.is_some_and(|x| x) {
        select = select.filter(db_trust::Column::DeletedAt.is_null());
    };

    let mut cursor = select.cursor_by(db_trust::Column::Id);
    if let Some(limit) = params.limit {
        cursor.first(limit);
    }
    if let Some(marker) = &params.marker {
        cursor.after(marker);
    }
    Ok(cursor)
}

/// List trusts.
pub async fn list(
    db: &DatabaseConnection,
    params: &TrustListParameters,
) -> Result<Vec<Trust>, TrustDatabaseError> {
    let db_trusts: Vec<db_trust::Model> = get_list_query(params)?
        .all(db)
        .await
        .context("listing trusts")?;

    let roles: Vec<Vec<Role>> = db_trusts
        .load_many_to_many(DbRole, DbTrustRole, db)
        .await
        .context("fetching trust roles")?
        .into_iter()
        .map(|tr| {
            tr.into_iter()
                .map(TryInto::<Role>::try_into)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?;

    db_trusts
        .into_iter()
        .zip(roles.into_iter())
        .map(|(trust, roles)| {
            let mut res: Trust = trust.try_into()?;
            if !roles.is_empty() {
                res.roles = Some(roles);
            }
            Ok(res)
        })
        .collect::<Result<Vec<_>, TrustDatabaseError>>()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::get_trust_mock;
    use crate::db::entity::trust_role as db_trust_role;
    use crate::role::backend::sql::role::tests::get_role_mock;

    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."deleted_at" IS NULL"#,
            QueryOrder::query(&mut get_list_query(&TrustListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_include_deleted() {
        assert!(
            !QueryOrder::query(
                &mut get_list_query(&TrustListParameters {
                    include_deleted: Some(true),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"trust\".\"deleted\" IS NULL")
        );
    }

    #[tokio::test]
    async fn test_list_no_params() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_trust_mock("1", "trustor", "trustee")]])
            .append_query_results([vec![db_trust_role::Model {
                trust_id: "1".into(),
                role_id: "rid".into(),
            }]])
            .append_query_results([vec![get_role_mock("1", "foo")]])
            .into_connection();
        assert_eq!(
            list(&db, &TrustListParameters::default()).await.unwrap(),
            vec![Trust {
                id: "1".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: Some("pid".into()),
                impersonation: false,
                ..Default::default()
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."deleted_at" IS NULL ORDER BY "trust"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust_role"."trust_id", "trust_role"."role_id" FROM "trust_role" WHERE "trust_role"."trust_id" IN ($1)"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."id" IN ($1)"#,
                    ["rid".into()]
                ),
            ]
        );
    }
}
