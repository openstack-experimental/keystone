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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::trust::TrustProviderError;
use openstack_keystone_core_types::role::RoleRef;
use openstack_keystone_core_types::trust::*;

use crate::entity::{
    prelude::{Trust as DbTrust, TrustRole as DbTrustRole},
    trust as db_trust,
};

/// Prepare the paginated query for listing trusts.
fn get_list_query(
    params: &TrustListParameters,
) -> Result<Cursor<SelectModel<db_trust::Model>>, TrustProviderError> {
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
) -> Result<Vec<Trust>, TrustProviderError> {
    let db_trusts: Vec<db_trust::Model> = get_list_query(params)?
        .all(db)
        .await
        .context("listing trusts")?;

    let roles: Vec<Vec<RoleRef>> = db_trusts
        .load_many(DbTrustRole, db)
        .await
        .context("fetching trust roles")?
        .into_iter()
        .map(|tr| tr.into_iter().map(Into::into).collect())
        .collect();

    db_trusts
        .into_iter()
        .zip(roles)
        .map(|(trust, roles)| {
            let mut res: Trust = trust.try_into()?;
            if !roles.is_empty() {
                res.roles = Some(roles);
            }
            Ok(res)
        })
        .collect::<Result<Vec<_>, TrustProviderError>>()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use crate::entity::trust_role as db_trust_role;
    use crate::trust::tests::get_trust_mock;

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
            .into_connection();
        assert_eq!(
            list(&db, &TrustListParameters::default()).await.unwrap(),
            vec![Trust {
                id: "1".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: Some("pid".into()),
                impersonation: false,
                roles: Some(vec![RoleRef {
                    id: "rid".into(),
                    name: None,
                    domain_id: None
                }]),
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
            ]
        );
    }
}
