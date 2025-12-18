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
//! Update the existing token restriction.

use sea_orm::DatabaseConnection;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;
use std::collections::BTreeSet;

use crate::db::entity::prelude::{
    TokenRestriction as DbTokenRestriction,
    TokenRestrictionRoleAssociation as DbTokenRestrictionRoleAssociation,
};
use crate::db::entity::{token_restriction, token_restriction_role_association};
use crate::error::DbContextExt;
use crate::token::error::TokenProviderError;
use crate::token::types::*;

/// Update existing token restriction by the ID.
pub async fn update<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
    restriction: TokenRestrictionUpdate,
) -> Result<TokenRestriction, TokenProviderError> {
    if let Some(current) = DbTokenRestriction::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("searching for the existing token restriction")?
    {
        let mut entry: token_restriction::ActiveModel = current.into();
        if let Some(val) = restriction.allow_renew {
            entry.allow_renew = Set(val);
        }
        if let Some(val) = restriction.allow_rescope {
            entry.allow_rescope = Set(val);
        }
        if let Some(val) = &restriction.user_id {
            entry.user_id = Set(val.clone());
        }
        if let Some(val) = &restriction.project_id {
            entry.project_id = Set(val.clone());
        }

        let txn = db.begin().await.context("starting the transaction")?;
        let db_entry: token_restriction::Model = entry
            .update(db)
            .await
            .context("updating the token restriction")?;

        if let Some(role_ids) = &restriction.role_ids {
            // Read the current role associations
            let current_roles: BTreeSet<String> = BTreeSet::from_iter(
                DbTokenRestrictionRoleAssociation::find()
                    .filter(
                        token_restriction_role_association::Column::RestrictionId.eq(id.as_ref()),
                    )
                    .select_only()
                    .column(token_restriction_role_association::Column::RoleId)
                    .into_tuple()
                    .all(db)
                    .await
                    .context("reading current token restriction roles")?,
            );
            // Calculate roles to be add and removed
            let roles_to_remove: BTreeSet<String> = current_roles
                .iter()
                .filter(|&item| !role_ids.contains(item))
                .cloned()
                .collect();
            let roles_to_add: BTreeSet<String> = role_ids
                .iter()
                .filter(|&item| !current_roles.contains(item))
                .cloned()
                .collect();
            // Add missing roles
            if !roles_to_add.is_empty() {
                DbTokenRestrictionRoleAssociation::insert_many(roles_to_add.into_iter().map(|r| {
                    token_restriction_role_association::ActiveModel {
                        restriction_id: Set(id.as_ref().into()),
                        role_id: Set(r),
                    }
                }))
                .on_empty_do_nothing()
                .exec(db)
                .await
                .context("Adding new token restriction roles")?;
            }
            // Delete unnecessary roles
            if !roles_to_remove.is_empty() {
                DbTokenRestrictionRoleAssociation::delete_many()
                    .filter(
                        Condition::all()
                            .add(
                                token_restriction_role_association::Column::RestrictionId
                                    .eq(id.as_ref()),
                            )
                            .add(
                                token_restriction_role_association::Column::RoleId
                                    .is_in(roles_to_remove.into_iter()),
                            ),
                    )
                    .exec(db)
                    .await
                    .context("delete obsolete token restriction roles")?;
            }
        }

        txn.commit().await.context("committing the transaction")?;
        Ok(db_entry.into())
    } else {
        Err(TokenProviderError::TokenRestrictionNotFound(
            id.as_ref().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{
        DatabaseBackend, IntoMockRow, MockDatabase, MockExecResult, Statement, Transaction,
    };
    use std::collections::BTreeMap;

    use super::super::tests::get_restriction_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_restriction_mock("tr1")]])
            .append_query_results([vec![get_restriction_mock("tr1")]])
            .append_query_results([vec![
                BTreeMap::from([("role_id", Into::<Value>::into("rid1"))]).into_mock_row(),
                BTreeMap::from([("role_id", Into::<Value>::into("rid2"))]).into_mock_row(),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let req = TokenRestrictionUpdate {
            user_id: Some(Some("new_uid".into())),
            project_id: Some(Some("new_pid".into())),
            allow_rescope: Some(true),
            allow_renew: Some(true),
            role_ids: Some(vec!["r1".into(), "r2".into()]),
        };

        update(&db, "tr1", req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "token_restriction"."id", "token_restriction"."domain_id", "token_restriction"."user_id", "token_restriction"."allow_renew", "token_restriction"."allow_rescope", "token_restriction"."project_id" FROM "token_restriction" WHERE "token_restriction"."id" = $1 LIMIT $2"#,
                    ["tr1".into(), 1u64.into()]
                ),
                Transaction::many(vec![
                    Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                    Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        r#"UPDATE "token_restriction" SET "user_id" = $1, "allow_renew" = $2, "allow_rescope" = $3, "project_id" = $4 WHERE "token_restriction"."id" = $5 RETURNING "id", "domain_id", "user_id", "allow_renew", "allow_rescope", "project_id""#,
                        [
                            "new_uid".into(),
                            true.into(),
                            true.into(),
                            "new_pid".into(),
                            "tr1".into()
                        ]
                    ),
                    Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        r#"SELECT "token_restriction_role_association"."role_id" FROM "token_restriction_role_association" WHERE "token_restriction_role_association"."restriction_id" = $1"#,
                        ["tr1".into(),]
                    ),
                    Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        r#"INSERT INTO "token_restriction_role_association" ("restriction_id", "role_id") VALUES ($1, $2), ($3, $4) RETURNING "restriction_id", "role_id""#,
                        ["tr1".into(), "r1".into(), "tr1".into(), "r2".into(),]
                    ),
                    Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        r#"DELETE FROM "token_restriction_role_association" WHERE "token_restriction_role_association"."restriction_id" = $1 AND "token_restriction_role_association"."role_id" IN ($2, $3)"#,
                        ["tr1".into(), "rid1".into(), "rid2".into()]
                    ),
                    Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
                ])
            ]
        );
    }
}
