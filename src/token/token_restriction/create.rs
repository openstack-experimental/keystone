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
//! Create token restriction "policy".

use sea_orm::DatabaseConnection;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;

use crate::db::entity::prelude::TokenRestrictionRoleAssociation as DbTokenRestrictionRoleAssociation;
use crate::db::entity::{token_restriction, token_restriction_role_association};
use crate::error::DbContextExt;
use crate::token::error::TokenProviderError;
use crate::token::types::*;

/// Create new token restriction.
pub async fn create(
    db: &DatabaseConnection,
    restriction: TokenRestrictionCreate,
) -> Result<TokenRestriction, TokenProviderError> {
    let entry = token_restriction::ActiveModel {
        id: Set(restriction.id.clone()),
        domain_id: Set(restriction.domain_id.clone()),
        allow_renew: Set(restriction.allow_renew),
        allow_rescope: Set(restriction.allow_rescope),
        project_id: restriction
            .project_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        user_id: restriction
            .user_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
    };

    let txn = db.begin().await.context("starting the transaction")?;
    let db_entry: token_restriction::Model = entry
        .insert(db)
        .await
        .context("creating token restriction")?;

    if !restriction.role_ids.is_empty() {
        DbTokenRestrictionRoleAssociation::insert_many(
            restriction.role_ids.clone().into_iter().map(|rid| {
                token_restriction_role_association::ActiveModel {
                    restriction_id: Set(restriction.id.clone()),
                    role_id: Set(rid.clone()),
                }
            }),
        )
        .exec(db)
        .await
        .context("persisting token restriction role association")?;
    }
    txn.commit().await.context("committing the transaction")?;

    Ok(db_entry.into())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::super::tests::get_restriction_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_restriction_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let req = TokenRestrictionCreate {
            id: "1".into(),
            domain_id: "did".into(),
            user_id: Some("uid".into()),
            project_id: Some("pid".into()),
            allow_rescope: true,
            allow_renew: true,
            role_ids: vec!["r1".into(), "r2".into()],
        };

        create(&db, req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "token_restriction" ("id", "domain_id", "user_id", "allow_renew", "allow_rescope", "project_id") VALUES ($1, $2, $3, $4, $5, $6) RETURNING "id", "domain_id", "user_id", "allow_renew", "allow_rescope", "project_id""#,
                    [
                        "1".into(),
                        "did".into(),
                        "uid".into(),
                        true.into(),
                        true.into(),
                        "pid".into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "token_restriction_role_association" ("restriction_id", "role_id") VALUES ($1, $2), ($3, $4) RETURNING "restriction_id", "role_id""#,
                    ["1".into(), "r1".into(), "1".into(), "r2".into(),]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ]),]
        );
    }
}
