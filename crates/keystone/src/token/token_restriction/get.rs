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
//! Get existing token restriction.
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::db::entity::prelude::{
    Role as DbRole, TokenRestriction as DbTokenRestriction,
    TokenRestrictionRoleAssociation as DbTokenRestrictionRoleAssociation,
};
use crate::db::entity::token_restriction_role_association;
use crate::error::DbContextExt;
use crate::token::error::TokenProviderError;
use crate::token::types::TokenRestriction;

/// Get existing token restriction by the ID.
pub async fn get<S: AsRef<str>>(
    db: &DatabaseConnection,
    token_restriction_id: S,
    expand_roles: bool,
) -> Result<Option<TokenRestriction>, TokenProviderError> {
    let restriction: Option<TokenRestriction> = if let Some(entry) =
        DbTokenRestriction::find_by_id(token_restriction_id.as_ref())
            .one(db)
            .await
            .context("reading token restriction record")?
    {
        if expand_roles {
            let roles = DbTokenRestrictionRoleAssociation::find()
                .filter(
                    token_restriction_role_association::Column::RestrictionId
                        .eq(token_restriction_id.as_ref()),
                )
                .find_also_related(DbRole)
                .all(db)
                .await
                .context("reading token restriction roles")?;
            Some((entry, roles).into())
        } else {
            let roles = DbTokenRestrictionRoleAssociation::find()
                .filter(
                    token_restriction_role_association::Column::RestrictionId
                        .eq(token_restriction_id.as_ref()),
                )
                .all(db)
                .await
                .context("reading token restriction roles")?;
            Some((entry, roles).into())
        }
    } else {
        None
    };
    Ok(restriction)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use crate::db::entity::{role, token_restriction_role_association};
    use crate::role::types::Role;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_restriction_mock;
    use super::*;

    fn get_restriction_roles_mock<S: AsRef<str>>(
        id: S,
    ) -> Vec<token_restriction_role_association::Model> {
        vec![
            token_restriction_role_association::Model {
                restriction_id: id.as_ref().to_string(),
                role_id: "rid1".to_string(),
            },
            token_restriction_role_association::Model {
                restriction_id: id.as_ref().to_string(),
                role_id: "rid2".to_string(),
            },
        ]
    }

    fn get_restriction_roles_mock_expand<S: AsRef<str>>(
        id: S,
    ) -> Vec<(token_restriction_role_association::Model, role::Model)> {
        vec![
            (
                token_restriction_role_association::Model {
                    restriction_id: id.as_ref().to_string(),
                    role_id: "rid1".to_string(),
                },
                role::Model {
                    id: "rid1".to_string(),
                    name: "rid1_name".into(),
                    ..Default::default()
                },
            ),
            (
                token_restriction_role_association::Model {
                    restriction_id: id.as_ref().to_string(),
                    role_id: "rid2".to_string(),
                },
                role::Model {
                    id: "rid2".to_string(),
                    name: "rid2_name".into(),
                    ..Default::default()
                },
            ),
        ]
    }

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_restriction_mock("id")]])
            .append_query_results([get_restriction_roles_mock("id")])
            .into_connection();

        assert_eq!(
            get(&db, "id", false).await.unwrap(),
            Some(TokenRestriction {
                id: "id".into(),
                domain_id: "did".into(),
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                allow_rescope: true,
                allow_renew: true,
                role_ids: vec!["rid1".into(), "rid2".into()],
                roles: None,
            })
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "token_restriction"."id", "token_restriction"."domain_id", "token_restriction"."user_id", "token_restriction"."allow_renew", "token_restriction"."allow_rescope", "token_restriction"."project_id" FROM "token_restriction" WHERE "token_restriction"."id" = $1 LIMIT $2"#,
                    ["id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "token_restriction_role_association"."restriction_id", "token_restriction_role_association"."role_id" FROM "token_restriction_role_association" WHERE "token_restriction_role_association"."restriction_id" = $1"#,
                    ["id".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_get_expand() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_restriction_mock("id")]])
            .append_query_results([get_restriction_roles_mock_expand("id")])
            .into_connection();

        assert_eq!(
            get(&db, "id", true).await.unwrap(),
            Some(TokenRestriction {
                id: "id".into(),
                domain_id: "did".into(),
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                allow_rescope: true,
                allow_renew: true,
                role_ids: vec!["rid1".into(), "rid2".into()],
                roles: Some(vec![
                    Role {
                        id: "rid1".into(),
                        name: "rid1_name".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "rid2".into(),
                        name: "rid2_name".into(),
                        ..Default::default()
                    },
                ]),
            })
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "token_restriction"."id", "token_restriction"."domain_id", "token_restriction"."user_id", "token_restriction"."allow_renew", "token_restriction"."allow_rescope", "token_restriction"."project_id" FROM "token_restriction" WHERE "token_restriction"."id" = $1 LIMIT $2"#,
                    ["id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "token_restriction_role_association"."restriction_id" AS "A_restriction_id", "token_restriction_role_association"."role_id" AS "A_role_id", "role"."id" AS "B_id", "role"."name" AS "B_name", "role"."extra" AS "B_extra", "role"."domain_id" AS "B_domain_id", "role"."description" AS "B_description" FROM "token_restriction_role_association" LEFT JOIN "role" ON "token_restriction_role_association"."role_id" = "role"."id" WHERE "token_restriction_role_association"."restriction_id" = $1"#,
                    ["id".into()]
                ),
            ]
        );
    }
}
