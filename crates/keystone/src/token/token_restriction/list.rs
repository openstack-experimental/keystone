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
//! List existing token restriction.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::db::entity::prelude::{
    TokenRestriction as DbTokenRestriction,
    TokenRestrictionRoleAssociation as DbTokenRestrictionRoleAssociation,
};
use crate::db::entity::token_restriction;
use crate::db::entity::token_restriction_role_association;
use crate::error::DbContextExt;
use crate::token::error::TokenProviderError;
use crate::token::types::{TokenRestriction, TokenRestrictionListParameters};

/// List existing token restrictions.
pub async fn list(
    db: &DatabaseConnection,
    params: &TokenRestrictionListParameters,
) -> Result<Vec<TokenRestriction>, TokenProviderError> {
    let mut select = DbTokenRestriction::find();
    if let Some(val) = &params.domain_id {
        select = select.filter(token_restriction::Column::DomainId.eq(val));
    }
    if let Some(val) = &params.user_id {
        select = select.filter(token_restriction::Column::UserId.eq(val));
    }
    if let Some(val) = &params.project_id {
        select = select.filter(token_restriction::Column::ProjectId.eq(val));
    }
    let db_restrictions: Vec<(
        token_restriction::Model,
        Vec<token_restriction_role_association::Model>,
    )> = select
        .find_with_related(DbTokenRestrictionRoleAssociation)
        .all(db)
        .await
        .context("listing token restrictions")?;

    Ok(db_restrictions.into_iter().map(Into::into).collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use crate::db::entity::token_restriction_role_association;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    fn get_restriction_with_roles_mock<T: AsRef<str>, R: AsRef<str>>(
        tid: T,
        rid: R,
    ) -> (
        token_restriction::Model,
        token_restriction_role_association::Model,
    ) {
        (
            token_restriction::Model {
                id: tid.as_ref().to_string(),
                domain_id: "did".to_string(),
                user_id: Some("uid".to_string()),
                project_id: Some("pid".to_string()),
                allow_rescope: true,
                allow_renew: true,
            },
            token_restriction_role_association::Model {
                restriction_id: tid.as_ref().to_string(),
                role_id: rid.as_ref().to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_restriction_with_roles_mock("id", "rid1"),
                get_restriction_with_roles_mock("id", "rid2"),
            ]])
            .into_connection();

        assert_eq!(
            list(
                &db,
                &TokenRestrictionListParameters {
                    domain_id: Some("did".into()),
                    user_id: Some("uid".into()),
                    project_id: Some("pid".into()),
                },
            )
            .await
            .unwrap(),
            vec![TokenRestriction {
                id: "id".into(),
                domain_id: "did".into(),
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                allow_rescope: true,
                allow_renew: true,
                role_ids: vec!["rid1".into(), "rid2".into()],
                roles: None,
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "token_restriction"."id" AS "A_id", "token_restriction"."domain_id" AS "A_domain_id", "token_restriction"."user_id" AS "A_user_id", "token_restriction"."allow_renew" AS "A_allow_renew", "token_restriction"."allow_rescope" AS "A_allow_rescope", "token_restriction"."project_id" AS "A_project_id", "token_restriction_role_association"."restriction_id" AS "B_restriction_id", "token_restriction_role_association"."role_id" AS "B_role_id" FROM "token_restriction" LEFT JOIN "token_restriction_role_association" ON "token_restriction"."id" = "token_restriction_role_association"."restriction_id" WHERE "token_restriction"."domain_id" = $1 AND "token_restriction"."user_id" = $2 AND "token_restriction"."project_id" = $3 ORDER BY "token_restriction"."id" ASC"#,
                ["did".into(), "uid".into(), "pid".into()]
            ),]
        );
    }
}
