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
    prelude::{Role as DbRole, Trust as DbTrust, TrustRole as DbTrustRole},
    trust_role as db_trust_role,
};
use crate::error::DbContextExt;
use crate::role::types::Role;
use crate::trust::{TrustProviderError, types::Trust};

/// Get trust credential by the ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Trust>, TrustProviderError> {
    if let Some(ref entry) = DbTrust::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching trust by id")?
    {
        // TODO: roles must be fetched with the provider api
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

/// Get trust delegation chain.
///
/// # Arguments
///  - `id` - The ID of the trust.
pub async fn get_delegation_chain<I: Into<String>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<Trust>>, TrustProviderError> {
    let mut chain: Vec<Trust> = Vec::new();
    let mut trust_id = Some(id.into());
    while let Some(id) = &trust_id {
        let (trust_handle, roles_handle) = tokio::join!(
            DbTrust::find_by_id(id).one(db),
            DbTrustRole::find()
                .filter(db_trust_role::Column::TrustId.eq(id))
                .all(db)
        );

        if let Some(db_trust) = trust_handle.context("fetching trust by id")? {
            let mut trust: Trust = db_trust.try_into()?;
            let roles: Vec<Role> = roles_handle
                .context("fetching trust roles")?
                .into_iter()
                .map(|trust_role| Role {
                    id: trust_role.role_id,
                    ..Default::default()
                })
                .collect();
            if !roles.is_empty() {
                trust.roles = Some(roles);
            }
            trust_id = trust.redelegated_trust_id.clone();
            chain.push(trust);
        }
    }
    Ok(if chain.is_empty() { None } else { Some(chain) })
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;
    use crate::role::backend::sql::role::tests::get_role_mock;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_trust_mock("trust_id", "trustor", "trustee")]])
            .append_query_results([vec![get_role_mock("role_id", "foo")]])
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

    #[tokio::test]
    async fn test_get_chain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_trust_redelegation_mock("a", Some("b"))]])
            .append_query_results([vec![db_trust_role::Model {
                trust_id: "a".to_string(),
                role_id: "rid".to_string(),
            }]])
            .append_query_results([vec![get_trust_redelegation_mock("b", Some("c"))]])
            .append_query_results([vec![db_trust_role::Model {
                trust_id: "a".to_string(),
                role_id: "rid".to_string(),
            }]])
            .append_query_results([vec![get_trust_redelegation_mock("c", None::<String>)]])
            .append_query_results([vec![db_trust_role::Model {
                trust_id: "a".to_string(),
                role_id: "rid".to_string(),
            }]])
            .into_connection();

        let chain = get_delegation_chain(&db, "a").await.unwrap().unwrap();
        assert_eq!(3, chain.len());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."id" = $1 LIMIT $2"#,
                    ["a".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust_role"."trust_id", "trust_role"."role_id" FROM "trust_role" WHERE "trust_role"."trust_id" = $1"#,
                    ["a".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."id" = $1 LIMIT $2"#,
                    ["b".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust_role"."trust_id", "trust_role"."role_id" FROM "trust_role" WHERE "trust_role"."trust_id" = $1"#,
                    ["b".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust"."id", "trust"."trustor_user_id", "trust"."trustee_user_id", "trust"."project_id", "trust"."impersonation", "trust"."deleted_at", "trust"."expires_at", "trust"."remaining_uses", "trust"."extra", "trust"."expires_at_int", "trust"."redelegated_trust_id", "trust"."redelegation_count" FROM "trust" WHERE "trust"."id" = $1 LIMIT $2"#,
                    ["c".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "trust_role"."trust_id", "trust_role"."role_id" FROM "trust_role" WHERE "trust_role"."trust_id" = $1"#,
                    ["c".into()]
                ),
            ]
        );
    }
}
