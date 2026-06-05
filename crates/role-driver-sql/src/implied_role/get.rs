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

use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleImply;

use super::ImpliedRoleFilter;

/// Get a role imply rule by prior and implied role IDs.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
/// - `implied_role_id`: The ID of the implied role.
///
/// # Returns
/// A `Result` containing an `Option` with the `RoleImply` if found, or an
/// `Error`.
pub async fn get(
    db: &DatabaseConnection,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<Option<RoleImply>, RoleProviderError> {
    Ok(super::list_expanded(
        db,
        Some(ImpliedRoleFilter::Exact(prior_role_id, implied_role_id)),
    )
    .await?
    .first()
    .cloned())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, MockRow, Transaction};

    use openstack_keystone_core_types::role::RoleRef;

    use super::*;
    use crate::implied_role::NULL_DOMAIN_ID;

    fn mock_row(prior_id: &str, prior_name: &str, implied_id: &str, implied_name: &str) -> MockRow {
        BTreeMap::from([
            ("prior_role_id", prior_id.into()),
            ("prior_role_name", prior_name.into()),
            ("prior_role_domain_id", NULL_DOMAIN_ID.into()),
            ("implied_role_id", implied_id.into()),
            ("implied_role_name", implied_name.into()),
            ("implied_role_domain_id", NULL_DOMAIN_ID.into()),
        ])
        .into_mock_row()
    }

    #[tokio::test]
    async fn test_get_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_row("admin", "admin", "member", "member")]])
            .into_connection();

        let result = get(&db, "admin", "member").await.unwrap().unwrap();

        assert_eq!(
            result.prior_role,
            RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: None,
            }
        );
        assert_eq!(
            result.implied_role,
            RoleRef {
                id: "member".into(),
                name: Some("member".into()),
                domain_id: None,
            }
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "prior_role"."id" AS "prior_role_id", "prior_role"."name" AS "prior_role_name", "prior_role"."domain_id" AS "prior_role_domain_id", "child_role"."id" AS "implied_role_id", "child_role"."name" AS "implied_role_name", "child_role"."domain_id" AS "implied_role_domain_id" FROM "implied_role" INNER JOIN "role" AS "prior_role" ON "implied_role"."prior_role_id" = "prior_role"."id" INNER JOIN "role" AS "child_role" ON "implied_role"."implied_role_id" = "child_role"."id" WHERE "implied_role"."prior_role_id" = $1 AND "implied_role"."implied_role_id" = $2"#,
                ["admin".into(), "member".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let result = get(&db, "admin", "member").await.unwrap();

        assert!(result.is_none());
    }
}
