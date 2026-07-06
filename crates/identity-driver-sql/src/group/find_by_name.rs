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
//! Domain-wide, case-insensitive group name lookup (ADR 0024 §3.D).

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::sea_query::{Expr, Func};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::group as db_group;

/// Find a group in `domain_id` whose `name` matches `name` case-insensitively,
/// regardless of which realm (or nothing) created it.
///
/// # Returns
/// A `Result` containing the matched group's ID, if any, or an `Error`.
#[tracing::instrument(skip(db))]
pub async fn find_by_name_ci(
    db: &DatabaseConnection,
    domain_id: &str,
    name: &str,
) -> Result<Option<String>, IdentityProviderError> {
    let name_lower = name.to_lowercase();
    let found = db_group::Entity::find()
        .filter(db_group::Column::DomainId.eq(domain_id))
        .filter(Expr::expr(Func::lower(Expr::col(db_group::Column::Name))).eq(name_lower))
        .one(db)
        .await
        .context("checking group name collision")?;
    Ok(found.map(|g| g.id))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::group::tests::get_group_mock;

    #[tokio::test]
    async fn test_find_by_name_ci_match() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")]])
            .into_connection();

        assert_eq!(
            find_by_name_ci(&db, "foo_domain", "GROUP").await.unwrap(),
            Some("1".to_string())
        );

        // Verify the comparison is actually done case-insensitively via
        // LOWER(), against the lowercased input value.
        let log = db.into_transaction_log();
        let sql = &log[0].statements()[0].sql;
        assert!(sql.contains("LOWER"), "query must lower() the name column");
    }

    #[tokio::test]
    async fn test_find_by_name_ci_no_match() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_group::Model>::new()])
            .into_connection();

        assert_eq!(
            find_by_name_ci(&db, "foo_domain", "missing").await.unwrap(),
            None
        );
    }
}
