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
//! Domain-wide, case-insensitive `userName` collision check (ADR 0024
//! §3.D), used by SCIM `POST /Users` to reject a create whenever *any*
//! existing `User` in the domain already has this name — regardless of
//! whether that user was created by this SCIM realm, another realm, or
//! manually via `/v3/users`.
//!
//! Scoped to `local_user` and `nonlocal_user` (both carry `domain_id`
//! directly). Federated users are deliberately not checked here: they are
//! provisioned through IdP federation (`idp_id` + `unique_id`), not
//! `userName` assignment, so they are not a realistic source of the
//! collision this check guards against, and checking them would require an
//! extra join against `user` for `domain_id`. This is a live pre-flight
//! query, not a transactional guarantee — see ADR 0024 §3.D for the
//! documented TOCTOU trade-off.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::sea_query::{Expr, Func};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::{local_user as db_local_user, nonlocal_user as db_nonlocal_user};

/// Find the `user_id` of any local or nonlocal user in `domain_id` whose
/// name matches `name`, case-insensitively.
#[tracing::instrument(skip(db))]
pub async fn find_by_name_ci(
    db: &DatabaseConnection,
    domain_id: &str,
    name: &str,
) -> Result<Option<String>, IdentityProviderError> {
    let name_lower = name.to_lowercase();

    if let Some(local) = db_local_user::Entity::find()
        .filter(db_local_user::Column::DomainId.eq(domain_id))
        .filter(
            Expr::expr(Func::lower(Expr::col(db_local_user::Column::Name))).eq(name_lower.clone()),
        )
        .one(db)
        .await
        .context("checking local_user name collision")?
    {
        return Ok(Some(local.user_id));
    }

    if let Some(nonlocal) = db_nonlocal_user::Entity::find()
        .filter(db_nonlocal_user::Column::DomainId.eq(domain_id))
        .filter(Expr::expr(Func::lower(Expr::col(db_nonlocal_user::Column::Name))).eq(name_lower))
        .one(db)
        .await
        .context("checking nonlocal_user name collision")?
    {
        return Ok(Some(nonlocal.user_id));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::local_user::tests::get_local_user_mock;

    #[tokio::test]
    async fn test_find_by_name_ci_matches_local_user() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_mock("1")]])
            .into_connection();

        let found = find_by_name_ci(&db, "foo_domain", "APPLE CAKE")
            .await
            .unwrap();
        assert_eq!(found, Some("1".to_string()));

        // Verify the comparison is actually done case-insensitively via
        // LOWER(), against the lowercased input value.
        let log = db.into_transaction_log();
        let sql = &log[0].statements()[0].sql;
        assert!(sql.contains("LOWER"), "query must lower() the name column");
    }

    #[tokio::test]
    async fn test_find_by_name_ci_no_match_falls_through_to_nonlocal() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_local_user::Model>::new()])
            .append_query_results([Vec::<db_nonlocal_user::Model>::new()])
            .into_connection();

        let found = find_by_name_ci(&db, "foo_domain", "nobody").await.unwrap();
        assert_eq!(found, None);
        assert_eq!(db.into_transaction_log().len(), 2, "both tables checked");
    }
}
