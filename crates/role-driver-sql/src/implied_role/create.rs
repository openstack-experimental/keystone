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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleImply;

use crate::entity::implied_role as db_implied_role;

/// Create a role imply rule.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
/// - `implied_role_id`: The ID of the implied role.
///
/// # Returns
/// A `Result` containing the created `RoleImply`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<RoleImply, RoleProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting role inference rule")?;
    let _model = db_implied_role::ActiveModel {
        prior_role_id: Set(prior_role_id.to_string()),
        implied_role_id: Set(implied_role_id.to_string()),
    }
    .insert(&txn)
    .await
    .context("creating role imply rule")?;

    let resolved = super::list_expanded(
        &txn,
        Some(super::ImpliedRoleFilter::Exact(
            prior_role_id,
            implied_role_id,
        )),
    )
    .await?
    .first()
    .cloned()
    .ok_or_else(|| {
        RoleProviderError::Conflict("cannot refetch implied role after insert".into())
    })?;

    txn.commit()
        .await
        .context("committing transaction for persisting role inference rule")?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, MockRow};

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

    fn mock_db_model(prior: &str, implied: &str) -> db_implied_role::Model {
        db_implied_role::Model {
            prior_role_id: prior.into(),
            implied_role_id: implied.into(),
        }
    }

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_db_model("admin", "member")]])
            .append_query_results([vec![mock_row("admin", "admin", "member", "member")]])
            .into_connection();

        let created = create(&db, "admin", "member").await.unwrap();

        assert_eq!(
            created.prior_role,
            RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: None,
            }
        );
        assert_eq!(
            created.implied_role,
            RoleRef {
                id: "member".into(),
                name: Some("member".into()),
                domain_id: None,
            }
        );
    }

    #[tokio::test]
    async fn test_create_with_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_db_model("admin", "member")]])
            .append_query_results([vec![
                BTreeMap::from([
                    ("prior_role_id", "admin".into()),
                    ("prior_role_name", "admin".into()),
                    ("prior_role_domain_id", "default".into()),
                    ("implied_role_id", "member".into()),
                    ("implied_role_name", "member".into()),
                    ("implied_role_domain_id", "default".into()),
                ])
                .into_mock_row(),
            ]])
            .into_connection();

        let created = create(&db, "admin", "member").await.unwrap();

        assert_eq!(
            created.prior_role,
            RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: Some("default".into()),
            }
        );
        assert_eq!(
            created.implied_role,
            RoleRef {
                id: "member".into(),
                name: Some("member".into()),
                domain_id: Some("default".into()),
            }
        );
    }
}
