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

/// List all role imply rules.
///
/// # Parameters
/// - `db`: The database connection.
///
/// # Returns
/// A `Result` containing a list of `RoleImply`, or an `Error`.
pub async fn list(db: &DatabaseConnection) -> Result<Vec<RoleImply>, RoleProviderError> {
    super::list_expanded(db, None).await
}

/// List role imply rules for a specific prior role.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
///
/// # Returns
/// A `Result` containing a list of `RoleImply`, or an `Error`.
pub async fn list_by_prior(
    db: &DatabaseConnection,
    prior_role_id: &str,
) -> Result<Vec<RoleImply>, RoleProviderError> {
    super::list_expanded(db, Some(ImpliedRoleFilter::PriorRole(prior_role_id))).await
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

    #[tokio::test]
    async fn test_list_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let results = list(&db).await.unwrap();

        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_list_multiple() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                mock_row("admin", "admin", "manager", "manager"),
                mock_row("manager", "manager", "member", "member"),
            ]])
            .into_connection();

        let results = list(&db).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "manager".into(),
                name: Some("manager".into()),
                domain_id: None,
            },
        }));
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "manager".into(),
                name: Some("manager".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "member".into(),
                name: Some("member".into()),
                domain_id: None,
            },
        }));
    }

    #[tokio::test]
    async fn test_list_by_prior() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                mock_row("admin", "admin", "manager", "manager"),
                mock_row("admin", "admin", "member", "member"),
            ]])
            .into_connection();

        let results = list_by_prior(&db, "admin").await.unwrap();

        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.prior_role.id, "admin");
        }
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "manager".into(),
                name: Some("manager".into()),
                domain_id: None,
            },
        }));
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "admin".into(),
                name: Some("admin".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "member".into(),
                name: Some("member".into()),
                domain_id: None,
            },
        }));
    }

    #[tokio::test]
    async fn test_list_by_prior_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let results = list_by_prior(&db, "admin").await.unwrap();

        assert!(results.is_empty());
    }
}
