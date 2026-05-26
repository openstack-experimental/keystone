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
//! OpenStack Keystone SQL driver for the role provider
use std::collections::{BTreeMap, BTreeSet, HashSet};

use async_trait::async_trait;

use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core::role::backend::RoleBackend;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::role::*;

pub mod entity;
mod implied_role;
mod role;

#[derive(Default)]
pub struct SqlBackend {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

/// Expand implied roles by resolving role inheritance and populating
/// missing role metadata.
///
/// # Parameters
/// - `db`: The database connection.
/// - `roles`: The list of roles to expand.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn expand_implied_roles(
    db: &DatabaseConnection,
    roles: &mut Vec<RoleRef>,
) -> Result<(), RoleProviderError> {
    let rules = implied_role::list_rules(db, true).await?;
    let mut role_ids: HashSet<String> =
        HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
    let mut implied_roles: Vec<RoleRef> = Vec::new();
    // iterate over all implied role ids for every role in the initial list
    for implied_role_id in roles
        .iter()
        .filter_map(|role| rules.get(&role.id))
        .flat_map(|val| val.iter())
    {
        // Add the role that was not processed yet (present in the `role_ids` into the
        // temporary list and save the processed id.
        if !role_ids.contains(implied_role_id) {
            implied_roles.push(
                role::get(db, implied_role_id)
                    .await?
                    .ok_or(RoleProviderError::RoleNotFound(implied_role_id.clone()))?
                    .into(),
            );
            role_ids.insert(implied_role_id.clone());
        }
    }
    roles.extend(implied_roles);
    // The request list may only contain role IDs. In the response we need to make
    // sure name and domain_id are populated.
    for role in roles.iter_mut() {
        if role.name.is_none() {
            // The role was not resolved and only has the ID. Re-fetch it
            let full_role = role::get(db, &role.id)
                .await?
                .ok_or(RoleProviderError::RoleNotFound(role.id.clone()))?;
            role.name = Some(full_role.name.clone());
            role.domain_id = full_role.domain_id;
        }
    }
    Ok(())
}

#[async_trait]
impl RoleBackend for SqlBackend {
    /// Create role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The role creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Role`, or an `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        Ok(role::create(&state.db, params).await?)
    }

    /// Delete a role by the ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The role ID.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        Ok(role::delete(&state.db, id).await?)
    }

    /// Get single role by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The role ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Role` if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        Ok(role::get(&state.db, id).await?)
    }

    /// Expand implied roles.
    ///
    /// Modify the list of roles resolving the role inheritance.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `roles`: The list of roles to expand.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError> {
        expand_implied_roles(&state.db, roles).await
    }

    /// List role imply rules.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `resolve`: Whether to resolve the rules recursively.
    ///
    /// # Returns
    /// A `Result` containing the map of role imply rules, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError> {
        Ok(implied_role::list_rules(&state.db, resolve).await?)
    }

    /// List roles.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// A `Result` containing a list of `Role`s, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        // TODO: Add possibility to list roles with expansion and filter (e.g.,
        // token_restriction has list of roles that need to be returned
        // resolved)
        Ok(role::list(&state.db, params).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database schema.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Role).await?;
        create_table(connection, schema, crate::entity::prelude::RoleOption).await?;
        create_table(connection, schema, crate::entity::prelude::ImpliedRole).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::entity::implied_role;
    use crate::implied_role::tests::get_implied_role_mock;
    use crate::role::tests::get_role_mock;

    use super::*;
    use openstack_keystone_core_types::role::RoleRefBuilder;

    fn mock_role_with_domain(id: &str, name: &str, domain: &str) -> crate::entity::role::Model {
        crate::entity::role::Model {
            id: id.into(),
            name: name.into(),
            extra: None,
            domain_id: domain.into(),
            description: None,
        }
    }

    #[tokio::test]
    async fn test_expand_no_implies_no_domain_populates_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<implied_role::Model>::new()])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
    }

    #[tokio::test]
    async fn test_expand_adds_implied_roles_and_resolves_names() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_implied_role_mock("r1", "r2")]])
            .append_query_results([vec![mock_role_with_domain("r2", "reader", "d1")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("reader"));
        assert_eq!(roles[1].domain_id.as_deref(), Some("d1"));
    }

    #[tokio::test]
    async fn test_expand_recursive_implied_roles_no_duplicates() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_implied_role_mock("r1", "r2"),
                get_implied_role_mock("r2", "r3"),
            ]])
            .append_query_results([vec![mock_role_with_domain("r2", "member", "d1")]])
            .append_query_results([vec![mock_role_with_domain("r3", "reader", "d1")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("member"));
        assert_eq!(roles[2].id, "r3");
        assert_eq!(roles[2].name.as_deref(), Some("reader"));
    }

    #[tokio::test]
    async fn test_expand_preserves_existing_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<implied_role::Model>::new()])
            .into_connection();

        let mut roles = vec![
            RoleRefBuilder::default()
                .id("r1")
                .name("admin")
                .domain_id("d1")
                .build()
                .unwrap(),
        ];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("d1"));
    }

    #[tokio::test]
    async fn test_expand_empty_roles_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<implied_role::Model>::new()])
            .into_connection();

        let mut roles: Vec<RoleRef> = vec![];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_expand_implied_role_not_in_rules_skipped() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_implied_role_mock("r2", "r3")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn test_expand_global_role_has_no_domain_in_output() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<implied_role::Model>::new()])
            .append_query_results([vec![mock_role_with_domain("r1", "admin", "<<null>>")]])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id, None);
    }

    #[tokio::test]
    async fn test_expand_multiple_roles_with_mixed_name_states() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_implied_role_mock("r1", "r3")]])
            .append_query_results([vec![mock_role_with_domain("r3", "viewer", "d1")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .into_connection();

        let mut roles = vec![
            RoleRef {
                id: "r1".into(),
                name: None,
                domain_id: None,
            },
            RoleRefBuilder::default()
                .id("r2")
                .name("member")
                .domain_id("d1")
                .build()
                .unwrap(),
        ];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("member"));
        assert_eq!(roles[1].domain_id.as_deref(), Some("d1"));
        assert_eq!(roles[2].id, "r3");
        assert_eq!(roles[2].name.as_deref(), Some("viewer"));
        assert_eq!(roles[2].domain_id.as_deref(), Some("d1"));
    }
}
