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
//! # OpenStack Keystone SQL driver for the role provider
use std::collections::HashSet;

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
//mod role_imply;

#[derive(Default)]
pub struct SqlBackend {}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

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
    let rules = implied_role::get_inference_tree(db, true).await?;
    let mut role_ids: HashSet<String> =
        HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
    let mut implied_roles: Vec<RoleRef> = Vec::new();
    // iterate over all implied role ids for every role in the initial list
    for implied_role in roles
        .iter()
        .filter_map(|role| rules.get(&role.id))
        .flat_map(|val| val.iter())
    {
        // Add the role that was not processed yet (present in the `role_ids` into the
        // temporary list and save the processed id.
        if !role_ids.contains(&implied_role.id) {
            implied_roles.push(implied_role.clone());
            role_ids.insert(implied_role.id.clone());
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

    /// Create a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` containing the created `RoleImply`, or an `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        Ok(implied_role::create(&state.db, prior_role_id, implied_role_id).await?)
    }

    /// Check if a role imply rule exists.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn check_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError> {
        Ok(implied_role::check(&state.db, prior_role_id, implied_role_id).await?)
    }

    /// Update a role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `role_id`: The ID of the role to update.
    /// - `role`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Role`, or an `Error`.
    async fn update_role<'a>(
        &self,
        state: &ServiceState,
        role_id: &'a str,
        role: RoleUpdate,
    ) -> Result<Role, RoleProviderError> {
        Ok(role::update(&state.db, role_id, role).await?)
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

    /// Delete a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    async fn delete_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        Ok(implied_role::delete(&state.db, prior_role_id, implied_role_id).await?)
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

    /// Get a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `RoleImply` if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError> {
        Ok(implied_role::get(&state.db, prior_role_id, implied_role_id).await?)
    }

    /// List role imply rules.
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// A `Result` containing a list of `RoleImply`, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_role_imply_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        Ok(implied_role::list(&state.db).await?)
    }

    /// List role imply rules for a specific prior role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    ///
    /// # Returns
    /// A `Result` containing a list of `RoleImply`, or an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        Ok(implied_role::list_by_prior(&state.db, prior_role_id).await?)
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
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, MockRow};

    use crate::role::NULL_DOMAIN_ID;
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

    fn mock_flat_imply_row(
        prior_id: &str,
        prior_name: &str,
        prior_domain: &str,
        implied_id: &str,
        implied_name: &str,
        implied_domain: &str,
    ) -> MockRow {
        BTreeMap::from([
            ("prior_role_id", prior_id.into()),
            ("prior_role_name", prior_name.into()),
            ("prior_role_domain_id", prior_domain.into()),
            ("implied_role_id", implied_id.into()),
            ("implied_role_name", implied_name.into()),
            ("implied_role_domain_id", implied_domain.into()),
        ])
        .into_mock_row()
    }

    fn mock_flat_imply(
        prior_id: &str,
        prior_name: &str,
        implied_id: &str,
        implied_name: &str,
    ) -> MockRow {
        mock_flat_imply_row(
            prior_id,
            prior_name,
            NULL_DOMAIN_ID,
            implied_id,
            implied_name,
            NULL_DOMAIN_ID,
        )
    }

    #[tokio::test]
    async fn test_expand_no_implies_no_domain_populates_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
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
            .append_query_results([vec![mock_flat_imply("r1", "admin", "r2", "reader")]])
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
        assert_eq!(roles[1].domain_id, None);
    }

    #[tokio::test]
    async fn test_expand_recursive_implied_roles_no_duplicates() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                mock_flat_imply("r1", "admin", "r2", "member"),
                mock_flat_imply("r2", "member", "r3", "reader"),
            ]])
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
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("member"));
        assert_eq!(roles[2].id, "r3");
        assert_eq!(roles[2].name.as_deref(), Some("reader"));
    }

    #[tokio::test]
    async fn test_expand_preserves_existing_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
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
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let mut roles: Vec<RoleRef> = vec![];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_expand_implied_role_not_in_rules_skipped() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_flat_imply("r2", "member", "r3", "reader")]])
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
            .append_query_results([Vec::<MockRow>::new()])
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
            .append_query_results([vec![mock_flat_imply("r1", "admin", "r3", "viewer")]])
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
    }
}
