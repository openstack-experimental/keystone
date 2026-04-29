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
        let rules = implied_role::list_rules(&state.db, true).await?;
        let mut role_ids: HashSet<String> =
            HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
        let mut implied_roles: Vec<RoleRef> = Vec::new();
        // iterate over all implied role ids for every role in the initial list
        for implied_role_id in roles
            .iter_mut()
            .filter_map(|role| rules.get(&role.id))
            .flat_map(|val| val.iter())
        {
            // Add the role that was not processed yet (present in the `role_ids` into the
            // temporary list and save the processed id.
            if !role_ids.contains(implied_role_id) {
                implied_roles.push(
                    self.get_role(state, implied_role_id)
                        .await?
                        .ok_or(RoleProviderError::RoleNotFound(implied_role_id.clone()))?
                        .into(),
                );
                role_ids.insert(implied_role_id.clone());
            }
        }
        roles.extend(implied_roles);
        Ok(())
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
