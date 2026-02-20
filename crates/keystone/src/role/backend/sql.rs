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

use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::super::types::*;
use crate::keystone::ServiceState;
use crate::role::backend::RoleCreate;
use crate::role::{RoleProviderError, backend::RoleBackend};

pub(crate) mod implied_role;
pub(crate) mod role;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl RoleBackend for SqlBackend {
    /// Create role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        Ok(role::create(&state.db, params).await?)
    }

    /// Get single role by ID.
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<Role>,
    ) -> Result<(), RoleProviderError> {
        let rules = implied_role::list_rules(&state.db, true).await?;
        let mut role_ids: HashSet<String> =
            HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
        let mut implied_roles: Vec<Role> = Vec::new();
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
                        .ok_or(RoleProviderError::RoleNotFound(implied_role_id.clone()))?,
                );
                role_ids.insert(implied_role_id.clone());
            }
        }
        roles.extend(implied_roles);
        Ok(())
    }

    /// List role imply rules.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError> {
        Ok(implied_role::list_rules(&state.db, resolve).await?)
    }

    /// List roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        Ok(role::list(&state.db, params).await?)
    }
}

impl From<crate::error::DatabaseError> for RoleProviderError {
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver(other.to_string()),
        }
    }
}
