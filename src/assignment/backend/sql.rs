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
use std::collections::HashSet;

use super::super::types::*;
use crate::assignment::backend::RoleCreate;
use crate::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use crate::keystone::ServiceState;

pub(crate) mod assignment;
pub(crate) mod implied_role;
pub(crate) mod role;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Check assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn check_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        Ok(assignment::check(&state.db, grant).await?)
    }

    /// Create assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: Assignment,
    ) -> Result<Assignment, AssignmentProviderError> {
        Ok(assignment::create(&state.db, grant).await?)
    }

    /// Create role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, AssignmentProviderError> {
        Ok(role::create(&state.db, params).await?)
    }

    /// Get single role by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError> {
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
    ) -> Result<(), AssignmentProviderError> {
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
                implied_roles.push(self.get_role(state, implied_role_id).await?.ok_or(
                    AssignmentProviderError::RoleNotFound(implied_role_id.clone()),
                )?);
                role_ids.insert(implied_role_id.clone());
            }
        }
        roles.extend(implied_roles);
        Ok(())
    }

    /// List roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError> {
        Ok(role::list(&state.db, params).await?)
    }

    /// List role assignments.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        Ok(assignment::list(&state.db, params).await?)
    }

    /// List role assignments for multiple actors/targets.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        Ok(assignment::list_for_multiple_actors_and_targets(&state.db, params).await?)
    }
}
