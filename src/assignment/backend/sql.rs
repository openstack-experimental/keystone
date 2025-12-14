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

use super::super::types::*;
use crate::assignment::backend::RoleCreate;
use crate::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use crate::config::Config;
use crate::keystone::ServiceState;

pub(crate) mod assignment;
pub(crate) mod implied_role;
pub(crate) mod role;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// List roles
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError> {
        // Ok(role::ge)
        Ok(role::list(&self.config, &state.db, params).await?)
    }

    /// Get single role by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError> {
        Ok(role::get(&self.config, &state.db, id).await?)
    }

    /// Create role
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, AssignmentProviderError> {
        Ok(role::create(&self.config, &state.db, &params).await?)
    }
    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        Ok(assignment::list(&self.config, &state.db, params).await?)
    }

    /// List role assignments for multiple actors/targets
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        Ok(
            assignment::list_for_multiple_actors_and_targets(&self.config, &state.db, params)
                .await?,
        )
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

    /// Check assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn check_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        Ok(assignment::check(&state.db, grant).await?)
    }
}
