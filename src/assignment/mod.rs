// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
use validator::Validate;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;

use crate::assignment::backend::{AssignmentBackend, SqlBackend};
use crate::assignment::error::AssignmentProviderError;
use crate::assignment::types::{
    Assignment, Role, RoleAssignmentListForMultipleActorTargetParametersBuilder,
    RoleAssignmentListParameters, RoleAssignmentTarget, RoleAssignmentTargetType,
    RoleListParameters,
};
use crate::config::Config;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::resource::ResourceApi;

#[cfg(test)]
pub use mock::MockAssignmentProvider;
pub use types::AssignmentApi;

#[derive(Clone, Debug)]
pub struct AssignmentProvider {
    backend_driver: Box<dyn AssignmentBackend>,
}

impl AssignmentProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, AssignmentProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_assignment_backend(config.assignment.driver.clone())
        {
            driver.clone()
        } else {
            match config.assignment.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                other => {
                    return Err(AssignmentProviderError::UnsupportedDriver(
                        other.to_string(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl AssignmentApi for AssignmentProvider {
    /// List roles
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<impl IntoIterator<Item = Role>, AssignmentProviderError> {
        self.backend_driver.list_roles(state, params).await
    }

    /// Get single role
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError> {
        self.backend_driver.get_role(state, id).await
    }

    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<impl IntoIterator<Item = Assignment>, AssignmentProviderError> {
        params.validate()?;
        let mut request = RoleAssignmentListForMultipleActorTargetParametersBuilder::default();
        let mut actors: Vec<String> = Vec::new();
        let mut targets: Vec<RoleAssignmentTarget> = Vec::new();
        if let Some(role_id) = &params.role_id {
            request.role_id(role_id);
        }
        if let Some(uid) = &params.user_id {
            actors.push(uid.into());
        }
        if let Some(true) = &params.effective
            && let Some(uid) = &params.user_id
        {
            let users = state
                .provider
                .get_identity_provider()
                .list_groups_of_user(state, uid)
                .await?;
            actors.extend(users.into_iter().map(|x| x.id));
        };
        if let Some(val) = &params.project_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Project,
                inherited: Some(false),
            });
            if let Some(parents) = state
                .provider
                .get_resource_provider()
                .get_project_parents(state, val)
                .await?
            {
                parents.iter().for_each(|parent_project| {
                    targets.push(RoleAssignmentTarget {
                        id: parent_project.id.clone(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: Some(true),
                    });
                });
            }
        } else if let Some(val) = &params.domain_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Domain,
                inherited: Some(false),
            });
        }
        request.targets(targets);
        request.actors(actors);
        self.backend_driver
            .list_assignments_for_multiple_actors_and_targets(state, &request.build()?)
            .await
    }

    /// Create assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        params: Assignment,
    ) -> Result<Assignment, AssignmentProviderError> {
        self.backend_driver.create_grant(state, params).await
    }
}
