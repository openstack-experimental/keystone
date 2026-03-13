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
//! # Assignments provider
use async_trait::async_trait;
use std::sync::Arc;
use validator::Validate;

use crate::assignment::{AssignmentProviderError, backend::AssignmentBackend, types::*};
use crate::config::Config;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::ResourceApi;
use crate::revoke::{RevokeApi, types::RevocationEventCreate};

pub struct AssignmentService {
    backend_driver: Arc<dyn AssignmentBackend>,
}

impl AssignmentService {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, AssignmentProviderError> {
        let backend_driver = plugin_manager
            .get_assignment_backend(config.assignment.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl AssignmentApi for AssignmentService {
    /// Create assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        self.backend_driver.create_grant(state, grant).await
    }

    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
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
        } else if let Some(val) = &params.system_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::System,
                inherited: Some(false),
            })
        }
        request.targets(targets);
        request.actors(actors);
        self.backend_driver
            .list_assignments_for_multiple_actors_and_targets(state, &request.build()?)
            .await
    }

    /// Revoke grant
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        grant: Assignment,
    ) -> Result<(), AssignmentProviderError> {
        // Call backend with reference (no move)
        self.backend_driver.revoke_grant(state, &grant).await?;

        // Determine user_id or group_id
        let user_id = match &grant.r#type {
            AssignmentType::UserDomain
            | AssignmentType::UserProject
            | AssignmentType::UserSystem => Some(grant.actor_id.clone()),

            AssignmentType::GroupDomain
            | AssignmentType::GroupProject
            | AssignmentType::GroupSystem => None,
        };

        // Determine project_id or domain_id
        let (project_id, domain_id) = match &grant.r#type {
            AssignmentType::UserProject | AssignmentType::GroupProject => {
                (Some(grant.target_id.clone()), None)
            }
            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                (None, Some(grant.target_id.clone()))
            }
            AssignmentType::UserSystem | AssignmentType::GroupSystem => (None, None),
        };

        let revocation_event = RevocationEventCreate {
            domain_id,
            project_id,
            user_id,
            role_id: Some(grant.role_id.clone()),
            trust_id: None,
            consumer_id: None,
            access_token_id: None,
            issued_before: chrono::Utc::now(),
            expires_at: None,
            audit_id: None,
            audit_chain_id: None,
            revoked_at: chrono::Utc::now(),
        };

        state
            .provider
            .get_revoke_provider()
            .create_revocation_event(state, revocation_event)
            .await?;

        Ok(())
    }
}
