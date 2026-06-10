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
//! # Role provider
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::role::*;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::{RoleApi, RoleProviderError, backend::RoleBackend};

pub struct RoleService {
    backend_driver: Arc<dyn RoleBackend>,
}

impl RoleService {
    /// Create a new RoleService.
    ///
    /// # Arguments
    /// * `config` - The configuration for the service.
    /// * `plugin_manager` - The plugin manager used to load the backend driver.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RoleProviderError> {
        let backend_driver = plugin_manager
            .get_role_backend(config.role.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl RoleApi for RoleService {
    /// Create role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for creating a role.
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        params.validate()?;

        let mut new_params = params;

        if new_params.id.is_none() {
            new_params.id = Some(Uuid::new_v4().simple().to_string());
        }
        let role = self.backend_driver.create_role(state, new_params).await?;

        state
            .event_dispatcher
            .emit(Event::new(
                Operation::Create,
                EventPayload::Role {
                    id: role.id.clone(),
                },
            ))
            .await;

        Ok(role)
    }

    /// Create a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn create_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        let rule = self
            .backend_driver
            .create_role_imply_rule(state, prior_role_id, implied_role_id)
            .await?;

        state
            .event_dispatcher
            .emit(Event::new(
                Operation::Create,
                EventPayload::RoleImply {
                    prior_role_id: prior_role_id.to_string(),
                    implied_role_id: implied_role_id.to_string(),
                },
            ))
            .await;

        Ok(rule)
    }

    /// Check if a role imply rule exists.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn check_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError> {
        self.backend_driver
            .check_role_imply_rule(state, prior_role_id, implied_role_id)
            .await
    }

    /// Delete a role by the ID.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to delete.
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        self.backend_driver.delete_role(state, id).await?;

        state
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Role { id: id.to_string() },
            ))
            .await;

        Ok(())
    }

    /// Delete a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn delete_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        self.backend_driver
            .delete_role_imply_rule(state, prior_role_id, implied_role_id)
            .await?;

        state
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::RoleImply {
                    prior_role_id: prior_role_id.to_string(),
                    implied_role_id: implied_role_id.to_string(),
                },
            ))
            .await;

        Ok(())
    }

    /// Expand implied roles.
    ///
    /// Return list of the roles with the imply rules being considered.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `roles` - The list of roles to expand.
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError> {
        // In most of the cases a logic for expanding the roles may be implemented by
        // the provider itself, but some backend drivers may have more efficient
        // methods.
        self.backend_driver
            .expand_implied_roles(state, roles)
            .await?;
        Ok(())
    }

    /// Get single role.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to retrieve.
    ///
    /// A `Result` containing an `Option` with the `Role` if found, or an
    /// `Error`.
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        self.backend_driver.get_role(state, id).await
    }

    /// Get a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn get_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError> {
        self.backend_driver
            .get_role_imply_rule(state, prior_role_id, implied_role_id)
            .await
    }

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    async fn list_role_imply_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        self.backend_driver.list_role_imply_rules(state).await
    }

    /// List role imply rules for a specific prior role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        self.backend_driver
            .list_role_imply_rules_by_prior(state, prior_role_id)
            .await
    }

    /// List roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for listing roles.
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        params.validate()?;
        self.backend_driver.list_roles(state, params).await
    }
}
