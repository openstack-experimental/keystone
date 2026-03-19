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
//! # Role provider
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::{RoleProviderError, backend::RoleBackend, types::*};

pub struct RoleService {
    backend_driver: Arc<dyn RoleBackend>,
}

impl RoleService {
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
    #[tracing::instrument(level = "info", skip(self, state))]
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
        self.backend_driver.create_role(state, new_params).await
    }

    /// Delete a role by the ID.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        self.backend_driver.delete_role(state, id).await
    }

    /// Get single role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        self.backend_driver.get_role(state, id).await
    }

    /// Expand implied roles.
    ///
    /// Return list of the roles with the imply rules being considered.
    #[tracing::instrument(level = "info", skip(self, state))]
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

    /// List role imply rules.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError> {
        self.backend_driver.list_imply_rules(state, resolve).await
    }

    /// List roles.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        params.validate()?;
        self.backend_driver.list_roles(state, params).await
    }
}
