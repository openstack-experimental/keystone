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
//!
//! Role provider provides possibility to manage roles (part of RBAC).
//!
//! Following Keystone concepts are covered by the provider:
//!
//! ## Role inference
//!
//! Roles in Keystone may imply other roles building an inference chain. For
//! example a role `manager` can imply the `member` role, which in turn implies
//! the `reader` role. As such with a single assignment of the `manager` role
//! the user will automatically get `manager`, `member` and `reader` roles. This
//! helps limiting number of necessary direct assignments.
//!
//! ## Role
//!
//! A personality with a defined set of user rights and privileges to perform a
//! specific set of operations. The Identity service issues a token to a user
//! that includes a list of roles. When a user calls a service, that service
//! interprets the user role set, and determines to which operations or
//! resources each role grants access.
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use backend::{RoleBackend, SqlBackend};
use error::RoleProviderError;
use types::*;

#[cfg(test)]
pub use mock::MockRoleProvider;
pub use types::RoleApi;

pub struct RoleProvider {
    backend_driver: Arc<dyn RoleBackend>,
}

impl RoleProvider {
    pub fn new(config: &Config, plugin_manager: &PluginManager) -> Result<Self, RoleProviderError> {
        let backend_driver =
            if let Some(driver) = plugin_manager.get_role_backend(config.role.driver.clone()) {
                driver.clone()
            } else {
                match config.role.driver.as_str() {
                    "sql" => Arc::new(SqlBackend::default()),
                    other => {
                        return Err(RoleProviderError::UnsupportedDriver(other.to_string()));
                    }
                }
            };
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl RoleApi for RoleProvider {
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
        roles: &mut Vec<Role>,
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

    /// List roles
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
