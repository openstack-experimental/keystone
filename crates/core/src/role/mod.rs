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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::role::*;

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::service::RoleService;

pub use error::RoleProviderError;
pub use hook::RoleHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockRoleProvider;
pub use provider_api::RoleApi;

pub enum RoleProvider {
    Service(RoleService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockRoleProvider),
}

impl RoleProvider {
    /// Create a new RoleProvider.
    ///
    /// # Arguments
    /// * `config` - The configuration for the provider.
    /// * `plugin_manager` - The plugin manager used to load the backend driver.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RoleProviderError> {
        Ok(Self::Service(RoleService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl RoleApi for RoleProvider {
    /// Create role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for creating a role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        match self {
            Self::Service(provider) => provider.create_role(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_role(state, params).await,
        }
    }

    /// Create a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .create_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .create_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
        }
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
        match self {
            Self::Service(provider) => {
                provider
                    .check_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .check_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
        }
    }

    /// Delete a role by the ID.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to delete.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        match self {
            Self::Service(provider) => provider.delete_role(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_role(state, id).await,
        }
    }

    /// Delete a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .delete_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .delete_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
        }
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
        match self {
            Self::Service(provider) => provider.expand_implied_roles(state, roles).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.expand_implied_roles(state, roles).await,
        }
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
        match self {
            Self::Service(provider) => provider.get_role(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_role(state, id).await,
        }
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
        match self {
            Self::Service(provider) => {
                provider
                    .get_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .get_role_imply_rule(state, prior_role_id, implied_role_id)
                    .await
            }
        }
    }

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    async fn list_role_imply_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        match self {
            Self::Service(provider) => provider.list_role_imply_rules(state).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_role_imply_rules(state).await,
        }
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
        match self {
            Self::Service(provider) => {
                provider
                    .list_role_imply_rules_by_prior(state, prior_role_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .list_role_imply_rules_by_prior(state, prior_role_id)
                    .await
            }
        }
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
        match self {
            Self::Service(provider) => provider.list_roles(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_roles(state, params).await,
        }
    }
}
