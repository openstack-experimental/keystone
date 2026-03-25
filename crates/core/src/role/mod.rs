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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::role::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::service::RoleService;

pub use error::RoleProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockRoleProvider;
pub use provider_api::RoleApi;

pub enum RoleProvider {
    Service(RoleService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockRoleProvider),
}

impl RoleProvider {
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

    /// Delete a role by the ID.
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

    /// Get single role.
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

    /// Expand implied roles.
    ///
    /// Return list of the roles with the imply rules being considered.
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

    /// List role imply rules.
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError> {
        match self {
            Self::Service(provider) => provider.list_imply_rules(state, resolve).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_imply_rules(state, resolve).await,
        }
    }

    /// List roles.
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
