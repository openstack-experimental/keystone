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
use std::collections::{BTreeMap, BTreeSet};

use openstack_keystone_core_types::role::*;

use crate::keystone::ServiceState;
use crate::role::RoleProviderError;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait RoleBackend: Send + Sync {
    /// Create Role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for creating a role.
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError>;

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
    ) -> Result<RoleImply, RoleProviderError>;

    /// Delete a role by the ID.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to delete.
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError>;

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
    ) -> Result<(), RoleProviderError>;

    /// Expand implied roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `roles` - The list of roles to expand.
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError>;

    /// Get single role by ID.
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
    ) -> Result<Option<Role>, RoleProviderError>;

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
    ) -> Result<Option<RoleImply>, RoleProviderError>;

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `resolve` - Whether to resolve the imply rules.
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError>;

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    async fn list_role_imply_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<RoleImply>, RoleProviderError>;

    /// List Roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for listing roles.
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError>;
}
