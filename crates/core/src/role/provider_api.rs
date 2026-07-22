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

use openstack_keystone_core_types::role::*;

use crate::auth::ExecutionContext;
use crate::role::RoleProviderError;

/// A trait defining the role API.
///
/// Manage roles that can be granted to `actors` on `targets` implementing the
/// ReBAC.
#[async_trait]
pub trait RoleApi: Send + Sync {
    /// Create Role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for creating a role.
    async fn create_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError>;

    /// Check if a role imply rule exists.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn check_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError>;

    /// Update a role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `role_id` - The ID of the role to update.
    /// * `role` - The fields to change.
    async fn update_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        role_id: &'a str,
        role: RoleUpdate,
    ) -> Result<Role, RoleProviderError>;

    /// Delete a role by the ID.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to delete.
    async fn delete_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError>;

    /// Expand implied roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `roles` - The list of roles to expand.
    async fn expand_implied_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError>;

    /// Get a single role.
    ///
    /// * `state` - The current service state.
    /// * `role_id` - The ID of the role to retrieve.
    ///
    /// A `Result` containing an `Option` with the `Role` if found, or an
    /// `Error`.
    async fn get_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        role_id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError>;

    /// Get a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    async fn get_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError>;

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    async fn list_role_imply_rules<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
    ) -> Result<Vec<RoleImply>, RoleProviderError>;

    /// List role imply rules for a specific prior role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError>;

    /// List Roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for listing roles.
    async fn list_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError>;
}
