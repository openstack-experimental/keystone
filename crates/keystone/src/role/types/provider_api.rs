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

use super::role::*;
use crate::keystone::ServiceState;
use crate::role::RoleProviderError;

/// A trait defining the role API.
///
/// Manage roles that can be granted to `actors` on `targets` implementing the
/// ReBAC.
#[async_trait]
pub trait RoleApi: Send + Sync {
    /// Create Role.
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError>;

    /// Get a single role.
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        role_id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError>;

    /// Expand implied roles.
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<Role>,
    ) -> Result<(), RoleProviderError>;

    /// List role imply rules.
    async fn list_imply_rules(
        &self,
        state: &ServiceState,
        resolve: bool,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError>;

    /// List Roles.
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError>;
}
