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

pub mod assignment;
pub mod role;

use async_trait::async_trait;

use crate::assignment::AssignmentProviderError;
use crate::keystone::ServiceState;

pub use crate::assignment::types::assignment::*;
pub use crate::assignment::types::role::{Role, RoleBuilder, RoleBuilderError, RoleListParameters};

#[async_trait]
pub trait AssignmentApi: Send + Sync + Clone {
    /// List Roles.
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<impl IntoIterator<Item = Role>, AssignmentProviderError>;

    /// Get a single role.
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        role_id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError>;

    /// List role assignments for given target/role/actor.
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<impl IntoIterator<Item = Assignment>, AssignmentProviderError>;

    /// Create assignment grant.
    async fn create_grant(
        &self,
        state: &ServiceState,
        params: Assignment,
    ) -> Result<Assignment, AssignmentProviderError>;
}
