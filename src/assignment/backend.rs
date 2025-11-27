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

pub mod error;
pub mod sql;

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::assignment::AssignmentProviderError;
use crate::config::Config;
use crate::keystone::ServiceState;

pub use crate::assignment::types::assignment::{
    Assignment, AssignmentBuilder, AssignmentBuilderError, AssignmentType,
    RoleAssignmentListForMultipleActorTargetParameters,
    RoleAssignmentListForMultipleActorTargetParametersBuilder, RoleAssignmentListParameters,
    RoleAssignmentListParametersBuilder, RoleAssignmentListParametersBuilderError,
    RoleAssignmentTarget,
};
pub use crate::assignment::types::role::{Role, RoleBuilder, RoleBuilderError, RoleListParameters};

pub use sql::SqlBackend;

#[async_trait]
pub trait AssignmentBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List Roles
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError>;

    /// Get single role by ID
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError>;

    /// List Role assignments
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;

    /// List all role assignments for multiple actors on multiple targets
    ///
    /// It is a naive interpretation of the effective role assignments where we
    /// check all roles assigned to the user (including groups) on a
    /// concrete target (including all higher targets the role can be
    /// inherited from)
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;

    /// Create assignment grant.
    async fn create_grant(
        &self,
        state: &ServiceState,
        params: Assignment,
    ) -> Result<Assignment, AssignmentProviderError>;

    /// Check assignment grant.
    async fn check_grant(
        &self,
        state: &ServiceState,
        params: &Assignment,
    ) -> Result<bool, AssignmentProviderError>;
}

dyn_clone::clone_trait_object!(AssignmentBackend);
