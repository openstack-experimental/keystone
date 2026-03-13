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

use super::assignment::*;
use crate::assignment::AssignmentProviderError;
use crate::keystone::ServiceState;

/// The trait covering [`Role`](crate::role::types::Role) assignments between
/// `actors` and `objects`.
#[async_trait]
pub trait AssignmentApi: Send + Sync {
    /// Create assignment grant.
    async fn create_grant(
        &self,
        state: &ServiceState,
        params: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError>;

    /// List role assignments for given target/role/actor.
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;

    /// Revoke role assignment grant.
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        params: Assignment,
    ) -> Result<(), AssignmentProviderError>;
}
