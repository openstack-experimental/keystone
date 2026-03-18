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

use crate::assignment::AssignmentProviderError;
use crate::assignment::types::assignment::*;
use crate::keystone::ServiceState;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AssignmentBackend: Send + Sync {
    /// Check assignment grant.
    async fn check_grant(
        &self,
        state: &ServiceState,
        params: &Assignment,
    ) -> Result<bool, AssignmentProviderError>;

    /// Create assignment grant.
    async fn create_grant(
        &self,
        state: &ServiceState,
        params: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError>;

    /// List Role assignments.
    ///
    /// List role assignments between the actor and the target matching
    /// parameters.
    ///
    /// When listing in effective mode, since the group assignments have been
    /// effectively expanded out into assignments for each user, the group role
    /// assignment entities themselves are not returned in the collection.
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;

    /// Revoke assignment grant.
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        params: &Assignment,
    ) -> Result<(), AssignmentProviderError>;
}
