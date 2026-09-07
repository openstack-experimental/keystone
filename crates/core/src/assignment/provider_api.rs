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
use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;
use openstack_keystone_core_types::assignment::*;

/// The trait covering [`Role`](crate::role::types::Role) assignments between
/// `actors` and `objects`.
#[async_trait]
pub trait AssignmentApi: Send + Sync {
    /// Create assignment grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The assignment creation parameters.
    ///
    /// # Returns
    /// - `Result<Assignment, AssignmentProviderError>` - The created assignment
    ///   or an error.
    async fn create_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError>;

    /// List role assignments for given target/role/actor.
    ///
    /// List role assignments between the actor and the target matching
    /// parameters.
    ///
    /// When listing in effective mode, since the group assignments have been
    /// effectively expanded out into assignments for each user, the group role
    /// assignment entities themselves are not returned in the collection.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The parameters for listing assignments.
    ///
    /// # Returns
    /// - `Result<Vec<Assignment>, AssignmentProviderError>` - A list of
    ///   assignments or an error.
    async fn list_role_assignments<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;

    /// Revoke role assignment grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The assignment to revoke.
    ///
    /// # Returns
    /// - `Result<(), AssignmentProviderError>` - Ok on success, or an error.
    async fn revoke_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: Assignment,
    ) -> Result<(), AssignmentProviderError>;

    /// Rebuild the per-domain dispatch bundle — the global backend, the named
    /// `[assignment.backends.*]` instances and the fan-out set — from the
    /// current configuration and the stored `assignment/driver` bindings
    /// (ADR 0034 §9). Clears the resolved-binding cache.
    ///
    /// Returns `true` when the active bundle actually changed. An unresolvable
    /// new configuration is logged and the last-known-good bundle is kept
    /// (`Ok(false)`).
    ///
    /// The default is a no-op, so a provider without per-domain dispatch — and
    /// `MockAssignmentProvider` — needs no implementation.
    async fn reload(&self, _state: &ServiceState) -> Result<bool, AssignmentProviderError> {
        Ok(false)
    }

    /// Recompute only the domain→driver bindings and the fan-out set after a
    /// domain-config API write, keeping the current resolver instance
    /// (ADR 0034 §9). Best-effort: a failure is logged and the fan-out set
    /// self-heals on the next full [`Self::reload`].
    async fn refresh_bindings(&self, _state: &ServiceState) -> Result<(), AssignmentProviderError> {
        Ok(())
    }
}
