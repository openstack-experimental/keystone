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
//! # Assignments provider
//!
//! Assignments provider implements RBAC concept of granting an actor set of
//! roles on the target. An actor could be a user or a group of users, in which
//! case such roles are granted implicitly to the all users which are the member
//! of the group. The target is the domain, project or the system.
//!
//! Keystone implements few additional features for the role assignments:
//!
//! ## Role inference
//!
//! Roles in Keystone may imply other roles building an inference chain. For
//! example a role `manager` can imply the `member` role, which in turn implies
//! the `reader` role. As such with a single assignment of the `manager` role
//! the user will automatically get `manager`, `member` and `reader` roles. This
//! helps limiting number of necessary direct assignments.
//!
//! ## Target assignment inheritance
//!
//! Keystone adds `inherited` parameter to the assignment of the role on the
//! target. In such case an assignment actor gets this role assignment
//! (including role inference) on the whole subtree targets excluding the target
//! itself. This way for an assignment on the domain level the actor
//! will get the role on the every project of the domain, but not the domain
//! itself.
use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::assignment::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use crate::assignment::service::AssignmentService;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub use error::AssignmentProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockAssignmentProvider;
pub use provider_api::AssignmentApi;

pub enum AssignmentProvider {
    Service(AssignmentService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockAssignmentProvider),
}

impl AssignmentProvider {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, AssignmentProviderError> {
        Ok(Self::Service(AssignmentService::new(
            config,
            plugin_manager,
        )?))
    }
}

#[async_trait]
impl AssignmentApi for AssignmentProvider {
    /// Create assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        match self {
            Self::Service(provider) => provider.create_grant(state, grant).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_grant(state, grant).await,
        }
    }

    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        match self {
            Self::Service(provider) => provider.list_role_assignments(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_role_assignments(state, params).await,
        }
    }

    /// Revoke grant
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        grant: Assignment,
    ) -> Result<(), AssignmentProviderError> {
        match self {
            Self::Service(provider) => provider.revoke_grant(state, grant).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.revoke_grant(state, grant).await,
        }
    }
}
