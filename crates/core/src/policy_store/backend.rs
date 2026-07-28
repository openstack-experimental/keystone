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

use openstack_keystone_core_types::policy_store::*;

use crate::keystone::ServiceState;
use crate::policy_store::error::PolicyStoreProviderError;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PolicyStoreBackend: Send + Sync {
    /// Create a new policy.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `policy`: The policy creation parameters. `policy.id` is always
    ///   populated by the service layer.
    ///
    /// # Returns
    /// A `Result` containing the created `Policy`, or a
    /// `PolicyStoreProviderError`.
    async fn create_policy(
        &self,
        state: &ServiceState,
        policy: PolicyCreate,
    ) -> Result<Policy, PolicyStoreProviderError>;

    /// Delete a policy by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PolicyStoreProviderError`.
    async fn delete_policy(
        &self,
        state: &ServiceState,
        id: &str,
    ) -> Result<(), PolicyStoreProviderError>;

    /// Get a single policy by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Policy` if found, or a
    /// `PolicyStoreProviderError`.
    async fn get_policy(
        &self,
        state: &ServiceState,
        id: &str,
    ) -> Result<Option<Policy>, PolicyStoreProviderError>;

    /// List policies.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the policy list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Policy` objects or a
    /// `PolicyStoreProviderError`.
    async fn list_policies(
        &self,
        state: &ServiceState,
        params: &PolicyListParameters,
    ) -> Result<Vec<Policy>, PolicyStoreProviderError>;

    /// Update an existing policy.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the policy.
    /// - `policy`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Policy`, or a
    /// `PolicyStoreProviderError`.
    async fn update_policy(
        &self,
        state: &ServiceState,
        id: &str,
        policy: PolicyUpdate,
    ) -> Result<Policy, PolicyStoreProviderError>;
}
