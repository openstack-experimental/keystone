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

use crate::auth::ExecutionContext;
use crate::policy_store::PolicyStoreProviderError;

#[async_trait]
pub trait PolicyStoreApi: Send + Sync {
    /// Create a new policy.
    ///
    /// This layer is the single source of the identifier: it **always** mints
    /// a fresh one, discarding any `policy.id` the caller set, so the audit
    /// event raised for the operation carries the final ID. The backend
    /// rejects a create whose `id` is unset.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `policy`: The policy creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Policy`, or a
    /// `PolicyStoreProviderError`.
    async fn create_policy<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        policy: PolicyCreate,
    ) -> Result<Policy, PolicyStoreProviderError>;

    /// Delete a policy by ID.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PolicyStoreProviderError`.
    async fn delete_policy<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), PolicyStoreProviderError>;

    /// Get a single policy by ID.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Policy` if found, or a
    /// `PolicyStoreProviderError`.
    async fn get_policy<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Policy>, PolicyStoreProviderError>;

    /// List policies.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `params`: Parameters for filtering the policy list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Policy` objects or a
    /// `PolicyStoreProviderError`.
    async fn list_policies<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &PolicyListParameters,
    ) -> Result<Vec<Policy>, PolicyStoreProviderError>;

    /// Update an existing policy.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `id`: The unique identifier of the policy.
    /// - `policy`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Policy`, or a
    /// `PolicyStoreProviderError`.
    async fn update_policy<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        policy: PolicyUpdate,
    ) -> Result<Policy, PolicyStoreProviderError>;
}
