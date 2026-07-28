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
//! # Policy store provider
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::policy_store::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::policy_store::{PolicyStoreApi, PolicyStoreProviderError, backend::PolicyStoreBackend};

pub struct PolicyStoreService {
    backend_driver: Arc<dyn PolicyStoreBackend>,
}

impl PolicyStoreService {
    /// Creates a new `PolicyStoreService`.
    ///
    /// # Parameters
    /// - `config`: The configuration for the policy store provider.
    /// - `plugin_manager`: The plugin manager used to load the backend.
    ///
    /// # Returns
    /// A `Result` containing the `PolicyStoreService` instance or a
    /// `PolicyStoreProviderError`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, PolicyStoreProviderError> {
        let backend_driver = plugin_manager
            .get_policy_store_backend(config.policy.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl PolicyStoreApi for PolicyStoreService {
    /// Create a new policy.
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
        mut policy: PolicyCreate,
    ) -> Result<Policy, PolicyStoreProviderError> {
        // This layer is the single source of the identifier, and it always
        // mints a fresh one — matching python keystone's `_assign_unique_id`,
        // which overwrites whatever the caller sent. Assigning it *here*,
        // before the audited operation is constructed, means the event raised
        // around the write already carries the final resource ID; doing it in
        // the backend would leave the pre-operation audit record without one.
        let id = Uuid::new_v4().simple().to_string();
        policy.id = Some(id.clone());
        policy.validate()?;

        let policy = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Policy { id: id.clone() },
                ),
                operation: async {
                    backend_driver.create_policy(exec.state(), policy).await
                },
                on_audit_error: |_: AuditDispatchError| PolicyStoreProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let policy = self
                .backend_driver
                .create_policy(exec.state(), policy)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Policy {
                        id: policy.id.clone(),
                    },
                ))
                .await;

            policy
        };

        Ok(policy)
    }

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
    ) -> Result<(), PolicyStoreProviderError> {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Policy { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_policy(exec.state(), id).await?;
                    Ok::<(), PolicyStoreProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| PolicyStoreProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_policy(exec.state(), id).await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Policy { id: id.to_string() },
                ))
                .await;
        }

        Ok(())
    }

    /// Get a single policy by ID.
    ///
    /// # Parameters
    /// - `exec`: The current execution context.
    /// - `id`: The unique identifier of the policy.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the policy if found, or a
    /// `PolicyStoreProviderError`.
    async fn get_policy<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Policy>, PolicyStoreProviderError> {
        self.backend_driver.get_policy(exec.state(), id).await
    }

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
    ) -> Result<Vec<Policy>, PolicyStoreProviderError> {
        params.validate()?;
        self.backend_driver
            .list_policies(exec.state(), params)
            .await
    }

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
    ) -> Result<Policy, PolicyStoreProviderError> {
        policy.validate()?;
        let updated = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Policy { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_policy(exec.state(), id, policy).await
                },
                on_audit_error: |_: AuditDispatchError| PolicyStoreProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let updated = self
                .backend_driver
                .update_policy(exec.state(), id, policy)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Policy { id: id.to_string() },
                ))
                .await;
            updated
        };
        Ok(updated)
    }
}
