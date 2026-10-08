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
//! # SCIM resource index provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::scim::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::scim_resource::{
    ScimResourceApi, backend::ScimResourceBackend, error::ScimResourceProviderError,
};

/// SCIM resource index Provider.
pub struct ScimResourceService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn ScimResourceBackend>,
}

impl ScimResourceService {
    /// Create a new `ScimResourceService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ScimResourceProviderError> {
        let backend_driver = plugin_manager
            .get_scim_resource_backend(config.scim_resource.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `ScimResourceService` from a backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: ScimResourceBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

/// Build the audit event for a SCIM index change.
fn scim_index_event(operation: Operation, provider_id: &str, keystone_id: &str) -> Event {
    Event::new(
        operation,
        EventPayload::ScimIndex {
            provider_id: provider_id.to_string(),
            keystone_id: keystone_id.to_string(),
        },
    )
}

#[async_trait]
impl ScimResourceApi for ScimResourceService {
    #[tracing::instrument(
        name = "provider.scim_resource.create_index",
        level = "debug",
        skip_all
    )]
    async fn create_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ScimResourceIndexCreate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        let event = scim_index_event(Operation::Create, &data.provider_id, &data.keystone_id);
        let op = async { self.backend_driver.create(ctx.state(), data).await };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: event,
            operation: op,
            on_audit_error: |_: AuditDispatchError| ScimResourceProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(name = "provider.scim_resource.get_index", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id, resource_type = ?resource_type, keystone_id = %keystone_id))]
    async fn get_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .get(
                ctx.state(),
                domain_id,
                provider_id,
                resource_type,
                keystone_id,
            )
            .await
    }

    #[tracing::instrument(name = "provider.scim_resource.get_index_by_external_id", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id, resource_type = ?resource_type, external_id = %external_id))]
    async fn get_index_by_external_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        external_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .get_by_external_id(
                ctx.state(),
                domain_id,
                provider_id,
                resource_type,
                external_id,
            )
            .await
    }

    #[tracing::instrument(name = "provider.scim_resource.list_index", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id, resource_type = ?resource_type))]
    async fn list_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
    ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver
            .list(ctx.state(), domain_id, provider_id, resource_type)
            .await
    }

    #[tracing::instrument(name = "provider.scim_resource.update_index", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id, resource_type = ?resource_type, keystone_id = %keystone_id))]
    async fn update_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
        data: ScimResourceIndexUpdate,
        expected_version: Option<u64>,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        let op = async {
            self.backend_driver
                .update(
                    ctx.state(),
                    domain_id,
                    provider_id,
                    resource_type,
                    keystone_id,
                    data,
                    expected_version,
                )
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: scim_index_event(Operation::Update, provider_id, keystone_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ScimResourceProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(
        name = "provider.scim_resource.list_all_index",
        level = "debug",
        skip_all
    )]
    async fn list_all_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
    ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError> {
        self.backend_driver.list_all(ctx.state()).await
    }

    #[tracing::instrument(name = "provider.scim_resource.purge_index", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id, resource_type = ?resource_type, keystone_id = %keystone_id))]
    async fn purge_index<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
    ) -> Result<(), ScimResourceProviderError> {
        let op = async {
            self.backend_driver
                .purge(
                    ctx.state(),
                    domain_id,
                    provider_id,
                    resource_type,
                    keystone_id,
                )
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: scim_index_event(Operation::Delete, provider_id, keystone_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ScimResourceProviderError::AuditUnavailable,
        }
    }
}
