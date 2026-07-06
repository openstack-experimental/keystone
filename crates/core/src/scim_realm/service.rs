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
//! # SCIM realm provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::scim::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::scim_realm::{ScimRealmApi, backend::ScimRealmBackend, error::ScimRealmProviderError};

/// SCIM realm Provider.
pub struct ScimRealmService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn ScimRealmBackend>,
}

impl ScimRealmService {
    /// Create a new `ScimRealmService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ScimRealmProviderError> {
        let backend_driver = plugin_manager
            .get_scim_realm_backend(config.scim_realm.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `ScimRealmService` from a backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: ScimRealmBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

#[async_trait]
impl ScimRealmApi for ScimRealmService {
    async fn create_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ScimRealmResourceCreate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError> {
        let provider_id = data.provider_id.clone();
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::ScimRealm { provider_id: provider_id.clone() },
                ),
                operation: async {
                    backend_driver.create(ctx.state(), data).await
                },
                on_audit_error: |_: AuditDispatchError| ScimRealmProviderError::Driver { source: "audit dispatch failed".into() },
            }
        } else {
            let created = self.backend_driver.create(ctx.state(), data).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::ScimRealm { provider_id },
                ))
                .await;
            Ok(created)
        }
    }

    async fn get_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<ScimRealmResource>, ScimRealmProviderError> {
        self.backend_driver
            .get(ctx.state(), domain_id, provider_id)
            .await
    }

    async fn list_realms<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ScimRealmResourceListParameters,
    ) -> Result<Vec<ScimRealmResource>, ScimRealmProviderError> {
        self.backend_driver.list(ctx.state(), params).await
    }

    async fn update_realm<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        data: ScimRealmResourceUpdate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let data_clone = data.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::ScimRealm { provider_id: provider_id.to_string() },
                ),
                operation: async {
                    backend_driver.update(ctx.state(), domain_id, provider_id, data_clone).await
                },
                on_audit_error: |_: AuditDispatchError| ScimRealmProviderError::Driver { source: "audit dispatch failed".into() },
            }
        } else {
            let updated = self
                .backend_driver
                .update(ctx.state(), domain_id, provider_id, data)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::ScimRealm {
                        provider_id: provider_id.to_string(),
                    },
                ))
                .await;
            Ok(updated)
        }
    }
}
