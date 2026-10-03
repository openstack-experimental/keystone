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
//! # Dynamic plugin identity index provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::auth_plugin_identity::{
    DynamicPluginIdentityApi, backend::DynamicPluginIdentityBackend,
    error::AuthPluginIdentityProviderError,
};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;

/// Dynamic plugin identity index Provider.
pub struct DynamicPluginIdentityService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn DynamicPluginIdentityBackend>,
}

impl DynamicPluginIdentityService {
    /// Create a new `DynamicPluginIdentityService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, AuthPluginIdentityProviderError> {
        let backend_driver = plugin_manager
            .get_auth_plugin_identity_backend(config.auth_plugin_identity.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `DynamicPluginIdentityService` from a backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: DynamicPluginIdentityBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

/// Build the audit event for a plugin identity link change. The external ID
/// is plugin-controlled data and is deliberately not carried.
fn plugin_identity_event(
    operation: Operation,
    plugin_name: Option<&str>,
    user_id: Option<&str>,
) -> Event {
    Event::new(
        operation,
        EventPayload::PluginIdentity {
            plugin_name: plugin_name.map(str::to_string),
            user_id: user_id.map(str::to_string),
        },
    )
}

#[async_trait]
impl DynamicPluginIdentityApi for DynamicPluginIdentityService {
    async fn create_or_resolve<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
        user_id: &'a str,
    ) -> Result<String, AuthPluginIdentityProviderError> {
        let op = async {
            self.backend_driver
                .create_or_resolve(ctx.state(), plugin_name, external_id, user_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: plugin_identity_event(
                Operation::Other("create_or_resolve".to_string()),
                Some(plugin_name),
                Some(user_id),
            ),
            operation: op,
            on_audit_error: |_: AuditDispatchError| AuthPluginIdentityProviderError::AuditUnavailable,
        }
    }

    async fn find<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<Option<String>, AuthPluginIdentityProviderError> {
        self.backend_driver
            .find(ctx.state(), plugin_name, external_id)
            .await
    }

    async fn purge<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
        external_id: &'a str,
    ) -> Result<(), AuthPluginIdentityProviderError> {
        let op = async {
            self.backend_driver
                .purge(ctx.state(), plugin_name, external_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: plugin_identity_event(Operation::Delete, Some(plugin_name), None),
            operation: op,
            on_audit_error: |_: AuditDispatchError| AuthPluginIdentityProviderError::AuditUnavailable,
        }
    }

    async fn purge_by_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), AuthPluginIdentityProviderError> {
        let op = async {
            self.backend_driver
                .purge_by_user(ctx.state(), user_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: plugin_identity_event(Operation::Delete, None, Some(user_id)),
            operation: op,
            on_audit_error: |_: AuditDispatchError| AuthPluginIdentityProviderError::AuditUnavailable,
        }
    }

    async fn list_by_plugin<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        plugin_name: &'a str,
    ) -> Result<Vec<(String, String)>, AuthPluginIdentityProviderError> {
        self.backend_driver
            .list_by_plugin(ctx.state(), plugin_name)
            .await
    }
}
