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
//! # Role provider
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::role::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::role::{RoleApi, RoleProviderError, backend::RoleBackend};

pub struct RoleService {
    backend_driver: Arc<dyn RoleBackend>,
}

impl RoleService {
    /// Create a new RoleService.
    ///
    /// # Arguments
    /// * `config` - The configuration for the service.
    /// * `plugin_manager` - The plugin manager used to load the backend driver.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RoleProviderError> {
        let backend_driver = plugin_manager
            .get_role_backend(config.role.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl RoleApi for RoleService {
    async fn create_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        params.validate()?;
        let mut new_params = params;
        if new_params.id.is_none() {
            new_params.id = Some(Uuid::new_v4().simple().to_string());
        }
        let role_id = new_params.id.clone().unwrap();

        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Role { id: role_id }),
                operation: async { backend_driver.create_role(state, new_params).await },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let role = self.backend_driver.create_role(ctx.state(), new_params).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Role { id: role.id.clone() },
                ))
                .await;
            Ok(role)
        }
    }

    async fn create_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::RoleImply {
                    prior_role_id: prior_role_id.to_string(),
                    implied_role_id: implied_role_id.to_string(),
                }),
                operation: async {
                    backend_driver.create_role_imply_rule(state, prior_role_id, implied_role_id).await
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let rule = self
                .backend_driver
                .create_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::RoleImply {
                        prior_role_id: prior_role_id.to_string(),
                        implied_role_id: implied_role_id.to_string(),
                    },
                ))
                .await;
            Ok(rule)
        }
    }

    async fn check_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError> {
        self.backend_driver
            .check_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
            .await
    }

    async fn delete_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Role { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_role(state, id).await?;
                    Ok::<(), RoleProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_role(ctx.state(), id).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Role { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn delete_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::RoleImply {
                    prior_role_id: prior_role_id.to_string(),
                    implied_role_id: implied_role_id.to_string(),
                }),
                operation: async {
                    backend_driver
                        .delete_role_imply_rule(state, prior_role_id, implied_role_id)
                        .await?;
                    Ok::<(), RoleProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::RoleImply {
                        prior_role_id: prior_role_id.to_string(),
                        implied_role_id: implied_role_id.to_string(),
                    },
                ))
                .await;
        }
        Ok(())
    }

    async fn expand_implied_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError> {
        // In most of the cases a logic for expanding the roles may be implemented by
        // the provider itself, but some backend drivers may have more efficient
        // methods.
        self.backend_driver
            .expand_implied_roles(ctx.state(), roles)
            .await?;
        Ok(())
    }

    async fn get_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        self.backend_driver.get_role(ctx.state(), id).await
    }

    async fn get_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError> {
        self.backend_driver
            .get_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
            .await
    }

    async fn list_role_imply_rules<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        self.backend_driver.list_role_imply_rules(ctx.state()).await
    }

    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        self.backend_driver
            .list_role_imply_rules_by_prior(ctx.state(), prior_role_id)
            .await
    }

    async fn list_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        params.validate()?;
        self.backend_driver.list_roles(ctx.state(), params).await
    }
}
