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
//! # Resource provider
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::resource::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::{ResourceApi, ResourceProviderError, backend::ResourceBackend};

pub struct ResourceService {
    backend_driver: Arc<dyn ResourceBackend>,
}

impl ResourceService {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ResourceProviderError> {
        let backend_driver = plugin_manager
            .get_resource_backend(config.resource.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ResourceApi for ResourceService {
    async fn get_domain_enabled<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        self.backend_driver
            .get_domain_enabled(ctx.state(), domain_id)
            .await
    }

    async fn create_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError> {
        let mut new_domain = domain;
        let domain_id = if let Some(id) = &new_domain.id {
            id.clone()
        } else {
            let id = Uuid::new_v4().simple().to_string();
            new_domain.id = Some(id.clone());
            id
        };
        new_domain.validate()?;

        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Domain { id: domain_id }),
                operation: async { backend_driver.create_domain(state, new_domain).await },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let domain = self.backend_driver.create_domain(ctx.state(), new_domain).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Domain { id: domain.id.clone() },
                ))
                .await;
            Ok(domain)
        }
    }

    async fn create_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        let mut new_project = project;
        let project_id = if let Some(id) = &new_project.id {
            id.clone()
        } else {
            let id = Uuid::new_v4().simple().to_string();
            new_project.id = Some(id.clone());
            id
        };
        new_project.validate()?;

        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Project { id: project_id }),
                operation: async { backend_driver.create_project(state, new_project).await },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let project = self.backend_driver.create_project(ctx.state(), new_project).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Project { id: project.id.clone() },
                ))
                .await;
            Ok(project)
        }
    }

    async fn delete_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Domain { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_domain(state, id).await?;
                    Ok::<(), ResourceProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_domain(ctx.state(), id).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Domain { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn delete_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Project { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_project(state, id).await?;
                    Ok::<(), ResourceProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_project(ctx.state(), id).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Project { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn get_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver.get_domain(ctx.state(), domain_id).await
    }

    async fn get_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project(ctx.state(), project_id)
            .await
    }

    async fn get_project_by_name<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project_by_name(ctx.state(), name, domain_id)
            .await
    }

    async fn get_project_parents<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        self.backend_driver
            .get_project_parents(ctx.state(), project_id)
            .await
    }

    async fn find_domain_by_name<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(ctx.state(), domain_name)
            .await
    }

    async fn list_domains<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        self.backend_driver.list_domains(ctx.state(), params).await
    }

    async fn list_projects<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        self.backend_driver.list_projects(ctx.state(), params).await
    }
}
