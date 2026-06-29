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
//! # Catalog provider
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::catalog::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::catalog::{CatalogApi, CatalogProviderError, backend::CatalogBackend};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;

pub struct CatalogService {
    backend_driver: Arc<dyn CatalogBackend>,
}

impl CatalogService {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, CatalogProviderError> {
        let backend_driver = plugin_manager
            .get_catalog_backend(config.catalog.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl CatalogApi for CatalogService {
    async fn create_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        endpoint: EndpointCreate,
    ) -> Result<Endpoint, CatalogProviderError> {
        let mut endpoint = endpoint;
        endpoint.validate()?;
        let endpoint_id = if let Some(id) = &endpoint.id {
            id.clone()
        } else {
            let id = Uuid::new_v4().simple().to_string();
            endpoint.id = Some(id.clone());
            id
        };

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Endpoint { id: endpoint_id }),
                operation: async { backend_driver.create_endpoint(state, endpoint).await },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let endpoint = self
                .backend_driver
                .create_endpoint(exec.state(), endpoint)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Endpoint { id: endpoint.id.clone() },
                ))
                .await;
            Ok(endpoint)
        }
    }

    async fn create_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        region: RegionCreate,
    ) -> Result<Region, CatalogProviderError> {
        let mut region = region;
        region.validate()?;
        let region_id = if let Some(id) = &region.id {
            id.clone()
        } else {
            let id = Uuid::new_v4().simple().to_string();
            region.id = Some(id.clone());
            id
        };

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Region { id: region_id }),
                operation: async { backend_driver.create_region(state, region).await },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let region = self
                .backend_driver
                .create_region(exec.state(), region)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Region { id: region.id.clone() },
                ))
                .await;
            Ok(region)
        }
    }

    async fn create_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        service: ServiceCreate,
    ) -> Result<Service, CatalogProviderError> {
        let mut service = service;
        service.validate()?;
        let service_id = if let Some(id) = &service.id {
            id.clone()
        } else {
            let id = Uuid::new_v4().simple().to_string();
            service.id = Some(id.clone());
            id
        };

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Create, EventPayload::Service { id: service_id }),
                operation: async { backend_driver.create_service(state, service).await },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let service = self
                .backend_driver
                .create_service(exec.state(), service)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Service { id: service.id.clone() },
                ))
                .await;
            Ok(service)
        }
    }

    async fn delete_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Endpoint { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_endpoint(state, id).await?;
                    Ok::<(), CatalogProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_endpoint(exec.state(), id)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Endpoint { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn delete_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Region { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_region(state, id).await?;
                    Ok::<(), CatalogProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_region(exec.state(), id).await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Region { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn delete_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Delete, EventPayload::Service { id: id.to_string() }),
                operation: async {
                    backend_driver.delete_service(state, id).await?;
                    Ok::<(), CatalogProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_service(exec.state(), id)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Service { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    async fn get_catalog<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        self.backend_driver.get_catalog(exec.state(), enabled).await
    }

    async fn get_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        self.backend_driver.get_endpoint(exec.state(), id).await
    }

    async fn get_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Region>, CatalogProviderError> {
        self.backend_driver.get_region(exec.state(), id).await
    }

    async fn get_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        self.backend_driver.get_service(exec.state(), id).await
    }

    async fn list_endpoints<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        params.validate()?;
        self.backend_driver
            .list_endpoints(exec.state(), params)
            .await
    }

    async fn list_regions<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &RegionListParameters,
    ) -> Result<Vec<Region>, CatalogProviderError> {
        params.validate()?;
        self.backend_driver.list_regions(exec.state(), params).await
    }

    async fn list_services<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError> {
        params.validate()?;
        self.backend_driver
            .list_services(exec.state(), params)
            .await
    }

    async fn update_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        endpoint: EndpointUpdate,
    ) -> Result<Endpoint, CatalogProviderError> {
        endpoint.validate()?;

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Update, EventPayload::Endpoint { id: id.to_string() }),
                operation: async {
                    backend_driver.update_endpoint(state, id, endpoint).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let updated = self
                .backend_driver
                .update_endpoint(exec.state(), id, endpoint)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Endpoint { id: id.to_string() },
                ))
                .await;
            Ok(updated)
        }
    }

    async fn update_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        region: RegionUpdate,
    ) -> Result<Region, CatalogProviderError> {
        region.validate()?;

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Update, EventPayload::Region { id: id.to_string() }),
                operation: async {
                    backend_driver.update_region(state, id, region).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let updated = self
                .backend_driver
                .update_region(exec.state(), id, region)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Region { id: id.to_string() },
                ))
                .await;
            Ok(updated)
        }
    }

    async fn update_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        service: ServiceUpdate,
    ) -> Result<Service, CatalogProviderError> {
        service.validate()?;

        if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let state = exec.state();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(Operation::Update, EventPayload::Service { id: id.to_string() }),
                operation: async {
                    backend_driver.update_service(state, id, service).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let updated = self
                .backend_driver
                .update_service(exec.state(), id, service)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Service { id: id.to_string() },
                ))
                .await;
            Ok(updated)
        }
    }
}
