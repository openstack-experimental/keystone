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
    /// Creates a new `CatalogService`.
    ///
    /// # Parameters
    /// - `config`: The configuration for the catalog provider.
    /// - `plugin_manager`: The plugin manager used to load the catalog backend.
    ///
    /// # Returns
    /// A `Result` containing the `CatalogService` instance or a
    /// `CatalogProviderError`.
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
    /// Associate an endpoint with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn add_endpoint_to_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        self.backend_driver
            .add_endpoint_to_project(exec.state(), project_id, endpoint_id)
            .await
    }

    /// Associate an endpoint group with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn add_endpoint_group_to_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        self.backend_driver
            .add_endpoint_group_to_project(exec.state(), project_id, endpoint_group_id)
            .await
    }

    /// Check whether an endpoint is associated with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` containing `true` when the association exists, or a
    /// `CatalogProviderError`.
    async fn check_endpoint_in_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<bool, CatalogProviderError> {
        self.backend_driver
            .check_endpoint_in_project(exec.state(), project_id, endpoint_id)
            .await
    }

    /// Check whether an endpoint group is associated with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` containing `true` when the association exists, or a
    /// `CatalogProviderError`.
    async fn check_endpoint_group_in_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<bool, CatalogProviderError> {
        self.backend_driver
            .check_endpoint_group_in_project(exec.state(), project_id, endpoint_group_id)
            .await
    }

    /// Create a new endpoint.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `endpoint`: The endpoint creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Endpoint`, or a
    /// `CatalogProviderError`.
    async fn create_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        endpoint: EndpointCreate,
    ) -> Result<Endpoint, CatalogProviderError> {
        endpoint.validate()?;
        let endpoint = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let endpoint_clone = endpoint.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Endpoint { id: endpoint_clone.id.clone().unwrap_or_default() },
                ),
                operation: async {
                    backend_driver.create_endpoint(exec.state(), endpoint_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let endpoint = self
                .backend_driver
                .create_endpoint(exec.state(), endpoint)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Endpoint {
                        id: endpoint.id.clone(),
                    },
                ))
                .await;

            endpoint
        };

        Ok(endpoint)
    }

    /// Create a new endpoint group.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `endpoint_group`: The endpoint group creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `EndpointGroup`, or a
    /// `CatalogProviderError`.
    async fn create_endpoint_group<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        endpoint_group: EndpointGroupCreate,
    ) -> Result<EndpointGroup, CatalogProviderError> {
        endpoint_group.validate()?;
        let endpoint_group = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let eg_clone = endpoint_group.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::EndpointGroup { id: eg_clone.id.clone().unwrap_or_default() },
                ),
                operation: async {
                    backend_driver.create_endpoint_group(exec.state(), eg_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let eg = self
                .backend_driver
                .create_endpoint_group(exec.state(), endpoint_group)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::EndpointGroup { id: eg.id.clone() },
                ))
                .await;

            eg
        };

        Ok(endpoint_group)
    }

    /// Create a new region.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `region`: The region creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Region`, or a `CatalogProviderError`.
    async fn create_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        region: RegionCreate,
    ) -> Result<Region, CatalogProviderError> {
        region.validate()?;
        let region = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let region_clone = region.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Region { id: region_clone.id.clone().unwrap_or_default() },
                ),
                operation: async {
                    backend_driver.create_region(exec.state(), region_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let region = self
                .backend_driver
                .create_region(exec.state(), region)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Region {
                        id: region.id.clone(),
                    },
                ))
                .await;

            region
        };

        Ok(region)
    }

    /// Create a new service.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `service`: The service creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Service`, or a
    /// `CatalogProviderError`.
    async fn create_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        service: ServiceCreate,
    ) -> Result<Service, CatalogProviderError> {
        service.validate()?;
        let service = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let service_clone = service.clone();
            let service_id = service_clone.id.clone().unwrap_or_default();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Service { id: service_id },
                ),
                operation: async {
                    backend_driver.create_service(exec.state(), service_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let service = self
                .backend_driver
                .create_service(exec.state(), service)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Service {
                        id: service.id.clone(),
                    },
                ))
                .await;

            service
        };

        Ok(service)
    }

    /// Delete an endpoint by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn delete_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Endpoint { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_endpoint(exec.state(), id).await?;
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

    /// Delete an endpoint group by ID.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `id`: The unique identifier of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn delete_endpoint_group<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::EndpointGroup { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_endpoint_group(exec.state(), id).await?;
                    Ok::<(), CatalogProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_endpoint_group(exec.state(), id)
                .await?;

            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::EndpointGroup { id: id.to_string() },
                ))
                .await;
        }

        Ok(())
    }

    /// Delete a region by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the region.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn delete_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Region { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_region(exec.state(), id).await?;
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

    /// Delete a service by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the service.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn delete_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Service { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_service(exec.state(), id).await?;
                    Ok::<(), CatalogProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_service(exec.state(), id).await?;

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

    /// Get catalog.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `enabled`: Whether to return only enabled services.
    ///
    /// # Returns
    /// A `Result` containing a vector of tuples of `Service` and its associated
    /// `Endpoint`s, or a `CatalogProviderError`.
    async fn get_catalog<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        self.backend_driver.get_catalog(exec.state(), enabled).await
    }

    /// Get single endpoint by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the endpoint if found, or an
    /// `Error`.
    async fn get_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        self.backend_driver.get_endpoint(exec.state(), id).await
    }

    /// Get single endpoint group by ID.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `id`: The unique identifier of the endpoint group.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the endpoint group if found, or an
    /// `Error`.
    async fn get_endpoint_group<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<EndpointGroup>, CatalogProviderError> {
        self.backend_driver
            .get_endpoint_group(exec.state(), id)
            .await
    }

    /// Get single region by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the region.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the region if found, or an
    /// `Error`.
    async fn get_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Region>, CatalogProviderError> {
        self.backend_driver.get_region(exec.state(), id).await
    }

    /// Get single service by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the service.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the service if found, or an
    /// `Error`.
    async fn get_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        self.backend_driver.get_service(exec.state(), id).await
    }

    /// List Endpoints.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the endpoint list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Endpoint` objects or a
    /// `CatalogProviderError`.
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

    /// List endpoint groups.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `params`: Parameters for filtering the endpoint group list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `EndpointGroup` objects or a
    /// `CatalogProviderError`.
    async fn list_endpoint_groups<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &EndpointGroupListParameters,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
        params.validate()?;
        self.backend_driver
            .list_endpoint_groups(exec.state(), params)
            .await
    }

    /// List the endpoints associated with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Endpoint` objects or a
    /// `CatalogProviderError`.
    async fn list_project_endpoints<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        self.backend_driver
            .list_project_endpoints(exec.state(), project_id)
            .await
    }

    /// List the endpoint groups associated with a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing a vector of `EndpointGroup` objects or a
    /// `CatalogProviderError`.
    async fn list_project_endpoint_groups<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
        self.backend_driver
            .list_project_endpoint_groups(exec.state(), project_id)
            .await
    }

    /// List regions.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the region list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Region` objects or a
    /// `CatalogProviderError`.
    async fn list_regions<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &RegionListParameters,
    ) -> Result<Vec<Region>, CatalogProviderError> {
        params.validate()?;
        self.backend_driver.list_regions(exec.state(), params).await
    }

    /// List services.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the service list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Service` objects or a
    /// `CatalogProviderError`.
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

    /// Update an existing endpoint.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint.
    /// - `endpoint`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Endpoint`, or a
    /// `CatalogProviderError`.
    /// Remove the association between an endpoint and a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn remove_endpoint_from_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        self.backend_driver
            .remove_endpoint_from_project(exec.state(), project_id, endpoint_id)
            .await
    }

    /// Remove the association between an endpoint group and a project.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn remove_endpoint_group_from_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        self.backend_driver
            .remove_endpoint_group_from_project(exec.state(), project_id, endpoint_group_id)
            .await
    }

    /// Update an existing endpoint.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `id`: The unique identifier of the endpoint.
    /// - `endpoint`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Endpoint`, or a
    /// `CatalogProviderError`.
    async fn update_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        endpoint: EndpointUpdate,
    ) -> Result<Endpoint, CatalogProviderError> {
        endpoint.validate()?;
        let updated = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let endpoint_clone = endpoint.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Endpoint { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_endpoint(exec.state(), id, endpoint_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
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
            updated
        };
        Ok(updated)
    }

    /// Update an existing endpoint group.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `id`: The unique identifier of the endpoint group.
    /// - `endpoint_group`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `EndpointGroup`, or a
    /// `CatalogProviderError`.
    async fn update_endpoint_group<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        endpoint_group: EndpointGroupUpdate,
    ) -> Result<EndpointGroup, CatalogProviderError> {
        endpoint_group.validate()?;
        let updated = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let eg_clone = endpoint_group.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::EndpointGroup { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_endpoint_group(exec.state(), id, eg_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let updated = self
                .backend_driver
                .update_endpoint_group(exec.state(), id, endpoint_group)
                .await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::EndpointGroup { id: id.to_string() },
                ))
                .await;
            updated
        };
        Ok(updated)
    }

    /// Update an existing region.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the region.
    /// - `region`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Region`, or a `CatalogProviderError`.
    async fn update_region<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        region: RegionUpdate,
    ) -> Result<Region, CatalogProviderError> {
        region.validate()?;
        let updated = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let region_clone = region.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Region { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_region(exec.state(), id, region_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
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
            updated
        };
        Ok(updated)
    }

    /// Update an existing service.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the service.
    /// - `service`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Service`, or a
    /// `CatalogProviderError`.
    async fn update_service<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        service: ServiceUpdate,
    ) -> Result<Service, CatalogProviderError> {
        service.validate()?;
        let updated = if let Some(vsc) = exec.ctx() {
            let backend_driver = &self.backend_driver;
            let service_clone = service.clone();
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Service { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_service(exec.state(), id, service_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CatalogProviderError::Driver("audit dispatch failed".into()),
            }?
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
            updated
        };
        Ok(updated)
    }
}
