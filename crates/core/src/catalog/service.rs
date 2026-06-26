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

        Ok(endpoint)
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
        self.backend_driver.delete_region(exec.state(), id).await?;

        exec.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Region { id: id.to_string() },
            ))
            .await;

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
        self.backend_driver.delete_service(exec.state(), id).await?;

        exec.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Service { id: id.to_string() },
            ))
            .await;

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
    async fn update_endpoint<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        endpoint: EndpointUpdate,
    ) -> Result<Endpoint, CatalogProviderError> {
        endpoint.validate()?;
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
        let updated = self
            .backend_driver
            .update_region(exec.state(), id, region)
            .await?;
        exec.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Region { id: id.to_string() },
            ))
            .await;
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
        let updated = self
            .backend_driver
            .update_service(exec.state(), id, service)
            .await?;
        exec.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Service { id: id.to_string() },
            ))
            .await;
        Ok(updated)
    }
}
