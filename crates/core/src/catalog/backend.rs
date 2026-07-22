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

use openstack_keystone_core_types::catalog::*;

use crate::catalog::error::CatalogProviderError;
use crate::keystone::ServiceState;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CatalogBackend: Send + Sync {
    /// Associate an endpoint with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn add_endpoint_to_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError>;

    /// Associate an endpoint group with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn add_endpoint_group_to_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError>;

    /// Check whether an endpoint is associated with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` containing `true` when the association exists, or a
    /// `CatalogProviderError`.
    async fn check_endpoint_in_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<bool, CatalogProviderError>;

    /// Check whether an endpoint group is associated with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` containing `true` when the association exists, or a
    /// `CatalogProviderError`.
    async fn check_endpoint_group_in_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<bool, CatalogProviderError>;

    /// Create a new endpoint.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `endpoint`: The endpoint creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Endpoint`, or a
    /// `CatalogProviderError`.
    async fn create_endpoint(
        &self,
        state: &ServiceState,
        endpoint: EndpointCreate,
    ) -> Result<Endpoint, CatalogProviderError>;

    /// Create a new endpoint group.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `endpoint_group`: The endpoint group creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `EndpointGroup`, or a
    /// `CatalogProviderError`.
    async fn create_endpoint_group(
        &self,
        state: &ServiceState,
        endpoint_group: EndpointGroupCreate,
    ) -> Result<EndpointGroup, CatalogProviderError>;

    /// Create a new region.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `region`: The region creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Region`, or a `CatalogProviderError`.
    async fn create_region(
        &self,
        state: &ServiceState,
        region: RegionCreate,
    ) -> Result<Region, CatalogProviderError>;

    /// Create a new service.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `service`: The service creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Service`, or a
    /// `CatalogProviderError`.
    async fn create_service(
        &self,
        state: &ServiceState,
        service: ServiceCreate,
    ) -> Result<Service, CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError>;

    /// Delete an endpoint group by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn delete_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError>;

    /// Get Catalog (Services with Endpoints).
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `enabled`: Whether to return only enabled services.
    ///
    /// # Returns
    /// A `Result` containing a vector of tuples of `Service` and its associated
    /// `Endpoint`s, or a `CatalogProviderError`.
    async fn get_catalog(
        &self,
        state: &ServiceState,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

    /// Get single endpoint by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Endpoint` if found, or a
    /// `CatalogProviderError`.
    async fn get_endpoint<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError>;

    /// Get single endpoint group by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint group.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `EndpointGroup` if found, or a
    /// `CatalogProviderError`.
    async fn get_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<EndpointGroup>, CatalogProviderError>;

    /// Get single region by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the region.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Region` if found, or a
    /// `CatalogProviderError`.
    async fn get_region<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Region>, CatalogProviderError>;

    /// Get single service by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the service.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Service` if found, or a
    /// `CatalogProviderError`.
    async fn get_service<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError>;

    /// List Endpoints.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the endpoint list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Endpoint` objects or a
    /// `CatalogProviderError`.
    async fn list_endpoints(
        &self,
        state: &ServiceState,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError>;

    /// List endpoint groups.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the endpoint group list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `EndpointGroup` objects or a
    /// `CatalogProviderError`.
    async fn list_endpoint_groups(
        &self,
        state: &ServiceState,
        params: &EndpointGroupListParameters,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError>;

    /// List the endpoints associated with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Endpoint` objects or a
    /// `CatalogProviderError`.
    async fn list_project_endpoints<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Vec<Endpoint>, CatalogProviderError>;

    /// List the endpoint groups associated with a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing a vector of `EndpointGroup` objects or a
    /// `CatalogProviderError`.
    async fn list_project_endpoint_groups<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError>;

    /// List regions.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the region list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Region` objects or a
    /// `CatalogProviderError`.
    async fn list_regions(
        &self,
        state: &ServiceState,
        params: &RegionListParameters,
    ) -> Result<Vec<Region>, CatalogProviderError>;

    /// List services.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the service list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Service` objects or a
    /// `CatalogProviderError`.
    async fn list_services(
        &self,
        state: &ServiceState,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError>;

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
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_id`: The ID of the endpoint.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn remove_endpoint_from_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError>;

    /// Remove the association between an endpoint group and a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    /// - `endpoint_group_id`: The ID of the endpoint group.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    async fn remove_endpoint_group_from_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
        endpoint: EndpointUpdate,
    ) -> Result<Endpoint, CatalogProviderError>;

    /// Update an existing endpoint group.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The unique identifier of the endpoint group.
    /// - `endpoint_group`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `EndpointGroup`, or a
    /// `CatalogProviderError`.
    async fn update_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        endpoint_group: EndpointGroupUpdate,
    ) -> Result<EndpointGroup, CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
        region: RegionUpdate,
    ) -> Result<Region, CatalogProviderError>;

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
        state: &ServiceState,
        id: &'a str,
        service: ServiceUpdate,
    ) -> Result<Service, CatalogProviderError>;
}
