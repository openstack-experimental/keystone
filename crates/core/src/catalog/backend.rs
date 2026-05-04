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
}
