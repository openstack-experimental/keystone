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
//!
//! Catalog provider takes care of returning the list of the service endpoints
//! that the API user is able to use according to the valid authentication.
//!
//! Following Keystone concepts are covered:
//!
//! ## Endpoint
//!
//! A network-accessible address, usually a URL, through which you can access a
//! service. If you are using an extension for templates, you can create an
//! endpoint template that represents the templates of all consumable services
//! that are available across the regions.
//!
//! ## Service
//!
//! An OpenStack service, such as Compute (nova), Object Storage (swift), or
//! Image service (glance), that provides one or more endpoints through which
//! users can access resources and perform operations.
use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::catalog::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use service::CatalogService;

pub use crate::catalog::error::CatalogProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockCatalogProvider;
pub use provider_api::CatalogApi;

pub enum CatalogProvider {
    Service(CatalogService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockCatalogProvider),
}

impl CatalogProvider {
    /// Creates a new `CatalogProvider`.
    ///
    /// # Parameters
    /// - `config`: The configuration for the catalog provider.
    /// - `plugin_manager`: The plugin manager used to load the catalog backend.
    ///
    /// # Returns
    /// A `Result` containing the `CatalogProvider` instance or a
    /// `CatalogProviderError`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, CatalogProviderError> {
        Ok(Self::Service(CatalogService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl CatalogApi for CatalogProvider {
    /// List services.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the service list.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Service` objects or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_services(
        &self,
        state: &ServiceState,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError> {
        match self {
            Self::Service(provider) => provider.list_services(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_services(state, params).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_service<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        match self {
            Self::Service(provider) => provider.get_service(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_service(state, id).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_endpoints(
        &self,
        state: &ServiceState,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        match self {
            Self::Service(provider) => provider.list_endpoints(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_endpoints(state, params).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_endpoint<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        match self {
            Self::Service(provider) => provider.get_endpoint(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_endpoint(state, id).await,
        }
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
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_catalog(
        &self,
        state: &ServiceState,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        match self {
            Self::Service(provider) => provider.get_catalog(state, enabled).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_catalog(state, enabled).await,
        }
    }
}
