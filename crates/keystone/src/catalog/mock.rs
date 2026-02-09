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
#[cfg(test)]
use mockall::mock;

use crate::catalog::CatalogApi;
use crate::catalog::error::CatalogProviderError;
use crate::catalog::types::{Endpoint, EndpointListParameters, Service, ServiceListParameters};
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;

#[cfg(test)]
mock! {
    pub CatalogProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, CatalogProviderError>;
    }

    #[async_trait]
    impl CatalogApi for CatalogProvider {
        async fn list_services(
            &self,
            state: &ServiceState,
            params: &ServiceListParameters
        ) -> Result<Vec<Service>, CatalogProviderError>;

        async fn get_service<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Service>, CatalogProviderError>;

        async fn list_endpoints(
            &self,
            state: &ServiceState,
            params: &EndpointListParameters,
        ) -> Result<Vec<Endpoint>, CatalogProviderError>;

        async fn get_endpoint<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Endpoint>, CatalogProviderError>;

        async fn get_catalog(
            &self,
            state: &ServiceState,
            enabled: bool,
        ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

    }
}
