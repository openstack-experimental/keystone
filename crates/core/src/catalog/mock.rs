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
use mockall::mock;

use openstack_keystone_core_types::catalog::*;

use crate::catalog::CatalogApi;
use crate::catalog::error::CatalogProviderError;
use crate::keystone::ServiceState;

mock! {
    pub CatalogProvider {}

    #[async_trait]
    impl CatalogApi for CatalogProvider {
        async fn create_region(
            &self,
            state: &ServiceState,
            region: RegionCreate,
        ) -> Result<Region, CatalogProviderError>;

        async fn delete_region<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), CatalogProviderError>;

        async fn get_catalog(
            &self,
            state: &ServiceState,
            enabled: bool,
        ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

        async fn get_endpoint<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Endpoint>, CatalogProviderError>;

        async fn get_region<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Region>, CatalogProviderError>;

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

        async fn list_regions(
            &self,
            state: &ServiceState,
            params: &RegionListParameters,
        ) -> Result<Vec<Region>, CatalogProviderError>;

        async fn list_services(
            &self,
            state: &ServiceState,
            params: &ServiceListParameters
        ) -> Result<Vec<Service>, CatalogProviderError>;

        async fn update_region<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            region: RegionUpdate,
        ) -> Result<Region, CatalogProviderError>;
    }
}
