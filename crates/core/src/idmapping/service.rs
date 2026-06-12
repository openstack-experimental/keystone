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

//! # IdMapping provider

use async_trait::async_trait;
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::idmapping::*;

use crate::idmapping::{IdMappingApi, IdMappingProviderError, backend::IdMappingBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

pub struct IdMappingService {
    /// Backend driver.
    backend_driver: Arc<dyn IdMappingBackend>,
}

impl IdMappingService {
    /// Create a new `IdMappingService`.
    ///
    /// # Parameters
    /// - `config`: The configuration.
    /// - `plugin_manager`: The plugin manager.
    ///
    /// # Returns
    /// - `Result<Self, IdMappingProviderError>` - The new service or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdMappingProviderError> {
        let backend_driver = plugin_manager
            .get_idmapping_backend(config.idmapping.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl IdMappingApi for IdMappingService {
    /// Get the `IdMapping` by the local data.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        self.backend_driver
            .get_by_local_id(state, local_id, domain_id, entity_type)
            .await
    }

    /// Get the `IdMapping` by the public identifier.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        self.backend_driver.get_by_public_id(state, public_id).await
    }
}

#[cfg(test)]
mod tests {
    // use std::sync::Arc;

    use super::*;
    use crate::idmapping::backend::MockIdMappingBackend;
    use crate::tests::get_mocked_state;

    fn create_provider(backend: MockIdMappingBackend) -> IdMappingService {
        IdMappingService {
            backend_driver: Arc::new(backend),
        }
    }

    #[tokio::test]
    async fn test_get_by_local_id() {
        let state = get_mocked_state(None, None).await;
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_local_id()
            .withf(|_, lid: &'_ str, did: &'_ str, _et: &IdMappingEntityType| {
                lid == "lid" && did == "did"
            })
            .returning(move |_, _, _, _| Ok(Some(sot_clone.clone())));
        let provider = create_provider(backend);

        let res: IdMapping = provider
            .get_by_local_id(&state, "lid", "did", IdMappingEntityType::User)
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }

    #[tokio::test]
    async fn test_get_by_public_id() {
        let state = get_mocked_state(None, None).await;
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_public_id()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(move |_, _| Ok(Some(sot_clone.clone())));
        let provider = create_provider(backend);

        let res: IdMapping = provider
            .get_by_public_id(&state, "pid")
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }
}
