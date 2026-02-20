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

//! # Identity mapping provider
//!
//! Identity mapping provider provides a mapping of the entity ID between
//! Keystone and the remote system (i.e. LDAP, IdP, OpenFGA, SCIM, etc).

use async_trait::async_trait;
use std::sync::Arc;

pub mod backend;
pub mod error;
#[cfg(test)]
pub mod mock;
pub mod types;

use crate::config::Config;
use crate::identity_mapping::backend::{IdentityMappingBackend, sql::SqlBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
pub use error::IdentityMappingProviderError;
use types::*;

#[cfg(test)]
pub use mock::MockIdentityMappingProvider;
pub use types::IdentityMappingApi;

pub struct IdentityMappingProvider {
    /// Backend driver.
    backend_driver: Arc<dyn IdentityMappingBackend>,
}

impl IdentityMappingProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, IdentityMappingProviderError> {
        let backend_driver = if let Some(driver) =
            plugin_manager.get_identity_mapping_backend(config.identity_mapping.driver.clone())
        {
            driver.clone()
        } else {
            match config.identity_mapping.driver.as_str() {
                "sql" => Arc::new(SqlBackend::default()),
                _ => {
                    return Err(IdentityMappingProviderError::UnsupportedDriver(
                        config.identity_mapping.driver.clone(),
                    ));
                }
            }
        };
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl IdentityMappingApi for IdentityMappingProvider {
    /// Get the `IdMapping` by the local data.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
        self.backend_driver
            .get_by_local_id(state, local_id, domain_id, entity_type)
            .await
    }

    /// Get the IdMapping by the public_id.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
        self.backend_driver.get_by_public_id(state, public_id).await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use super::backend::MockIdentityMappingBackend;
    use super::*;
    use crate::config::Config;
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;

    fn get_state_mock() -> Arc<Service> {
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                Provider::mocked_builder().build().unwrap(),
                MockPolicyFactory::default(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_get_by_local_id() {
        let state = get_state_mock();
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdentityMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_local_id()
            .withf(|_, lid: &'_ str, did: &'_ str, _et: &IdMappingEntityType| {
                lid == "lid" && did == "did"
            })
            .returning(move |_, _, _, _| Ok(Some(sot_clone.clone())));
        let provider = IdentityMappingProvider {
            backend_driver: Arc::new(backend),
        };

        let res: IdMapping = provider
            .get_by_local_id(&state, "lid", "did", IdMappingEntityType::User)
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }

    #[tokio::test]
    async fn test_get_by_public_id() {
        let state = get_state_mock();
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdentityMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_public_id()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(move |_, _| Ok(Some(sot_clone.clone())));
        let provider = IdentityMappingProvider {
            backend_driver: Arc::new(backend),
        };

        let res: IdMapping = provider
            .get_by_public_id(&state, "pid")
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }
}
