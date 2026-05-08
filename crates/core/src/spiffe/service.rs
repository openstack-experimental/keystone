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
//! # Kubernetes authentication.

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::spiffe::*;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::spiffe::{SpiffeApi, SpiffeProviderError, backend::SpiffeBackend};

/// Spiffeprovider.
pub struct SpiffeService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn SpiffeBackend>,
}

impl SpiffeService {
    /// Create a new `SpiffeService`.
    ///
    /// # Arguments
    /// * `config` - Reference to the [`Config`].
    /// * `plugin_manager` - Reference to the [`PluginManagerApi`].
    ///
    /// # Returns
    /// * Success with a new `SpiffeService` instance.
    /// * `SpiffeProviderError` if the backend driver cannot be loaded.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, SpiffeProviderError> {
        let backend_driver = plugin_manager
            .get_spiffe_backend(config.spiffe.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl SpiffeApi for SpiffeService {
    /// Register new binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `binding` - [`SpiffeBindingCreate`] data for the new binding.
    ///
    /// # Returns
    /// * Success with the created [`SpiffeBinding`].
    /// * Error if the instance could not be created.
    async fn create_binding(
        &self,
        state: &ServiceState,
        binding: SpiffeBindingCreate,
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        todo!();
    }

    /// Delete SPIFFE binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID of a binding to delete.
    ///
    /// # Returns
    /// * Success if the binding was deleted.
    /// * Error if the deletion failed.
    async fn delete_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<(), SpiffeProviderError> {
        todo!();
    }

    /// Fetch binding for the SVID.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID identifier to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`SpiffeBinding`] if found,
    /// or an `Error`.
    async fn get_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<Option<SpiffeBinding>, SpiffeProviderError> {
        todo!();
    }

    /// List SpiffeBindings.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`SpiffeBindingListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`SpiffeBinding`].
    /// * Error if the listing failed.
    async fn list_bindings(
        &self,
        state: &ServiceState,
        params: &SpiffeBindingListParameters,
    ) -> Result<Vec<SpiffeBinding>, SpiffeProviderError> {
        todo!();
    }

    /// Update binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID for the binding to update.
    /// * `data` - [`SpiffeBindingUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`SpiffeBinding`].
    /// * Error if the update failed.
    async fn update_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
        data: SpiffeBindingUpdate,
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        todo!();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // use std::sync::Arc;

    // use super::*;
    // use crate::k8s_auth::backend::MockK8sAuthBackend;
    // use crate::tests::get_mocked_state;

    //#[tokio::test]
    //async fn test_create_auth_instance() {
    //    let state = get_mocked_state(None, None).await;
    //    let mut backend = MockK8sAuthBackend::default();
    //    backend
    //        .expect_create_auth_instance()
    //        .returning(|_, _| Ok(K8sAuthInstance::default()));
    //    let provider = K8sAuthService {
    //        backend_driver: Arc::new(backend),
    //        http_client_pool: Box::new(HttpClientPool::default()),
    //    };

    //    assert!(
    //        provider
    //            .create_auth_instance(
    //                &state,
    //                K8sAuthInstanceCreate {
    //                    ca_cert: Some("ca".into()),
    //                    disable_local_ca_jwt: Some(true),
    //                    domain_id: "did".into(),
    //                    enabled: true,
    //                    host: "host".into(),
    //                    id: Some("id".into()),
    //                    name: Some("name".into()),
    //                }
    //            )
    //            .await
    //            .is_ok()
    //    );
    //}

    //#[tokio::test]
    //async fn test_create_auth_role() {
    //    let state = get_mocked_state(None, None).await;
    //    let mut backend = MockK8sAuthBackend::default();
    //    backend
    //        .expect_create_auth_role()
    //        .returning(|_, _| Ok(K8sAuthRole::default()));
    //    let provider = K8sAuthService {
    //        backend_driver: Arc::new(backend),
    //        http_client_pool: Box::new(HttpClientPool::default()),
    //    };

    //    assert!(
    //        provider
    //            .create_auth_role(
    //                &state,
    //                K8sAuthRoleCreate {
    //                    auth_instance_id: "cid".into(),
    //                    bound_audience: Some("aud".into()),
    //                    bound_service_account_names: vec!["a".into(), "b".into()],
    //                    bound_service_account_namespaces: vec!["na".into(), "nb".into()],
    //                    domain_id: "did".into(),
    //                    enabled: true,
    //                    id: Some("id".into()),
    //                    name: "name".into(),
    //                    token_restriction_id: "trid".into(),
    //                }
    //            )
    //            .await
    //            .is_ok()
    //    );
    //}
}
