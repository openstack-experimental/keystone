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
//! # K8s auth - internal mocking tools.
use async_trait::async_trait;
use mockall::mock;

use openstack_keystone_core_types::k8s_auth::*;

use crate::auth::AuthenticationResult;
use crate::k8s_auth::{K8sAuthApi, K8sAuthProviderError};
use crate::keystone::ServiceState;

mock! {
    pub K8sAuthProvider {}

    #[async_trait]
    impl K8sAuthApi for K8sAuthProvider {

        /// Authenticate via K8s TokenReview + mapping engine.
        async fn authenticate_by_k8s_mapping(
            &self,
            state: &ServiceState,
            req: &K8sAuthRequest,
        ) -> Result<AuthenticationResult, K8sAuthProviderError>;

        /// Register new K8s auth instance.
        async fn create_auth_instance(
            &self,
            state: &ServiceState,
            config: K8sAuthInstanceCreate,
        ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

        /// Delete K8s auth instance.
        async fn delete_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), K8sAuthProviderError>;

        /// Fetch auth instance
        async fn get_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError>;

        /// List K8s auth instances.
        async fn list_auth_instances(
            &self,
            state: &ServiceState,
            params: &K8sAuthInstanceListParameters,
        ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError>;

        /// Update K8s auth instance.
        async fn update_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            data: K8sAuthInstanceUpdate,
        ) -> Result<K8sAuthInstance, K8sAuthProviderError>;
    }
}
