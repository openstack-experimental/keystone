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

use openstack_keystone_core_types::spiffe::*;

use crate::keystone::ServiceState;
use crate::spiffe::{SpiffeApi, SpiffeProviderError};

mock! {
    pub SpiffeProvider {}

    #[async_trait]
    impl SpiffeApi for SpiffeProvider {

        async fn create_binding(
            &self,
            state: &ServiceState,
            binding: SpiffeBindingCreate,
        ) -> Result<SpiffeBinding, SpiffeProviderError>;

        async fn delete_binding<'a>(
            &self,
            state: &ServiceState,
            svid: &'a str,
        ) -> Result<(), SpiffeProviderError>;

        async fn get_binding<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<SpiffeBinding>, SpiffeProviderError>;

        async fn list_bindings(
            &self,
            state: &ServiceState,
            params: &SpiffeBindingListParameters,
        ) -> Result<Vec<SpiffeBinding>, SpiffeProviderError>;

        async fn update_binding<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            data: SpiffeBindingUpdate,
        ) -> Result<SpiffeBinding, SpiffeProviderError>;
    }
}
