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

use crate::config::Config;
use crate::identity_mapping::{IdentityMappingApi, IdentityMappingError, types::*};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;

mock! {
    pub IdentityMappingProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, IdentityMappingError>;
    }

    #[async_trait]
    impl IdentityMappingApi for IdentityMappingProvider {
        async fn get_by_local_id<'a>(
            &self,
            state: &ServiceState,
            local_id: &'a str,
            domain_id: &'a str,
            entity_type: IdMappingEntityType,
        ) -> Result<Option<IdMapping>, IdentityMappingError>;

        async fn get_by_public_id<'a>(
            &self,
            state: &ServiceState,
            public_id: &'a str,
        ) -> Result<Option<IdMapping>, IdentityMappingError>;
    }

    impl Clone for IdentityMappingProvider {
        fn clone(&self) -> Self;
    }

}
